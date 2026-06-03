package bindcrypto

/*
	Sliver Implant Framework
	Copyright (C) 2026  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.

	------------------------------------------------------------------------

	Bind crypto layer: HMAC-SHA256 authentication + ChaCha20-Poly1305
	encrypted transport for bind session connections.

	The handshake authenticates both sides via a shared secret and derives
	a symmetric session key. The encrypted conn wrapper provides a framed,
	goroutine-safe net.Conn that transparently encrypts/decrypts all
	traffic using ChaCha20-Poly1305 AEAD.

	Direction-specific nonces prevent nonce reuse when both sides write
	simultaneously:
	  - Server (implant) writes use EVEN sequence numbers (0, 2, 4, ...)
	  - Client (operator) writes use ODD sequence numbers  (1, 3, 5, ...)
*/

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// nonceSize is the ChaCha20-Poly1305 nonce length (96 bits).
	nonceSize = chacha20poly1305.NonceSize // 12

	// handshakeNonceSize is the size of the random nonce exchanged
	// during the authentication handshake.
	handshakeNonceSize = 32

	// hmacSize is the HMAC-SHA256 output size.
	hmacSize = sha256.Size // 32

	// frameLenSize is the 4-byte little-endian length prefix per frame.
	frameLenSize = 4

	// maxFrameSize caps the ciphertext frame size to prevent memory
	// exhaustion from corrupt/malicious length headers (16 MiB).
	maxFrameSize = 16 * 1024 * 1024

	// kdLabel is the domain-separation label mixed into key derivation.
	kdLabel = "bind-session-v1"
)

// DeriveSessionKey derives a 32-byte ChaCha20-Poly1305 key from the
// shared secret and handshake nonce:
//
//	key = SHA256(secret || nonce || "bind-session-v1")
func DeriveSessionKey(secret, nonce []byte) [32]byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(nonce)
	h.Write([]byte(kdLabel))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// AuthHandshakeServer performs the implant (server) side of the bind
// authentication handshake. The implant listens, so it is the "server"
// in the handshake protocol.
//
// Protocol:
//  1. Generate 32-byte random nonce, write to rw
//  2. Read 32-byte HMAC response from rw
//  3. Verify HMAC-SHA256(nonce, secret) in constant time
//  4. Derive session key, construct ChaCha20-Poly1305 AEAD
func AuthHandshakeServer(rw io.ReadWriter, secret []byte) (cipher.AEAD, error) {
	// Step 1: generate and send nonce.
	nonce := make([]byte, handshakeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("bindcrypto: generate nonce: %w", err)
	}
	if _, err := rw.Write(nonce); err != nil {
		return nil, fmt.Errorf("bindcrypto: write nonce: %w", err)
	}

	// Step 2: read HMAC response.
	peerHMAC := make([]byte, hmacSize)
	if _, err := io.ReadFull(rw, peerHMAC); err != nil {
		return nil, fmt.Errorf("bindcrypto: read hmac: %w", err)
	}

	// Step 3: verify.
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	if !hmac.Equal(peerHMAC, expected) {
		return nil, errors.New("authentication failed")
	}

	// Step 4: derive key and create AEAD.
	key := DeriveSessionKey(secret, nonce)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("bindcrypto: create aead: %w", err)
	}
	return aead, nil
}

// AuthHandshakeClient performs the operator/server (client) side of the
// bind authentication handshake. The Sliver server dials the implant,
// so it is the "client" in the handshake protocol.
//
// Protocol:
//  1. Read 32-byte nonce from rw
//  2. Compute HMAC-SHA256(nonce, secret), write to rw
//  3. Derive session key, construct ChaCha20-Poly1305 AEAD
func AuthHandshakeClient(rw io.ReadWriter, secret []byte) (cipher.AEAD, error) {
	// Step 1: read nonce.
	nonce := make([]byte, handshakeNonceSize)
	if _, err := io.ReadFull(rw, nonce); err != nil {
		return nil, fmt.Errorf("bindcrypto: read nonce: %w", err)
	}

	// Step 2: compute and send HMAC.
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	if _, err := rw.Write(mac.Sum(nil)); err != nil {
		return nil, fmt.Errorf("bindcrypto: write hmac: %w", err)
	}

	// Step 3: derive key and create AEAD.
	key := DeriveSessionKey(secret, nonce)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("bindcrypto: create aead: %w", err)
	}
	return aead, nil
}

// nonceFromSeq builds a 12-byte ChaCha20-Poly1305 nonce from a uint64
// sequence number (little-endian in the first 8 bytes, remaining 4
// bytes zero).
func nonceFromSeq(seq uint64) []byte {
	nonce := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(nonce[:8], seq)
	return nonce
}

// encryptedConn wraps a net.Conn with ChaCha20-Poly1305 AEAD
// encryption. Each frame is:
//
//	[4-byte LE ciphertext length] [ciphertext]
//
// where ciphertext = AEAD.Seal(plaintext) using a nonce derived from
// a per-direction sequence counter. The struct is goroutine-safe:
// separate mutexes protect Read and Write paths (yamux calls them
// from different goroutines).
//
// Direction-specific nonce spaces prevent collisions:
//   - isServer=true  (implant): write seq starts at 0, increments by 2 (even)
//   - isServer=false (client):  write seq starts at 1, increments by 2 (odd)
//
// Read-side seq counters mirror the peer's write-side:
//   - isServer=true  reads odd  seq (peer is client, writes odd)
//   - isServer=false reads even seq (peer is server, writes even)
type encryptedConn struct {
	net.Conn
	aead     cipher.AEAD
	readBuf  []byte // leftover decrypted bytes from previous Read
	readMu   sync.Mutex
	writeMu  sync.Mutex
	readSeq  uint64
	writeSeq uint64
}

// NewEncryptedConn wraps conn with ChaCha20-Poly1305 frame encryption.
// isServer should be true on the implant (handshake server) side and
// false on the operator (handshake client) side. This determines the
// nonce parity to avoid nonce reuse.
func NewEncryptedConn(conn net.Conn, aead cipher.AEAD, isServer bool) net.Conn {
	ec := &encryptedConn{
		Conn: conn,
		aead: aead,
	}
	if isServer {
		// Implant writes even (0,2,4,...), reads odd (1,3,5,...).
		ec.writeSeq = 0
		ec.readSeq = 1
	} else {
		// Client writes odd (1,3,5,...), reads even (0,2,4,...).
		ec.writeSeq = 1
		ec.readSeq = 0
	}
	return ec
}

// Read decrypts the next frame (or returns leftover bytes from a
// previous frame) into p.
func (ec *encryptedConn) Read(p []byte) (int, error) {
	ec.readMu.Lock()
	defer ec.readMu.Unlock()

	// Drain leftover decrypted bytes from a previous frame first.
	if len(ec.readBuf) > 0 {
		n := copy(p, ec.readBuf)
		ec.readBuf = ec.readBuf[n:]
		return n, nil
	}

	// Read the 4-byte LE frame length.
	var lenBuf [frameLenSize]byte
	if _, err := io.ReadFull(ec.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := binary.LittleEndian.Uint32(lenBuf[:])
	if frameLen == 0 || int(frameLen) > maxFrameSize {
		return 0, fmt.Errorf("bindcrypto: invalid frame length %d", frameLen)
	}

	// Read the ciphertext frame.
	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(ec.Conn, ciphertext); err != nil {
		return 0, fmt.Errorf("bindcrypto: read frame: %w", err)
	}

	// Decrypt.
	nonce := nonceFromSeq(ec.readSeq)
	ec.readSeq += 2 // stride of 2 keeps parity

	plaintext, err := ec.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("bindcrypto: decrypt: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		ec.readBuf = plaintext[n:]
	}
	return n, nil
}

// Write encrypts plaintext into a framed ciphertext and writes it to
// the underlying connection.
func (ec *encryptedConn) Write(p []byte) (int, error) {
	ec.writeMu.Lock()
	defer ec.writeMu.Unlock()

	nonce := nonceFromSeq(ec.writeSeq)
	ec.writeSeq += 2 // stride of 2 keeps parity

	ciphertext := ec.aead.Seal(nil, nonce, p, nil)

	// Write length prefix + ciphertext as a single syscall where
	// possible to avoid interleaving with concurrent writes on the
	// underlying conn (though writeMu already serializes us).
	frame := make([]byte, frameLenSize+len(ciphertext))
	binary.LittleEndian.PutUint32(frame[:frameLenSize], uint32(len(ciphertext)))
	copy(frame[frameLenSize:], ciphertext)

	if _, err := ec.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// EncryptDatagram performs per-datagram ChaCha20-Poly1305 encryption
// for UDP transports. The nonce is derived from seq and prepended to
// the ciphertext:
//
//	output = nonce (12 bytes) || AEAD.Seal(plaintext)
func EncryptDatagram(aead cipher.AEAD, seq uint64, plaintext []byte) []byte {
	nonce := nonceFromSeq(seq)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, nonceSize+len(ciphertext))
	copy(out[:nonceSize], nonce)
	copy(out[nonceSize:], ciphertext)
	return out
}

// DecryptDatagram performs per-datagram ChaCha20-Poly1305 decryption
// for UDP transports. Extracts the 12-byte nonce prefix, decrypts, and
// returns the plaintext and the sequence number encoded in the nonce.
func DecryptDatagram(aead cipher.AEAD, data []byte) ([]byte, uint64, error) {
	if len(data) < nonceSize+aead.Overhead() {
		return nil, 0, errors.New("bindcrypto: datagram too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("bindcrypto: decrypt datagram: %w", err)
	}

	seq := binary.LittleEndian.Uint64(nonce[:8])
	return plaintext, seq, nil
}
