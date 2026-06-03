package c2

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

	Server-side bind crypto layer: HMAC-SHA256 authentication +
	ChaCha20-Poly1305 encrypted transport for bind session connections.

	The server is the "client" in the handshake protocol because it dials
	the implant's bind listener. The encrypted conn wrapper uses the same
	frame format and nonce derivation as the implant side so both ends
	interoperate.

	Direction-specific nonces prevent nonce reuse:
	  - Implant (server) writes use EVEN seq (0, 2, 4, ...)
	  - Server  (client) writes use ODD  seq (1, 3, 5, ...)
*/

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// bindNonceSize is the ChaCha20-Poly1305 nonce length (96 bits).
	bindNonceSize = chacha20poly1305.NonceSize // 12

	// bindHandshakeNonceSize is the random nonce exchanged during auth.
	bindHandshakeNonceSize = 32

	// bindHMACSize is the HMAC-SHA256 output size.
	bindHMACSize = sha256.Size // 32

	// bindFrameLenSize is the 4-byte LE length prefix per frame.
	bindFrameLenSize = 4

	// bindMaxFrameSize caps the ciphertext frame to 16 MiB.
	bindMaxFrameSize = 16 * 1024 * 1024

	// bindKDLabel is the domain-separation label for key derivation.
	// Must match the implant side exactly.
	bindKDLabel = "bind-session-v1"
)

// bindDeriveSessionKey derives a 32-byte ChaCha20-Poly1305 key from
// the shared secret and handshake nonce:
//
//	key = SHA256(secret || nonce || "bind-session-v1")
func bindDeriveSessionKey(secret, nonce []byte) [32]byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(nonce)
	h.Write([]byte(bindKDLabel))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// bindAuthHandshake performs the client side of the bind authentication
// handshake. The Sliver server is the "client" because it dials the
// implant's bind listener.
//
// Protocol:
//  1. Read 32-byte nonce from implant
//  2. Compute HMAC-SHA256(nonce, secret), write to implant
//  3. Derive session key, construct ChaCha20-Poly1305 AEAD
func bindAuthHandshake(conn net.Conn, secret []byte) (cipher.AEAD, error) {
	// Step 1: read nonce from implant.
	nonce := make([]byte, bindHandshakeNonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return nil, fmt.Errorf("bind auth: read nonce: %w", err)
	}

	// Step 2: compute and send HMAC.
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	if _, err := conn.Write(mac.Sum(nil)); err != nil {
		return nil, fmt.Errorf("bind auth: write hmac: %w", err)
	}

	// Step 3: derive key and create AEAD.
	key := bindDeriveSessionKey(secret, nonce)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("bind auth: create aead: %w", err)
	}
	return aead, nil
}

// bindNonceFromSeq builds a 12-byte nonce from a uint64 sequence number
// (little-endian in the first 8 bytes, remaining 4 bytes zero).
func bindNonceFromSeq(seq uint64) []byte {
	nonce := make([]byte, bindNonceSize)
	binary.LittleEndian.PutUint64(nonce[:8], seq)
	return nonce
}

// bindEncryptedConn wraps a net.Conn with ChaCha20-Poly1305 AEAD
// encryption. Identical frame format to the implant side.
//
// Frame: [4-byte LE ciphertext length] [ciphertext]
//
// Direction-specific nonce spaces:
//   - isServer=true  (implant): write seq 0,2,4,... / read seq 1,3,5,...
//   - isServer=false (client):  write seq 1,3,5,... / read seq 0,2,4,...
type bindEncryptedConn struct {
	net.Conn
	aead     cipher.AEAD
	readBuf  []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex
	readSeq  uint64
	writeSeq uint64
}

// bindNewEncryptedConn wraps conn with ChaCha20-Poly1305 frame
// encryption. isServer controls nonce parity (true = implant side,
// false = server/operator side).
func bindNewEncryptedConn(conn net.Conn, aead cipher.AEAD, isServer bool) net.Conn {
	ec := &bindEncryptedConn{
		Conn: conn,
		aead: aead,
	}
	if isServer {
		ec.writeSeq = 0
		ec.readSeq = 1
	} else {
		ec.writeSeq = 1
		ec.readSeq = 0
	}
	return ec
}

// Read decrypts the next frame into p, draining any leftover bytes
// from a previous oversized frame first.
func (ec *bindEncryptedConn) Read(p []byte) (int, error) {
	ec.readMu.Lock()
	defer ec.readMu.Unlock()

	if len(ec.readBuf) > 0 {
		n := copy(p, ec.readBuf)
		ec.readBuf = ec.readBuf[n:]
		return n, nil
	}

	// Read 4-byte LE frame length.
	var lenBuf [bindFrameLenSize]byte
	if _, err := io.ReadFull(ec.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := binary.LittleEndian.Uint32(lenBuf[:])
	if frameLen == 0 || int(frameLen) > bindMaxFrameSize {
		return 0, fmt.Errorf("bind crypto: invalid frame length %d", frameLen)
	}

	// Read ciphertext.
	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(ec.Conn, ciphertext); err != nil {
		return 0, fmt.Errorf("bind crypto: read frame: %w", err)
	}

	// Decrypt.
	nonce := bindNonceFromSeq(ec.readSeq)
	ec.readSeq += 2

	plaintext, err := ec.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("bind crypto: decrypt: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		ec.readBuf = plaintext[n:]
	}
	return n, nil
}

// Write encrypts plaintext into a framed ciphertext and writes it to
// the underlying connection.
func (ec *bindEncryptedConn) Write(p []byte) (int, error) {
	ec.writeMu.Lock()
	defer ec.writeMu.Unlock()

	nonce := bindNonceFromSeq(ec.writeSeq)
	ec.writeSeq += 2

	ciphertext := ec.aead.Seal(nil, nonce, p, nil)

	frame := make([]byte, bindFrameLenSize+len(ciphertext))
	binary.LittleEndian.PutUint32(frame[:bindFrameLenSize], uint32(len(ciphertext)))
	copy(frame[bindFrameLenSize:], ciphertext)

	if _, err := ec.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}
