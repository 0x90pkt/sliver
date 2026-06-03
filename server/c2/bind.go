package c2

/*
	Sliver Implant Framework
	Copyright (C) 2026  Bishop Fox

	Server-side bind session connector. After the implant opens a bind
	listener (triggered via the "bind" intent), the server dials it,
	performs the HMAC auth handshake, wraps the connection in ChaCha20-
	Poly1305 encryption, and establishes a full Sliver session using
	the standard yamux + signed envelope protocol.
*/

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/log"
	kcp "github.com/xtaci/kcp-go/v5"
)

var bindLog = log.NamedLogger("c2", "bind")

// ConnectToBindImplant dials a connection to an implant's bind
// listener, performs the HMAC auth handshake, wraps the connection
// in ChaCha20-Poly1305 encryption, and establishes a full Sliver
// session using yamux + signed envelopes.
//
// The protocol parameter ("tcp" or "udp") determines the transport.
// TCP uses a plain TCP dial; UDP uses KCP (reliable UDP).
//
// Called from the TriggerFire RPC after the implant responds with its
// bind address. The session appears in core.Sessions asynchronously.
func ConnectToBindImplant(targetHost string, port int, sharedSecret []byte, protocol string) error {
	addr := fmt.Sprintf("%s:%d", targetHost, port)
	bindLog.Infof("Connecting to bind implant at %s (proto=%s)", addr, protocol)

	var conn net.Conn
	var err error

	switch protocol {
	case "udp":
		// KCP provides reliable ordered stream over UDP.
		// No block cipher (we handle encryption above yamux).
		kcpConn, kcpErr := kcp.DialWithOptions(addr, nil, 0, 0)
		if kcpErr != nil {
			bindLog.Errorf("Failed to connect (KCP) to bind implant at %s: %v", addr, kcpErr)
			return fmt.Errorf("kcp dial bind implant %s: %w", addr, kcpErr)
		}
		conn = kcpConn
		err = nil
	default:
		conn, err = net.DialTimeout("tcp", addr, 30*time.Second)
	}

	if err != nil {
		bindLog.Errorf("Failed to connect to bind implant at %s: %v", addr, err)
		return fmt.Errorf("dial bind implant %s: %w", addr, err)
	}

	go handleBindImplantConnection(conn, sharedSecret)
	return nil
}

// handleBindImplantConnection performs the auth handshake, establishes
// encryption, then delegates to the standard yamux session handler.
func handleBindImplantConnection(conn net.Conn, secret []byte) {
	defer recoverAndLogPanic(bindLog.Errorf, "bind handleBindImplantConnection")

	bindLog.Infof("Bind connection established: %s", conn.RemoteAddr())

	defer func() {
		bindLog.Debugf("Bind connection closing: %s", conn.RemoteAddr())
		conn.Close()
	}()

	// Auth handshake (client side) + encrypted stream wrapper.
	// bindAuthHandshake and bindNewEncryptedConn are in bindcrypto.go.
	aead, err := bindAuthHandshake(conn, secret)
	if err != nil {
		bindLog.Errorf("Bind auth failed for %s: %v", conn.RemoteAddr(), err)
		return
	}
	bindLog.Infof("Bind auth OK for %s, establishing encrypted session", conn.RemoteAddr())

	// isServer=false: the Sliver server is the "client" in the bind
	// handshake (it dials the implant).
	encConn := bindNewEncryptedConn(conn, aead, false)

	// --- Standard yamux session (reuse mTLS infrastructure) ---
	implantConn := core.NewImplantConnection("bind", conn.RemoteAddr().String())
	defer implantConn.Cleanup()

	br := bufio.NewReader(encConn)
	bufferedConn := &mtlsBufferedConn{Conn: encConn, r: br}

	preface, err := br.Peek(len(mtlsYamuxPrefaceBytes))
	if err == nil && bytes.Equal(preface, mtlsYamuxPrefaceBytes) {
		if _, err := br.Discard(len(mtlsYamuxPrefaceBytes)); err != nil {
			bindLog.Errorf("Failed to discard yamux preface: %v", err)
			return
		}
		handleSliverConnectionYamux(bufferedConn, implantConn)
		return
	}

	bindLog.Warnf("No yamux preface from bind implant at %s (auth succeeded but protocol mismatch)", conn.RemoteAddr())
}
