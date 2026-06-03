package rpc

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
*/

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/log"
)

var triggerRPCLog = log.NamedLogger("rpc", "trigger")

// StartTriggerListener starts an authenticated UDP trigger listener
// as a Sliver job. Follows the same pattern as StartMTLSListener:
// validate, PortInUse precheck, call factory, persist the listener
// config via db.SaveC2Listener so it survives restart, return a
// minimal ListenerJob with the new JobID.
func (rpc *Server) StartTriggerListener(ctx context.Context, req *clientpb.TriggerListenerReq) (*clientpb.ListenerJob, error) {
	if req == nil {
		return nil, rpcError(errors.New("nil request"))
	}
	if req.Port == 0 {
		return nil, rpcError(errors.New("port must be set"))
	}
	if 65535 < req.Port {
		return nil, ErrInvalidPort
	}
	if err := PortInUse(req.Port); err != nil {
		return nil, rpcError(err)
	}

	job, err := c2.StartTriggerListenerJob(req)
	if err != nil {
		return nil, rpcError(err)
	}

	listenerJob := &clientpb.ListenerJob{
		JobID:       uint32(job.ID),
		Type:        constants.TriggerStr,
		TriggerConf: req,
	}
	if err := db.SaveC2Listener(listenerJob); err != nil {
		return nil, rpcError(err)
	}

	return &clientpb.ListenerJob{JobID: uint32(job.ID)}, nil
}

// TriggerDispatchTask fires a named task handler on a running trigger
// listener, bypassing the UDP wire protocol entirely. This is the
// server-side implementation of "trigger send <job-id> <task-name>",
// allowing operators to dispatch tasks interactively from the sliver
// console.
func (rpc *Server) TriggerDispatchTask(ctx context.Context, req *clientpb.TriggerDispatchTaskReq) (*commonpb.Empty, error) {
	if req == nil {
		return nil, rpcError(errors.New("nil request"))
	}
	if req.TaskName == "" {
		return nil, rpcError(errors.New("task name must be set"))
	}
	if err := c2.DispatchTaskForJob(int(req.JobID), req.TaskName); err != nil {
		return nil, rpcError(err)
	}
	return &commonpb.Empty{}, nil
}

// TriggerFire constructs a signed trigger packet and sends it as a
// single UDP datagram to the specified target, enabling operators to
// wake dormant implants, fire implant-side self-destruct, or execute
// commands on dormant implants entirely from the sliver console.
//
// For bidirectional intents (exec), the server waits for a response
// from the implant and returns the output in TriggerFireResp.
func (rpc *Server) TriggerFire(ctx context.Context, req *clientpb.TriggerFireReq) (*clientpb.TriggerFireResp, error) {
	if req == nil {
		return nil, rpcError(errors.New("nil request"))
	}
	if req.TargetHost == "" {
		return nil, rpcError(errors.New("target host must be set"))
	}
	if req.TargetPort == 0 || req.TargetPort > 65535 {
		return nil, rpcError(errors.New("target port must be 1-65535"))
	}
	if req.Intent == "" {
		return nil, rpcError(errors.New("intent must be set"))
	}
	if len(req.SharedSecret) == 0 {
		return nil, rpcError(errors.New("shared secret must be set"))
	}

	// "connect" intent: direct server→implant connection (no UDP trigger).
	// Used by "trigger connect" command to attach to an existing bind port.
	if req.Intent == "connect" {
		proto, port, err := parseBindAddress(req.Payload)
		if err != nil {
			return nil, rpcError(fmt.Errorf("invalid bind address %q: %w", req.Payload, err))
		}
		triggerRPCLog.Infof("trigger connect: %s:%d (proto=%s)", req.TargetHost, port, proto)
		go func() {
			if err := c2.ConnectToBindImplant(req.TargetHost, port, req.SharedSecret, proto); err != nil {
				triggerRPCLog.Errorf("trigger connect failed: %v", err)
			}
		}()
		return &clientpb.TriggerFireResp{Sent: true}, nil
	}

	clientID := req.ClientID
	if clientID == "" {
		clientID = "sliver-operator"
	}
	result, err := c2.FireTriggerPacket(
		req.TargetHost,
		int(req.TargetPort),
		req.Intent,
		string(req.SharedSecret),
		clientID,
		req.Payload,
	)
	if err != nil {
		return nil, rpcError(err)
	}

	// Record activity for the TTL reaper. Best-effort: a DB error here
	// must not block the operator's fire command.
	go recordTriggerActivity(req.SharedSecret, req.TargetHost, req.TargetPort)

	// For bind intents: the implant responded with the actual bind
	// address (e.g., "tcp://0.0.0.0:52341" or "udp://0.0.0.0:41337").
	// The server automatically connects unless the payload contains
	// "noconnect" (operator used --no-connect).
	if req.Intent == "bind" && result.Output != "" && result.Error == "" {
		noConnect := strings.Contains(req.Payload, "noconnect")
		if !noConnect {
			proto, port, err := parseBindAddress(result.Output)
			if err == nil {
				triggerRPCLog.Infof("bind response received, connecting to %s:%d (proto=%s)", req.TargetHost, port, proto)
				go func() {
					if err := c2.ConnectToBindImplant(req.TargetHost, port, req.SharedSecret, proto); err != nil {
						triggerRPCLog.Errorf("bind connect failed: %v", err)
					}
				}()
			}
		} else {
			triggerRPCLog.Infof("bind response received (no-connect mode): %s", result.Output)
		}
	}

	return &clientpb.TriggerFireResp{
		Sent:     result.Sent,
		Output:   result.Output,
		ExitCode: int32(result.ExitCode),
		Error:    result.Error,
	}, nil
}

// parseBindAddress extracts the protocol and port from a bind response.
// Format: "tcp://0.0.0.0:52341" or "udp://0.0.0.0:4444".
// Returns (protocol, port, error).
func parseBindAddress(bindAddr string) (string, int, error) {
	proto := "tcp"
	addr := bindAddr
	if idx := strings.Index(addr, "://"); idx >= 0 {
		proto = addr[:idx]
		addr = addr[idx+3:]
	}
	// Extract port from host:port.
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", 0, errors.New("missing port in address")
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return "", 0, err
	}
	return proto, port, nil
}

// TriggerIntents returns the task bindings registered against a
// running trigger listener job. Operators use this to verify what a
// listener will accept and dispatch.
func (rpc *Server) TriggerIntents(ctx context.Context, req *clientpb.TriggerIntentsReq) (*clientpb.TriggerIntents, error) {
	if req == nil {
		return nil, rpcError(errors.New("nil request"))
	}
	bindings, ok := c2.BindingsForJob(int(req.JobID))
	if !ok {
		return nil, rpcError(errors.New("no trigger listener with that job ID"))
	}
	return &clientpb.TriggerIntents{
		JobID:    req.JobID,
		Bindings: bindings,
	}, nil
}

// recordTriggerActivity looks up the ImplantConfig(s) matching the
// shared secret used in a TriggerFire call and upserts a
// TriggerActivity record for each. This feeds the server-side TTL
// reaper with last-known target locations.
//
// Runs in a goroutine so DB latency never blocks the operator.
func recordTriggerActivity(secret []byte, targetHost string, targetPort uint32) {
	configs, err := db.ImplantConfigsByTriggerSecret(secret)
	if err != nil {
		triggerRPCLog.Warnf("trigger activity: failed to look up configs by secret: %v", err)
		return
	}
	if len(configs) == 0 {
		// No matching config -- could be a standalone trigger fire with
		// a secret not baked into any implant. Not an error.
		return
	}
	for _, cfg := range configs {
		configID := cfg.ID.String()
		// Try to find a friendly build name.
		buildName := configID
		build, err := db.ImplantBuildByConfigID(configID)
		if err == nil && build != nil {
			buildName = build.Name
		}
		if err := db.UpsertTriggerActivity(configID, buildName, targetHost, targetPort); err != nil {
			triggerRPCLog.Warnf("trigger activity: upsert failed for config %s: %v", configID, err)
		} else {
			triggerRPCLog.Debugf("trigger activity: recorded %s:%d for config %s (%s)",
				targetHost, targetPort, configID, buildName)
		}
	}
}
