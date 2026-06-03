// SPDX-License-Identifier: GPL-3.0-or-later
//
// Package protocol defines the wire format and HMAC signing for the
// trigger protocol. It is import-safe from both server and client code
// and has no transport or I/O dependencies.
//
// Wire format is JSON-over-UDP. The canonical signable payload is the
// JSON encoding of a map containing the fields {version, client_id,
// nonce, timestamp, intent} in Go's deterministic alphabetical key
// order. The HMAC-SHA256 of that payload is hex-encoded and attached
// as the "signature" field of the wire message.
package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ProtocolVersion is the current wire-protocol version. Any change to
// the canonical signable layout, field set, or HMAC scheme MUST bump
// this constant — receivers reject unknown versions outright.
const ProtocolVersion = 1

// Bounds enforced by ValidateStructure. Tight enough to keep the wire
// format compact and reject obvious abuse; loose enough that operators
// don't trip over them by accident.
const (
	NonceMinLength     = 16
	SignatureHexLength = 64
	ClientIDMaxLength  = 128
	IntentMaxLength    = 128
)

// TriggerMessage is the on-wire structure operators send.
type TriggerMessage struct {
	Version   int    `json:"version"`
	ClientID  string `json:"client_id"`
	Nonce     string `json:"nonce"`
	Timestamp string `json:"timestamp"`
	Intent    string `json:"intent"`
	Signature string `json:"signature,omitempty"`
}

// NowUTC returns the current UTC time formatted to RFC3339 nanoseconds.
// All on-wire timestamps use this format.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// ParseTimestamp parses an RFC3339Nano timestamp and converts to UTC.
func ParseTimestamp(ts string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp: %w", err)
	}
	return parsed.UTC(), nil
}

// GenerateNonce returns a 16-byte cryptographically random nonce,
// hex-encoded to a 32-character string.
func GenerateNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed generating nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func validateSignature(signature string) error {
	if len(signature) != SignatureHexLength || !isHexString(signature) {
		return fmt.Errorf("signature must be a %d-character hex digest", SignatureHexLength)
	}
	return nil
}

// ValidateStructure checks every field of a TriggerMessage against the
// protocol's structural constraints. It does NOT verify the signature
// or check the timestamp against wall-clock skew — those are caller
// responsibilities.
func ValidateStructure(msg TriggerMessage) error {
	if msg.Version != ProtocolVersion {
		return fmt.Errorf("unsupported version %d, expected %d", msg.Version, ProtocolVersion)
	}
	if msg.ClientID == "" {
		return errors.New("client_id must be set")
	}
	if len(msg.ClientID) > ClientIDMaxLength {
		return fmt.Errorf("client_id must be at most %d characters", ClientIDMaxLength)
	}
	if len(msg.Nonce) < NonceMinLength {
		return fmt.Errorf("nonce must be at least %d characters", NonceMinLength)
	}
	if !isHexString(msg.Nonce) {
		return errors.New("nonce must be hexadecimal")
	}
	if msg.Intent == "" {
		return errors.New("intent must be set")
	}
	if len(msg.Intent) > IntentMaxLength {
		return fmt.Errorf("intent must be at most %d characters", IntentMaxLength)
	}
	if msg.Timestamp == "" {
		return errors.New("timestamp must be set")
	}
	if _, err := ParseTimestamp(msg.Timestamp); err != nil {
		return err
	}
	if msg.Signature != "" {
		if err := validateSignature(msg.Signature); err != nil {
			return err
		}
	}
	return nil
}

// canonicalSignableJSON returns the deterministic JSON payload used as
// the HMAC input. Go's json.Marshal on a map emits keys in alphabetical
// order, which is the cross-language contract: any other implementation
// of this protocol MUST emit the same byte sequence for the same input.
func canonicalSignableJSON(msg TriggerMessage) ([]byte, error) {
	payload := map[string]interface{}{
		"version":   msg.Version,
		"client_id": msg.ClientID,
		"nonce":     msg.Nonce,
		"timestamp": msg.Timestamp,
		"intent":    msg.Intent,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling signable payload: %w", err)
	}
	return b, nil
}

// Sign computes the HMAC-SHA256 signature over the canonical signable
// JSON of msg, using sharedSecret as the key. The returned signature is
// hex-encoded. The msg's existing Signature field is ignored.
func Sign(msg TriggerMessage, sharedSecret string) (string, error) {
	if sharedSecret == "" {
		return "", errors.New("shared secret must be set")
	}
	if err := ValidateStructure(msg); err != nil {
		return "", err
	}

	body, err := canonicalSignableJSON(msg)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(sharedSecret))
	if _, err := mac.Write(body); err != nil {
		return "", fmt.Errorf("failed computing hmac: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify recomputes the expected signature for msg using sharedSecret
// and compares it to msg.Signature in constant time. Returns false
// without error if Signature is empty.
func Verify(msg TriggerMessage, sharedSecret string) (bool, error) {
	if msg.Signature == "" {
		return false, nil
	}
	expected, err := Sign(msg, sharedSecret)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(expected), []byte(msg.Signature)), nil
}

// EncodeWire returns the on-wire JSON encoding of msg, validating
// structure first.
func EncodeWire(msg TriggerMessage) ([]byte, error) {
	if err := ValidateStructure(msg); err != nil {
		return nil, err
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling message: %w", err)
	}
	return b, nil
}

// DecodeWire parses raw bytes as a TriggerMessage and validates the
// structure. The signature, if present, is NOT verified here — call
// Verify separately so the caller controls when HMAC compute happens
// in the validation pipeline.
func DecodeWire(raw []byte) (TriggerMessage, error) {
	var msg TriggerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return TriggerMessage{}, fmt.Errorf("invalid JSON payload: %w", err)
	}
	if err := ValidateStructure(msg); err != nil {
		return TriggerMessage{}, err
	}
	return msg, nil
}
