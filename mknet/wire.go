// Package mknet implements the real two-party network transport for the
// MK-BFV computation scenarios (mkbfv/scenarios.go): each party runs in its
// own process, the hostfile lists the parties' ip:port in order, and the two
// processes talk over a plain TCP socket using the frame protocol below.
//
// Wire protocol (all integers big-endian):
//
//	frame   = magic "MKN1" (4B) | msgType (1B) | payloadLen (4B) | payload
//	HELLO   = ver u8=1 | scenario u8 | eval u8 | receiver u8
//	        | confLen u8 | conf | seedLen u8 | seed (32B from P1, empty from P2)
//	BOUND   = records u64 | K u32 | maxAbs[K] u64   (per-column |value| max)
//	RLK     = see marshal.go (MarshalRLK, 5 switching keys)
//	CT_BATCH= count u32 | ciphertexts back-to-back (see MarshalCiphertext)
//	DONE    = empty
//	ERROR   = error text (forwarded to the peer before aborting)
//
// The CRS seed travels inside HELLO and is the ONLY coordination needed for
// both parties to derive identical parameters: mkbfv.NewParametersFromLiteralSeeded
// expands it into all CRS elements, which key generation embeds into pk/rlk.
package mknet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const frameMagic = "MKN1"

// Message types.
const (
	MsgHello    byte = 0x01 // session metadata + CRS seed
	MsgBound    byte = 0x02 // per-column data bounds (T derivation)
	MsgRLK      byte = 0x03 // one party's relinearization key
	MsgCTBatch  byte = 0x04 // a batch of ciphertexts
	MsgDone     byte = 0x05 // clean shutdown
	MsgError    byte = 0x7F // peer-side error text
)

const maxPayload = 0xFFFFFFFF // u32 frame length (pn15 rlk ~180 MiB fits)

var errBadFrame = errors.New("mknet: bad frame header")

// WriteMsg writes one frame. The payload is written in two calls to avoid
// concatenating multi-MiB buffers.
func WriteMsg(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > maxPayload {
		return fmt.Errorf("mknet: payload too large (%d bytes)", len(payload))
	}
	var head [9]byte
	copy(head[:4], frameMagic)
	head[4] = msgType
	binary.BigEndian.PutUint32(head[5:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadMsg reads one frame and returns its type and payload.
func ReadMsg(r io.Reader) (msgType byte, payload []byte, err error) {
	var head [9]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	if string(head[:4]) != frameMagic {
		return 0, nil, errBadFrame
	}
	n := binary.BigEndian.Uint32(head[5:])
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[4], payload, nil
}

// ---------- HELLO / BOUND payload codecs ----------

// Hello is the session metadata exchanged in both directions right after
// connect. Seed carries the 32-byte CRS seed and is non-empty only in the
// message sent by party 1 (who draws it from crypto/rand).
type Hello struct {
	Ver      byte
	Scenario byte
	Eval     byte
	Recv     byte
	Conf     string
	Seed     []byte
}

func (h Hello) encode() []byte {
	buf := []byte{h.Ver, h.Scenario, h.Eval, h.Recv}
	buf = append(buf, byte(len(h.Conf)))
	buf = append(buf, h.Conf...)
	buf = append(buf, byte(len(h.Seed)))
	buf = append(buf, h.Seed...)
	return buf
}

func decodeHello(b []byte) (Hello, error) {
	h := Hello{}
	if len(b) < 6 {
		return h, errBadFrame
	}
	h.Ver, h.Scenario, h.Eval, h.Recv = b[0], b[1], b[2], b[3]
	cl := int(b[4])
	if len(b) < 5+cl+1 {
		return h, errBadFrame
	}
	h.Conf = string(b[5 : 5+cl])
	sl := int(b[5+cl])
	b = b[5+cl+1:]
	if len(b) != sl {
		return h, errBadFrame
	}
	h.Seed = append([]byte{}, b...)
	return h, nil
}

// Bound is the data-range summary exchanged so that both sides derive the
// identical plaintext modulus T (mkbfv.MinT / MinTSumProduct / FindPrimeT).
type Bound struct {
	Records uint64
	MaxAbs  []uint64 // per-column max |value| of the sender's own input
}

func (m Bound) encode() []byte {
	buf := make([]byte, 0, 12+8*len(m.MaxAbs))
	buf = binary.BigEndian.AppendUint64(buf, m.Records)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(m.MaxAbs)))
	for _, v := range m.MaxAbs {
		buf = binary.BigEndian.AppendUint64(buf, v)
	}
	return buf
}

func decodeBound(b []byte) (Bound, error) {
	m := Bound{}
	if len(b) < 12 {
		return m, errBadFrame
	}
	m.Records = binary.BigEndian.Uint64(b)
	k := int(binary.BigEndian.Uint32(b[8:12]))
	b = b[12:]
	if len(b) != k*8 {
		return m, errBadFrame
	}
	m.MaxAbs = make([]uint64, k)
	for i := range m.MaxAbs {
		m.MaxAbs[i] = binary.BigEndian.Uint64(b[i*8:])
	}
	return m, nil
}
