package mknet

import (
	"fmt"
	"sort"

	"mk-lattigo/mkbfv"
	"mk-lattigo/mkrlwe"

	"github.com/ldsec/lattigo/v2/ring"
)

// ---------- ciphertexts ----------

// MarshalCiphertext serializes an mkrlwe.Ciphertext deterministically:
// map keys are sorted ("0" < "P1" < "P2") so both parties produce identical
// bytes, and each ring.Poly self-describes its NTT/MForm flags and limb count
// (lattigo ring.Poly MarshalBinary, 4B header + 8B per coefficient per limb).
//
//	idCount u8 | (idLen u8 + id)* | polyCount u8 | poly MarshalBinary*
//
// (polyCount always equals idCount: the map holds "0" plus one entry per id.)
func MarshalCiphertext(ct *mkrlwe.Ciphertext) ([]byte, error) {
	ids := make([]string, 0, len(ct.Value))
	for id := range ct.Value {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	buf := make([]byte, 0, 16+ct.Value["0"].GetDataLen(true)*len(ids))
	buf = append(buf, byte(len(ids)))
	for _, id := range ids {
		buf = append(buf, byte(len(id)))
		buf = append(buf, id...)
	}
	buf = append(buf, byte(len(ids)))
	for _, id := range ids {
		b, err := ct.Value[id].MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

// UnmarshalCiphertext is the inverse of MarshalCiphertext.
func UnmarshalCiphertext(b []byte) (*mkrlwe.Ciphertext, error) {
	if len(b) < 2 {
		return nil, errBadFrame
	}
	n := int(b[0])
	off := 1
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if off >= len(b) {
			return nil, errBadFrame
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return nil, errBadFrame
		}
		ids = append(ids, string(b[off:off+l]))
		off += l
	}
	if off >= len(b) || int(b[off]) != n {
		return nil, errBadFrame
	}
	off++

	ct := new(mkrlwe.Ciphertext)
	ct.Value = make(map[string]*ring.Poly, n)
	for _, id := range ids {
		poly, next, err := readPoly(b, off)
		if err != nil {
			return nil, err
		}
		ct.Value[id] = poly
		off = next
	}
	return ct, nil
}

// MarshalCTBatch frames count ciphertexts back-to-back (count u32 first).
func MarshalCTBatch(cts []*mkrlwe.Ciphertext) ([]byte, error) {
	buf := make([]byte, 4, 16*len(cts))
	buf[0] = byte(len(cts) >> 24)
	buf[1] = byte(len(cts) >> 16)
	buf[2] = byte(len(cts) >> 8)
	buf[3] = byte(len(cts))
	for i, ct := range cts {
		b, err := MarshalCiphertext(ct)
		if err != nil {
			return nil, fmt.Errorf("ciphertext %d: %w", i, err)
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

// UnmarshalCTBatch is the inverse of MarshalCTBatch.
func UnmarshalCTBatch(b []byte) ([]*mkrlwe.Ciphertext, error) {
	if len(b) < 4 {
		return nil, errBadFrame
	}
	n := int(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	cts := make([]*mkrlwe.Ciphertext, 0, n)
	off := 4
	for i := 0; i < n; i++ {
		ct, next, err := readCiphertext(b, off)
		if err != nil {
			return nil, fmt.Errorf("ciphertext %d: %w", i, err)
		}
		cts = append(cts, ct)
		off = next
	}
	return cts, nil
}

// readCiphertext decodes one MarshalCiphertext record at offset off and
// returns the offset just past it.
func readCiphertext(b []byte, off int) (*mkrlwe.Ciphertext, int, error) {
	if off >= len(b) {
		return nil, 0, errBadFrame
	}
	n := int(b[off])
	p := off + 1
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if p >= len(b) {
			return nil, 0, errBadFrame
		}
		l := int(b[p])
		p++
		if p+l > len(b) {
			return nil, 0, errBadFrame
		}
		ids = append(ids, string(b[p:p+l]))
		p += l
	}
	if p >= len(b) || int(b[p]) != n {
		return nil, 0, errBadFrame
	}
	p++

	ct := new(mkrlwe.Ciphertext)
	ct.Value = make(map[string]*ring.Poly, n)
	for _, id := range ids {
		poly, next, err := readPoly(b, p)
		if err != nil {
			return nil, 0, err
		}
		ct.Value[id] = poly
		p = next
	}
	return ct, p, nil
}

// readPoly decodes one ring.Poly at offset off: the 4-byte header gives N and
// the limb count, so the record size is 4 + 8*N*limbs.
func readPoly(b []byte, off int) (*ring.Poly, int, error) {
	if off+4 > len(b) {
		return nil, 0, errBadFrame
	}
	n := 1 << b[off]
	limbs := int(b[off+1])
	size := 4 + 8*n*limbs
	if off+size > len(b) {
		return nil, 0, errBadFrame
	}
	poly := new(ring.Poly)
	if err := poly.UnmarshalBinary(b[off : off+size]); err != nil {
		return nil, 0, err
	}
	return poly, off + size, nil
}

// ---------- relinearization keys ----------

// rlkSlots lists the (outer, inner) switching-key indices that
// mkbfv.GenRelinearizationKey actually fills (keygen.go): b1, d1, v, b2, d2.
// The remaining slot [1][2] stays zero and is not transmitted
// (pn14: 5 x 6 MiB = 30 MiB per party instead of 36 MiB).
var rlkSlots = [5][2]int{{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}}

// MarshalRLK serializes an mkbfv relinearization key:
//
//	idLen u8 | id | for each of the 5 slots: for i in 0..beta-1:
//	  polyQ MarshalBinary | polyP MarshalBinary
//
// beta is implied by the receiver's parameters and validated on decode.
func MarshalRLK(rlk *mkbfv.RelinearizationKey) ([]byte, error) {
	buf := []byte{byte(len(rlk.ID))}
	buf = append(buf, rlk.ID...)
	for _, slot := range rlkSlots {
		swk := rlk.Value[slot[0]].Value[slot[1]]
		for i := range swk.Value {
			q, err := swk.Value[i].Q.MarshalBinary()
			if err != nil {
				return nil, err
			}
			buf = append(buf, q...)
			p, err := swk.Value[i].P.MarshalBinary()
			if err != nil {
				return nil, err
			}
			buf = append(buf, p...)
		}
	}
	return buf, nil
}

// UnmarshalRLK decodes into a fresh zero rlk allocated with params (the
// poly pointers from the wire replace the allocated ones; the unused [1][2]
// slot stays zero, matching the state after local GenRelinearizationKey).
func UnmarshalRLK(b []byte, params mkbfv.Parameters) (*mkbfv.RelinearizationKey, error) {
	if len(b) < 1 {
		return nil, errBadFrame
	}
	l := int(b[0])
	if 1+l > len(b) {
		return nil, errBadFrame
	}
	id := string(b[1 : 1+l])
	off := 1 + l

	rlk := mkbfv.NewRelinearizationKey(params, id)
	for _, slot := range rlkSlots {
		swk := rlk.Value[slot[0]].Value[slot[1]]
		for i := range swk.Value {
			q, next, err := readPoly(b, off)
			if err != nil {
				return nil, fmt.Errorf("swk[%d][%d].%d Q: %w", slot[0], slot[1], i, err)
			}
			p, next2, err := readPoly(b, next)
			if err != nil {
				return nil, fmt.Errorf("swk[%d][%d].%d P: %w", slot[0], slot[1], i, err)
			}
			swk.Value[i].Q = q
			swk.Value[i].P = p
			off = next2
		}
	}
	if off != len(b) {
		return nil, fmt.Errorf("rlk: %d trailing bytes", len(b)-off)
	}
	return rlk, nil
}
