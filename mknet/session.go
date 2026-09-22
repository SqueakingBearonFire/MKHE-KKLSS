package mknet

import (
	"crypto/rand"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"mk-lattigo/mkbfv"
	"mk-lattigo/mkrlwe"
)

// Config configures one party of a two-party networked session.
type Config struct {
	SelfIdx  int    // this process is party SelfIdx (1 or 2)
	EvalIdx  int    // the evaluator party (1 or 2, default 1 at the CLI)
	RecvIdx  int    // the result receiver party (1 or 2, default 1 at the CLI)
	Scenario int    // 1 | 2 | 3 (mkbfv.Scenario*)
	ConfName string // "pn14" | "pn15"
	Literal  mkbfv.ParametersLiteral
	// T is overwritten with the modulus derived from the BOUND handshake.

	Hosts  []string // hostfile entries (party order)
	P1CSV  string   // P1 data CSV (read by party 1; receiver reads it too when Verify)
	P2CSV  string   // P2 input CSV (read by party 2; receiver reads it too when Verify)
	OutCSV string   // written by the receiver
	Verify bool     // receiver verifies against local plaintext (test only)
}

// Stats holds the per-phase timings and measured socket traffic of one party.
type Stats struct {
	Connect, Handshake, CRS, Keygen   time.Duration
	RlkXfer, EncOwn, InputXfer        time.Duration
	Eval, Result                      time.Duration
	MulOps, AddOps                    int
	Sent, Recv                        uint64 // total socket bytes
	PhaseSent, PhaseRecv              map[string]uint64
	T                                 uint64
	Records, K, CtsPerCol             int
	Mismatch                          int
	FirstMismatch                     string
}

func fmtMiB(b uint64) string { return fmt.Sprintf("%.2f MiB", float64(b)/1024/1024) }

// RunParty runs one party of the two-party protocol end to end and returns
// its stats. Either the evaluator or the receiver role (or both, or neither)
// belongs to this party; see the four message flows inside.
func RunParty(cfg Config) (*Stats, error) {
	st := &Stats{PhaseSent: map[string]uint64{}, PhaseRecv: map[string]uint64{}}
	selfID := fmt.Sprintf("P%d", cfg.SelfIdx)
	evalID := fmt.Sprintf("P%d", cfg.EvalIdx)
	recvID := fmt.Sprintf("P%d", cfg.RecvIdx)

	logf := func(format string, args ...interface{}) {
		fmt.Printf("[mknet] "+format+"\n", args...)
	}
	fail := func(fc *framedConn, format string, args ...interface{}) error {
		err := fmt.Errorf(format, args...)
		if fc != nil {
			fc.write(MsgError, []byte(err.Error()))
		}
		return err
	}

	// -------- load this party's own input --------
	var dCols, wCols [][]int64 // P1 columns / P2 columns (scenarios 2,3)
	var ws []int64             // scenario 1 weights
	var k int
	var myRows uint64
	if cfg.SelfIdx == 1 {
		_, cols, err := readIntCSV(cfg.P1CSV)
		if err != nil {
			return nil, fmt.Errorf("read p1: %w", err)
		}
		dCols = cols
		k = len(dCols)
		myRows = uint64(len(dCols[0]))
	} else {
		_, cols, err := readIntCSV(cfg.P2CSV)
		if err != nil {
			return nil, fmt.Errorf("read p2: %w", err)
		}
		if cfg.Scenario == mkbfv.ScenarioWeightedSum {
			if len(cols[0]) != 1 {
				return nil, fmt.Errorf("%s: scenario 1 needs exactly one row of weights", cfg.P2CSV)
			}
			ws = make([]int64, len(cols))
			for c := range ws {
				ws[c] = cols[c][0]
			}
			myRows = 1
		} else {
			wCols = cols
			myRows = uint64(len(cols[0]))
		}
		k = len(cols)
	}
	if k == 0 {
		return nil, errors.New("empty input CSV")
	}

	// -------- connect --------
	t0 := time.Now()
	conn, err := Connect(cfg.Hosts, cfg.SelfIdx)
	if err != nil {
		return nil, err
	}
	st.Connect = time.Since(t0)
	fc := newFramedConn(conn)
	defer conn.Close()
	logf("connected to peer as %s (%s <-> %s)", selfID, cfg.Hosts[cfg.SelfIdx-1], cfg.Hosts[2-cfg.SelfIdx])

	snap := func() (uint64, uint64) { return conn.SentBytes(), conn.RecvBytes() }
	phase := func(name string, s0, r0 uint64) {
		st.PhaseSent[name] = conn.SentBytes() - s0
		st.PhaseRecv[name] = conn.RecvBytes() - r0
	}

	// -------- HELLO: exchange session metadata + CRS seed --------
	hs0, hr0 := snap()
	t0 = time.Now()
	hello := Hello{Ver: 1, Scenario: byte(cfg.Scenario), Eval: byte(cfg.EvalIdx),
		Recv: byte(cfg.RecvIdx), Conf: cfg.ConfName}
	if cfg.SelfIdx == 1 {
		hello.Seed = make([]byte, 32)
		if _, err := rand.Read(hello.Seed); err != nil {
			return nil, err
		}
	}
	if err := fc.write(MsgHello, hello.encode()); err != nil {
		return nil, fail(nil, "send hello: %w", err)
	}
	msgType, payload, err := fc.read()
	if err != nil {
		return nil, fail(nil, "recv hello: %w", err)
	}
	if msgType == MsgError {
		return nil, fmt.Errorf("remote error: %s", payload)
	}
	if msgType != MsgHello {
		return nil, fail(fc, "expected HELLO, got message type 0x%02x", msgType)
	}
	peerHello, err := decodeHello(payload)
	if err != nil {
		return nil, fail(fc, "decode hello: %w", err)
	}
	if peerHello.Ver != 1 || int(peerHello.Scenario) != cfg.Scenario ||
		int(peerHello.Eval) != cfg.EvalIdx || int(peerHello.Recv) != cfg.RecvIdx ||
		peerHello.Conf != cfg.ConfName {
		return nil, fail(fc, "peer session mismatch: local {scenario=%d eval=%d recv=%d conf=%s} vs peer {scenario=%d eval=%d recv=%d conf=%s}",
			cfg.Scenario, cfg.EvalIdx, cfg.RecvIdx, cfg.ConfName,
			peerHello.Scenario, peerHello.Eval, peerHello.Recv, peerHello.Conf)
	}
	var crsSeed []byte
	if cfg.SelfIdx == 1 {
		if len(peerHello.Seed) != 0 {
			return nil, fail(fc, "party 2 must not carry a CRS seed in HELLO")
		}
		crsSeed = hello.Seed
	} else {
		if len(peerHello.Seed) != 32 {
			return nil, fail(fc, "party 1 HELLO must carry a 32-byte CRS seed")
		}
		crsSeed = peerHello.Seed
	}

	// -------- BOUND: exchange per-column data bounds, derive T --------
	myBound := Bound{Records: myRows}
	if cfg.SelfIdx == 1 {
		myBound.MaxAbs = colAbsMaxPerCol(dCols)
	} else if cfg.Scenario == mkbfv.ScenarioWeightedSum {
		myBound.MaxAbs = colAbsMaxPerCol(oneRowCols(ws))
	} else {
		myBound.MaxAbs = colAbsMaxPerCol(wCols)
	}
	if err := fc.write(MsgBound, myBound.encode()); err != nil {
		return nil, fail(nil, "send bound: %w", err)
	}
	msgType, payload, err = fc.read()
	if err != nil {
		return nil, fail(nil, "recv bound: %w", err)
	}
	if msgType == MsgError {
		return nil, fmt.Errorf("remote error: %s", payload)
	}
	if msgType != MsgBound {
		return nil, fail(fc, "expected BOUND, got message type 0x%02x", msgType)
	}
	peerBound, err := decodeBound(payload)
	if err != nil {
		return nil, fail(fc, "decode bound: %w", err)
	}
	if len(peerBound.MaxAbs) != k {
		return nil, fail(fc, "peer has %d columns, we have %d", len(peerBound.MaxAbs), k)
	}
	if cfg.Scenario != mkbfv.ScenarioWeightedSum {
		a, b := myRows, peerBound.Records
		if cfg.SelfIdx == 2 {
			a, b = peerBound.Records, myRows // P1's count is authoritative
		}
		if a != b {
			return nil, fail(fc, "row count mismatch: P1 %d vs P2 %d", a, b)
		}
	}
	maxD, maxW := maxOf(myBound.MaxAbs), maxOf(peerBound.MaxAbs)
	if cfg.SelfIdx == 2 {
		maxD, maxW = maxOf(peerBound.MaxAbs), maxOf(myBound.MaxAbs)
	}
	var minT uint64
	if cfg.Scenario == mkbfv.ScenarioSumProduct {
		minT = mkbfv.MinTSumProduct(k, maxD, maxW)
	} else {
		minT = mkbfv.MinT(k, maxD, maxW)
	}
	T := mkbfv.FindPrimeT(minT)
	if T > cfg.Literal.Q[0] {
		return nil, fail(fc, "data range too large for %s: need T>=%d but lattigo requires T<=Q[0]=%d (|d|max=%d |w|max=%d K=%d); reduce values or use CRT limbs",
			cfg.ConfName, T, cfg.Literal.Q[0], maxD, maxW, k)
	}
	cfg.Literal.T = T
	st.T = T
	st.Handshake = time.Since(t0)
	st.K = k
	phase("handshake", hs0, hr0)
	logf("handshake done: scenario=%d (%s) eval=%s recv=%s conf=%s T=%d (%d bits)",
		cfg.Scenario, mkbfv.ScenarioName(cfg.Scenario), evalID, recvID, cfg.ConfName,
		T, uint64Len(T))

	// -------- parameters + CRS (deterministic from the shared seed) --------
	t0 = time.Now()
	params := mkbfv.NewParametersFromLiteralSeeded(cfg.Literal, crsSeed)
	st.CRS = time.Since(t0)
	logf("params+CRS (seeded, identical on both sides): %v", st.CRS)

	records := int(peerBound.Records)
	if cfg.SelfIdx == 1 {
		records = int(myRows)
	}
	slots := params.N()
	ctsPerCol := (records + slots - 1) / slots
	st.Records, st.CtsPerCol = records, ctsPerCol

	// -------- per-party keygen (own secret keys, shared CRS) --------
	t0 = time.Now()
	kgen := mkbfv.NewKeyGenerator(params)
	enc := mkbfv.NewEncryptor(params)
	dec := mkbfv.NewDecryptor(params)
	sk, pk := kgen.GenKeyPair(selfID)
	r := kgen.GenSecretKey(selfID)
	rlk := kgen.GenRelinearizationKey(sk, r)
	st.Keygen = time.Since(t0)
	logf("keygen (%s): %v", selfID, st.Keygen)

	// -------- rlk transfer: non-evaluator -> evaluator --------
	t0 = time.Now()
	s0, r0 := snap()
	var rlkSet *mkbfv.RelinearizationKeySet
	if cfg.SelfIdx == cfg.EvalIdx {
		rlkSet = mkbfv.NewRelinearizationKeyKeySet(params)
		rlkSet.AddRelinearizationKey(rlk)
		msgType, payload, err = fc.read()
		if err != nil {
			return nil, fail(nil, "recv rlk: %w", err)
		}
		if msgType == MsgError {
			return nil, fmt.Errorf("remote error: %s", payload)
		}
		if msgType != MsgRLK {
			return nil, fail(fc, "expected RLK, got message type 0x%02x", msgType)
		}
		peerRlk, err := UnmarshalRLK(payload, params)
		if err != nil {
			return nil, fail(fc, "decode rlk: %w", err)
		}
		rlkSet.AddRelinearizationKey(peerRlk)
	} else {
		payload, err := MarshalRLK(rlk)
		if err != nil {
			return nil, fail(nil, "marshal rlk: %w", err)
		}
		if err := fc.write(MsgRLK, payload); err != nil {
			return nil, fail(nil, "send rlk: %w", err)
		}
	}
	st.RlkXfer = time.Since(t0)
	phase("rlk", s0, r0)
	logf("rlk %s: %v | sent %s recv %s", map[bool]string{true: "recv", false: "send"}[cfg.SelfIdx == cfg.EvalIdx],
		st.RlkXfer, fmtMiB(st.PhaseSent["rlk"]), fmtMiB(st.PhaseRecv["rlk"]))

	// -------- encrypt this party's own input --------
	t0 = time.Now()
	var ctD [][]*mkbfv.Ciphertext       // P1 data cts [k][ctsPerCol]
	var ctW []*mkbfv.Ciphertext         // scenario 1 weights [k]
	var ctWcols [][]*mkbfv.Ciphertext   // scenarios 2/3 P2 columns [k][ctsPerCol]
	var ownCts []*mkrlwe.Ciphertext     // flat view for the wire
	if cfg.SelfIdx == 1 {
		ctD = encryptColumns(enc, params, pk, dCols, records, slots)
		for _, col := range ctD {
			for _, ct := range col {
				ownCts = append(ownCts, ct.Ciphertext)
			}
		}
	} else if cfg.Scenario == mkbfv.ScenarioWeightedSum {
		ctW = make([]*mkbfv.Ciphertext, k)
		for c := range ctW {
			msg := mkbfv.NewMessage(params)
			for i := range msg.Value {
				msg.Value[i] = ws[c]
			}
			ctW[c] = enc.EncryptMsgNew(msg, pk)
			ownCts = append(ownCts, ctW[c].Ciphertext)
		}
	} else {
		ctWcols = encryptColumns(enc, params, pk, wCols, records, slots)
		for _, col := range ctWcols {
			for _, ct := range col {
				ownCts = append(ownCts, ct.Ciphertext)
			}
		}
	}
	st.EncOwn = time.Since(t0)
	logf("own input encrypted (%d cts): %v", len(ownCts), st.EncOwn)

	// -------- input transfer: non-evaluator -> evaluator --------
	t0 = time.Now()
	s0, r0 = snap()
	if cfg.SelfIdx == cfg.EvalIdx {
		msgType, payload, err = fc.read()
		if err != nil {
			return nil, fail(nil, "recv input: %w", err)
		}
		if msgType == MsgError {
			return nil, fmt.Errorf("remote error: %s", payload)
		}
		if msgType != MsgCTBatch {
			return nil, fail(fc, "expected CT_BATCH, got message type 0x%02x", msgType)
		}
		peerCts, err := UnmarshalCTBatch(payload)
		if err != nil {
			return nil, fail(fc, "decode input cts: %w", err)
		}
		expected := k * ctsPerCol
		if cfg.EvalIdx == 1 && cfg.Scenario == mkbfv.ScenarioWeightedSum {
			expected = k // peer is P2 in scenario 1: K broadcast scalars
		}
		if len(peerCts) != expected {
			return nil, fail(fc, "peer sent %d input ciphertexts, expected %d", len(peerCts), expected)
		}
		if cfg.EvalIdx == 2 { // peer is P1
			ctD = wrapColumns(peerCts, k, ctsPerCol)
		} else if cfg.Scenario == mkbfv.ScenarioWeightedSum {
			ctW = wrapAll(peerCts)
		} else {
			ctWcols = wrapColumns(peerCts, k, ctsPerCol)
		}
	} else {
		payload, err := MarshalCTBatch(ownCts)
		if err != nil {
			return nil, fail(nil, "marshal input cts: %w", err)
		}
		if err := fc.write(MsgCTBatch, payload); err != nil {
			return nil, fail(nil, "send input cts: %w", err)
		}
	}
	st.InputXfer = time.Since(t0)
	phase("input", s0, r0)
	logf("input %s: %v | sent %s recv %s", map[bool]string{true: "recv", false: "send"}[cfg.SelfIdx == cfg.EvalIdx],
		st.InputXfer, fmtMiB(st.PhaseSent["input"]), fmtMiB(st.PhaseRecv["input"]))

	// -------- evaluation (evaluator only) --------
	var resCt []*mkbfv.Ciphertext
	if cfg.SelfIdx == cfg.EvalIdx {
		evalSt := &mkbfv.DotProductStats{Verbose: true, Records: records, K: k, T: T}
		resCt = mkbfv.EvalScenario(mkbfv.NewEvaluator(params), cfg.Scenario, ctD, ctW, ctWcols, rlkSet, evalSt)
		st.Eval = evalSt.EvalTime
		st.MulOps, st.AddOps = evalSt.MulOps, evalSt.AddOps
	}

	// -------- result flow (four cases by (eval, recv) roles) --------
	skSet := mkrlwe.NewSecretKeySet()
	skSet.AddSecretKey(sk)
	writeOut := func(res []int64) error {
		if cfg.SelfIdx != cfg.RecvIdx {
			return nil
		}
		if err := writeResultCSV(cfg.OutCSV, res); err != nil {
			return err
		}
		logf("result written to %s (%d rows)", cfg.OutCSV, len(res))
		if cfg.Verify {
			mism, first := verifyResult(cfg, res)
			st.Mismatch = mism
			st.FirstMismatch = first
			if mism == 0 {
				logf("verify : OK, %d/%d records exact", records, records)
			} else {
				logf("verify : FAILED, %d/%d mismatches, first: %s", mism, records, first)
			}
		}
		return nil
	}
	decodeBatches := func(cts []*mkbfv.Ciphertext) []int64 {
		res := make([]int64, records)
		for j, ct := range cts {
			msg := dec.Decrypt(ct, skSet)
			for i := 0; i < slots; i++ {
				if idx := j*slots + i; idx < records {
					res[idx] = msg.Value[i]
				}
			}
		}
		return res
	}

	t0 = time.Now()
	s0, r0 = snap()
	recvCTBatch := func() ([]*mkbfv.Ciphertext, error) {
		msgType, payload, err := fc.read()
		if err != nil {
			return nil, err
		}
		if msgType == MsgError {
			return nil, fmt.Errorf("remote error: %s", payload)
		}
		if msgType != MsgCTBatch {
			return nil, fmt.Errorf("expected CT_BATCH, got message type 0x%02x", msgType)
		}
		rlweCts, err := UnmarshalCTBatch(payload)
		if err != nil {
			return nil, err
		}
		return wrapAll(rlweCts), nil
	}
	recvDone := func() error {
		msgType, payload, err := fc.read()
		if err != nil {
			return err
		}
		if msgType == MsgError {
			return fmt.Errorf("remote error: %s", payload)
		}
		if msgType != MsgDone {
			return fmt.Errorf("expected DONE, got message type 0x%02x", msgType)
		}
		return nil
	}

	switch {
	case cfg.SelfIdx == cfg.EvalIdx && cfg.SelfIdx == cfg.RecvIdx:
		// evaluator receives the peer's blind partial first
		flat := make([]*mkrlwe.Ciphertext, len(resCt))
		for i, ct := range resCt {
			flat[i] = ct.Ciphertext
		}
		if err := fc.write(MsgCTBatch, mustMarshalBatch(flat)); err != nil {
			return nil, fail(nil, "send result cts: %w", err)
		}
		partial, err := recvCTBatch()
		if err != nil {
			return nil, fail(nil, "recv partial: %w", err)
		}
		res := decodeBatches(partial)
		if err := writeOut(res); err != nil {
			return nil, fail(nil, "write out: %w", err)
		}
		if err := fc.write(MsgDone, nil); err != nil {
			return nil, fail(nil, "send done: %w", err)
		}

	case cfg.SelfIdx == cfg.EvalIdx: // receiver is the peer
		for _, ct := range resCt {
			dec.PartialDecrypt(ct, sk) // evaluator stays blind
		}
		flat := make([]*mkrlwe.Ciphertext, len(resCt))
		for i, ct := range resCt {
			flat[i] = ct.Ciphertext
		}
		if err := fc.write(MsgCTBatch, mustMarshalBatch(flat)); err != nil {
			return nil, fail(nil, "send partial: %w", err)
		}
		if err := fc.write(MsgDone, nil); err != nil {
			return nil, fail(nil, "send done: %w", err)
		}

	case cfg.SelfIdx == cfg.RecvIdx: // evaluator is the peer
		partial, err := recvCTBatch()
		if err != nil {
			return nil, fail(nil, "recv partial: %w", err)
		}
		res := decodeBatches(partial)
		if err := writeOut(res); err != nil {
			return nil, fail(nil, "write out: %w", err)
		}
		if err := recvDone(); err != nil {
			return nil, fail(nil, "recv done: %w", err)
		}

	default: // neither evaluator nor receiver: blind partial decrypt only
		full, err := recvCTBatch()
		if err != nil {
			return nil, fail(nil, "recv result cts: %w", err)
		}
		for _, ct := range full {
			dec.PartialDecrypt(ct, sk)
		}
		flat := make([]*mkrlwe.Ciphertext, len(full))
		for i, ct := range full {
			flat[i] = ct.Ciphertext
		}
		if err := fc.write(MsgCTBatch, mustMarshalBatch(flat)); err != nil {
			return nil, fail(nil, "send partial: %w", err)
		}
		if err := recvDone(); err != nil {
			return nil, fail(nil, "recv done: %w", err)
		}
	}
	st.Result = time.Since(t0)
	phase("result", s0, r0)
	logf("result flow: %v | sent %s recv %s", st.Result,
		fmtMiB(st.PhaseSent["result"]), fmtMiB(st.PhaseRecv["result"]))

	st.Sent, st.Recv = conn.SentBytes(), conn.RecvBytes()
	st.print(cfg, selfID, evalID, recvID)
	return st, nil
}

func (st *Stats) print(cfg Config, selfID, evalID, recvID string) {
	fmt.Printf("==============================================================\n")
	fmt.Printf("MK-BFV 2-party networked: %s | this=%s eval=%s recv=%s\n",
		mkbfv.ScenarioName(cfg.Scenario), selfID, evalID, recvID)
	fmt.Printf("  conf=%s T=%d (%d bits) records=%d K=%d cts/col=%d\n",
		cfg.ConfName, st.T, uint64Len(st.T), st.Records, st.K, st.CtsPerCol)
	fmt.Printf("--------------------------------------------------------------\n")
	fmt.Printf("phase                           | time       | sent        | recv        \n")
	fmt.Printf("--------------------------------|------------|-------------|-------------\n")
	row := func(name string, d time.Duration) {
		fmt.Printf("%-32s| %10v | %10s | %10s\n", name, d,
			fmtMiB(st.PhaseSent[name]), fmtMiB(st.PhaseRecv[name]))
	}
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "0 connect", st.Connect, "-", "-")
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "1 handshake (HELLO+BOUND)", st.Handshake,
		fmtMiB(st.PhaseSent["handshake"]), fmtMiB(st.PhaseRecv["handshake"]))
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "2 params+CRS (seeded)", st.CRS, "-", "-")
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "3 keygen (own pk+rlk)", st.Keygen, "-", "-")
	row("rlk", st.RlkXfer)
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "5 own encode+encrypt", st.EncOwn, "-", "-")
	row("input", st.InputXfer)
	fmt.Printf("%-32s| %10v | %10s | %10s\n", "7 eval (MulRelin+Add)", st.Eval, "-", "-")
	row("result", st.Result)
	fmt.Printf("--------------------------------------------------------------\n")
	if cfg.SelfIdx == cfg.RecvIdx {
		if cfg.Verify {
			if st.Mismatch == 0 {
				fmt.Printf("correctness: OK (0/%d mismatches)\n", st.Records)
			} else {
				fmt.Printf("correctness: FAILED %d/%d mismatches, first: %s\n",
					st.Mismatch, st.Records, st.FirstMismatch)
			}
		} else {
			fmt.Printf("correctness: not verified (-verify=false)\n")
		}
	} else {
		fmt.Printf("correctness: n/a (this party is not the receiver)\n")
	}
	fmt.Printf("socket bytes sent/recv          | %10s / %s\n", fmtMiB(st.Sent), fmtMiB(st.Recv))
	fmt.Printf("total time online (keygen->result): %v\n",
		st.Keygen+st.RlkXfer+st.EncOwn+st.InputXfer+st.Eval+st.Result)
	fmt.Printf("==============================================================\n\n")
}

// ---------- helpers ----------

// encryptColumns packs each column of data into ctsPerCol ciphertexts under pk.
func encryptColumns(enc *mkbfv.Encryptor, params mkbfv.Parameters, pk *mkrlwe.PublicKey, cols [][]int64, records, slots int) [][]*mkbfv.Ciphertext {
	out := make([][]*mkbfv.Ciphertext, len(cols))
	ctsPerCol := (records + slots - 1) / slots
	for c := range cols {
		out[c] = make([]*mkbfv.Ciphertext, ctsPerCol)
		for j := range out[c] {
			msg := mkbfv.NewMessage(params)
			for i := 0; i < slots; i++ {
				if idx := j*slots + i; idx < records {
					msg.Value[i] = cols[c][idx]
				}
			}
			out[c][j] = enc.EncryptMsgNew(msg, pk)
		}
	}
	return out
}

// wrapColumns reshapes a column-major flat ciphertext list into [k][ctsPerCol].
func wrapColumns(flat []*mkrlwe.Ciphertext, k, ctsPerCol int) [][]*mkbfv.Ciphertext {
	out := make([][]*mkbfv.Ciphertext, k)
	for c := range out {
		out[c] = make([]*mkbfv.Ciphertext, ctsPerCol)
		for j := range out[c] {
			out[c][j] = &mkbfv.Ciphertext{Ciphertext: flat[c*ctsPerCol+j]}
		}
	}
	return out
}

// wrapAll wraps flat mkrlwe ciphertexts into mkbfv ones (order preserved).
func wrapAll(flat []*mkrlwe.Ciphertext) []*mkbfv.Ciphertext {
	out := make([]*mkbfv.Ciphertext, len(flat))
	for i, ct := range flat {
		out[i] = &mkbfv.Ciphertext{Ciphertext: ct}
	}
	return out
}

func mustMarshalBatch(flat []*mkrlwe.Ciphertext) []byte {
	b, err := MarshalCTBatch(flat)
	if err != nil {
		panic(err)
	}
	return b
}

func oneRowCols(ws []int64) [][]int64 {
	cols := make([][]int64, len(ws))
	for c, w := range ws {
		cols[c] = []int64{w}
	}
	return cols
}

func maxOf(v []uint64) int64 {
	m := uint64(0)
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return int64(m)
}

func colAbsMaxPerCol(cols [][]int64) []uint64 {
	out := make([]uint64, len(cols))
	for c, col := range cols {
		m := int64(0)
		for _, v := range col {
			if v > m {
				m = v
			} else if -v > m {
				m = -v
			}
		}
		out[c] = uint64(m)
	}
	return out
}

func uint64Len(v uint64) int {
	n := 0
	for v > 0 {
		n++
		v >>= 1
	}
	return n
}

// verifyResult recomputes the scenario in the clear (receiver side, test
// only: needs both CSVs locally) and returns the mismatch count.
func verifyResult(cfg Config, res []int64) (int, string) {
	_, dCols, err := readIntCSV(cfg.P1CSV)
	if err != nil {
		return -1, "verify: read p1: " + err.Error()
	}
	records := len(dCols[0])
	k := len(dCols)

	var ws []int64
	var wCols [][]int64
	if cfg.Scenario != mkbfv.ScenarioWeightedSum {
		_, wCols, err = readIntCSV(cfg.P2CSV)
		if err != nil {
			return -1, "verify: read p2: " + err.Error()
		}
	} else {
		_, cols, err := readIntCSV(cfg.P2CSV)
		if err != nil {
			return -1, "verify: read p2: " + err.Error()
		}
		ws = make([]int64, k)
		for c := range ws {
			ws[c] = cols[c][0]
		}
	}

	mism := 0
	first := ""
	for i := 0; i < records && i < len(res); i++ {
		want := int64(0)
		switch cfg.Scenario {
		case mkbfv.ScenarioWeightedSum:
			for c := 0; c < k; c++ {
				want += dCols[c][i] * ws[c]
			}
		case mkbfv.ScenarioWeightedSumRowwise:
			for c := 0; c < k; c++ {
				want += dCols[c][i] * wCols[c][i]
			}
		case mkbfv.ScenarioSumProduct:
			want = 1
			for c := 0; c < k; c++ {
				want *= dCols[c][i] + wCols[c][i]
			}
		}
		if res[i] != want {
			mism++
			if first == "" {
				first = fmt.Sprintf("idx=%d got=%d want=%d", i, res[i], want)
			}
		}
	}
	return mism, first
}

// ---------- CSV I/O (same formats as the dotproduct CLI) ----------

func readIntCSV(path string) (header []string, cols [][]int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(rows) < 2 {
		return nil, nil, fmt.Errorf("%s: need a header row and at least one data row", path)
	}
	n := len(rows) - 1
	cols = make([][]int64, len(rows[0]))
	for c := range cols {
		cols[c] = make([]int64, 0, n)
	}
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, nil, fmt.Errorf("%s: ragged row %q", path, row)
		}
		for c, field := range row {
			v, err := strconv.ParseInt(field, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %q: %v", path, field, err)
			}
			cols[c] = append(cols[c], v)
		}
	}
	return rows[0], cols, nil
}

func writeResultCSV(path string, res []int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"res"}); err != nil {
		return err
	}
	for _, v := range res {
		if err := w.Write([]string{strconv.FormatInt(v, 10)}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
