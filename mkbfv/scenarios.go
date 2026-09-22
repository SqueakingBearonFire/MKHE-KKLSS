package mkbfv

// Three two-party MK-BFV computation scenarios sharing one protocol skeleton:
//
//	1. ScenarioWeightedSum         res[i] = sum_k  dk[i]*wk
//	   (P2 holds K scalars w1..wK)
//	2. ScenarioWeightedSumRowwise  res[i] = sum_k  dk[i]*wk[i]
//	3. ScenarioSumProduct          res[i] = prod_k (dk[i]+wk[i])
//	   (P2 holds K columns w1..wK, each `records` values)
//
// P1 holds d1..dK, each `records` int64 values. All scenarios run the same
// phases: keygen (pk+rlk per party) -> P1/P2 encryption -> homomorphic
// evaluation under the joint key {P1,P2} -> threshold decryption (P2 first,
// blind; P1 final, sole recipient of the plaintext). Timings and analytic
// communication volumes are recorded in DotProductStats (dotproduct.go).
//
// Evaluation circuits:
//   - scenarios 1/2: per batch j, sum of K cross-party MulRelin products
//     (K*ctsPerCol muls + (K-1)*ctsPerCol adds);
//   - scenario 3: per batch j, K cross-party AddNew sums followed by a
//     balanced pairwise MulRelin product tree of depth ceil(log2 K)
//     ((K-1)*ctsPerCol muls + K*ctsPerCol adds) — keeps the multiplicative
//     depth minimal so noise stays well inside the budget of Q/T.

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"time"

	"mk-lattigo/mkrlwe"
)

// Scenario identifiers accepted by runScenario and the dotproduct CLI.
const (
	ScenarioWeightedSum        = 1
	ScenarioWeightedSumRowwise = 2
	ScenarioSumProduct         = 3
)

// ScenarioName returns a human-readable name for a scenario identifier.
func ScenarioName(scenario int) string {
	switch scenario {
	case ScenarioWeightedSum:
		return "weighted-sum (P2 holds K scalars)"
	case ScenarioWeightedSumRowwise:
		return "weighted-sum row-wise (P2 holds K columns)"
	case ScenarioSumProduct:
		return "sum-product (d1+w1)*...*(dK+wK)"
	default:
		return fmt.Sprintf("unknown scenario %d", scenario)
	}
}

// MinTSumProduct returns a safe plaintext-modulus lower bound for scenario 3:
// decryption is exact as long as |prod_k (dk[i]+wk[i])| <= (maxD+maxW)^K
// < T/2; a 2x margin is applied. Saturates at MaxUint64 when the bound
// exceeds 64 bits ( callers must then reject or use CRT splitting).
func MinTSumProduct(k int, maxD, maxW int64) uint64 {
	base := new(big.Int).Add(big.NewInt(maxD), big.NewInt(maxW))
	bound := new(big.Int).Exp(base, big.NewInt(int64(k)), nil)
	bound.Mul(bound, big.NewInt(4))
	if !bound.IsUint64() {
		return math.MaxUint64
	}
	return bound.Uint64()
}

// RunWeightedSum executes scenario 1: res[i] = sum_k dk[i]*wk.
func RunWeightedSum(params Parameters, data [][]int64, ws []int64, verify bool, st *DotProductStats) (res []int64) {
	return runScenario(params, ScenarioWeightedSum, data, ws, nil, verify, st)
}

// RunWeightedSumRowwise executes scenario 2: res[i] = sum_k dk[i]*wk[i].
func RunWeightedSumRowwise(params Parameters, data, wdata [][]int64, verify bool, st *DotProductStats) (res []int64) {
	return runScenario(params, ScenarioWeightedSumRowwise, data, nil, wdata, verify, st)
}

// RunSumProduct executes scenario 3: res[i] = prod_k (dk[i]+wk[i]).
func RunSumProduct(params Parameters, data, wdata [][]int64, verify bool, st *DotProductStats) (res []int64) {
	return runScenario(params, ScenarioSumProduct, data, nil, wdata, verify, st)
}

// runScenario is the shared protocol skeleton behind the three public
// Run* wrappers. Exactly one of ws (scenario 1) / wdata (scenarios 2, 3) is
// used as P2's input.
func runScenario(params Parameters, scenario int, data [][]int64, ws []int64, wdata [][]int64, verify bool, st *DotProductStats) (res []int64) {

	k := len(data)
	records := len(data[0])
	for i := range data {
		if len(data[i]) != records {
			panic("runScenario: ragged P1 data columns")
		}
	}
	switch scenario {
	case ScenarioWeightedSum:
		if len(ws) != k {
			panic("runScenario: number of weights != number of data columns")
		}
	case ScenarioWeightedSumRowwise, ScenarioSumProduct:
		if len(wdata) != k {
			panic("runScenario: number of P2 columns != number of P1 columns")
		}
		for i := range wdata {
			if len(wdata[i]) != records {
				panic("runScenario: ragged P2 data columns")
			}
		}
	default:
		panic("runScenario: unknown scenario " + fmt.Sprint(scenario))
	}

	// communication helpers (exact RNS serialization: 1 uint64 per limb per coeff)
	N := params.N()
	qLimbs := params.QCount()
	pLimbs := params.PCount()
	beta := uint64(params.Beta(params.QCount() - 1))
	polyQ := uint64(N) * uint64(qLimbs) * 8
	polyQP := uint64(N) * uint64(qLimbs+pLimbs) * 8

	slots := N
	ctsPerCol := (records + slots - 1) / slots

	st.Scenario = ScenarioName(scenario)
	st.LogN, st.LogQP = params.LogN(), params.LogQP()
	st.N, st.QLimbs, st.PLimbs, st.Beta = N, qLimbs, pLimbs, int(beta)
	st.T = params.T()
	st.Slots, st.CtsPerCol, st.Records, st.K = slots, ctsPerCol, records, k
	st.PolyQ, st.PolyQP = polyQ, polyQP
	st.ResCtBytes = uint64(ctsPerCol) * 3 * polyQ // 2-party result ciphertext
	st.ResPdBytes = uint64(ctsPerCol) * 2 * polyQ // after P2's partial decrypt

	logf := func(format string, args ...interface{}) {
		if st.Verbose {
			fmt.Printf("[mkbfv] "+format+"\n", args...)
		}
	}
	logf("phase0 params+CRS: %v (local, no comm)", st.CRSTime)
	logf("scenario: %s", st.Scenario)
	logf("config : LogN=%d N=%d logQP=%d beta=%d T=%d(%dbits) slots/ct=%d cts/col=%d records=%d K=%d",
		params.LogN(), N, params.LogQP(), beta, params.T(), bits.Len64(params.T()), slots, ctsPerCol, records, k)

	kgen := NewKeyGenerator(params)
	enc := NewEncryptor(params)
	dec := NewDecryptor(params)
	eval := NewEvaluator(params)

	// -------- Phase 1: per-party key generation --------
	idP1, idP2 := "P1", "P2"
	skSet := mkrlwe.NewSecretKeySet()
	pkSet := mkrlwe.NewPublicKeyKeySet()
	rlkSet := NewRelinearizationKeyKeySet(params)
	sks := map[string]*mkrlwe.SecretKey{}
	pks := map[string]*mkrlwe.PublicKey{}

	t0 := time.Now()
	for _, id := range []string{idP1, idP2} {
		sk, pk := kgen.GenKeyPair(id)
		r := kgen.GenSecretKey(id)
		rlk := kgen.GenRelinearizationKey(sk, r)
		skSet.AddSecretKey(sk)
		pkSet.AddPublicKey(pk)
		rlkSet.AddRelinearizationKey(rlk)
		sks[id], pks[id] = sk, pk
	}
	st.KeygenTime = time.Since(t0)
	st.PkBytes = 2 * polyQP
	st.RlkBytes = 6 * beta * polyQP
	st.SetupBytes = 2 * (st.PkBytes + st.RlkBytes)
	logf("phase1 keygen 2 parties: %10v | comm %s/party -> %s once (pk %s + rlk %s)",
		st.KeygenTime, fmtMiB(st.PkBytes+st.RlkBytes), fmtMiB(st.SetupBytes), fmtMiB(st.PkBytes), fmtMiB(st.RlkBytes))

	// -------- Phase 2: P1 encode+encrypt its data --------
	t0 = time.Now()
	ctD := make([][]*Ciphertext, k)
	for c := 0; c < k; c++ {
		ctD[c] = make([]*Ciphertext, ctsPerCol)
		for j := 0; j < ctsPerCol; j++ {
			msg := NewMessage(params)
			for i := 0; i < slots; i++ {
				if idx := j*slots + i; idx < records {
					msg.Value[i] = data[c][idx]
				}
			}
			ctD[c][j] = enc.EncryptMsgNew(msg, pks[idP1])
		}
	}
	st.EncP1Time = time.Since(t0)
	st.EncP1Bytes = uint64(k*ctsPerCol) * 2 * polyQ
	logf("phase2 P1 encode+encrypt (%2d cts): %10v | comm %s P1->E",
		k*ctsPerCol, st.EncP1Time, fmtMiB(st.EncP1Bytes))

	// -------- Phase 3: P2 encrypts its input --------
	t0 = time.Now()
	ctWscalar := make([]*Ciphertext, k)          // scenario 1: wk broadcast into all slots
	ctWcols := make([][]*Ciphertext, k)          // scenarios 2/3: packed columns
	p2cts := k                                  // ciphertexts P2 uploads
	if scenario == ScenarioWeightedSum {
		for c := 0; c < k; c++ {
			msg := NewMessage(params)
			for i := range msg.Value {
				msg.Value[i] = ws[c]
			}
			ctWscalar[c] = enc.EncryptMsgNew(msg, pks[idP2])
		}
	} else {
		p2cts = k * ctsPerCol
		for c := 0; c < k; c++ {
			ctWcols[c] = make([]*Ciphertext, ctsPerCol)
			for j := 0; j < ctsPerCol; j++ {
				msg := NewMessage(params)
				for i := 0; i < slots; i++ {
					if idx := j*slots + i; idx < records {
						msg.Value[i] = wdata[c][idx]
					}
				}
				ctWcols[c][j] = enc.EncryptMsgNew(msg, pks[idP2])
			}
		}
	}
	st.EncP2Time = time.Since(t0)
	st.EncP2Bytes = uint64(p2cts) * 2 * polyQ
	st.P2Cts = p2cts
	logf("phase3 P2 encode+encrypt (%2d cts): %10v | comm %s P2->E",
		p2cts, st.EncP2Time, fmtMiB(st.EncP2Bytes))

	// -------- Phase 4: homomorphic evaluation under the joint key --------
	var expMul, expAdd int
	switch scenario {
	case ScenarioWeightedSum, ScenarioWeightedSumRowwise:
		expMul, expAdd = k*ctsPerCol, (k-1)*ctsPerCol
	case ScenarioSumProduct:
		expMul, expAdd = (k-1)*ctsPerCol, k*ctsPerCol
	}
	logf("phase4 eval: %d MulRelin + %d Add ...", expMul, expAdd)

	t0 = time.Now()
	resCt := make([]*Ciphertext, ctsPerCol)
	evalStart := time.Now()
	mulDone := 0
	for j := 0; j < ctsPerCol; j++ {
		switch scenario {
		case ScenarioWeightedSum, ScenarioWeightedSumRowwise:
			// res[j] = sum_c D[c][j] * W[c]
			ta := time.Now()
			if scenario == ScenarioWeightedSum {
				resCt[j] = eval.MulRelinNew(ctD[0][j], ctWscalar[0], rlkSet)
			} else {
				resCt[j] = eval.MulRelinNew(ctD[0][j], ctWcols[0][j], rlkSet)
			}
			st.MulTime += time.Since(ta)
			mulDone++
			for c := 1; c < k; c++ {
				ta = time.Now()
				var tmp *Ciphertext
				if scenario == ScenarioWeightedSum {
					tmp = eval.MulRelinNew(ctD[c][j], ctWscalar[c], rlkSet)
				} else {
					tmp = eval.MulRelinNew(ctD[c][j], ctWcols[c][j], rlkSet)
				}
				st.MulTime += time.Since(ta)
				mulDone++
				ta = time.Now()
				resCt[j] = eval.AddNew(resCt[j], tmp)
				st.AddTime += time.Since(ta)
			}
		case ScenarioSumProduct:
			// res[j] = prod_c (D[c][j] + W[c][j]) via a balanced pairwise
			// product tree (depth ceil(log2 K), minimal noise growth).
			cur := make([]*Ciphertext, k)
			for c := 0; c < k; c++ {
				ta := time.Now()
				cur[c] = eval.AddNew(ctD[c][j], ctWcols[c][j])
				st.AddTime += time.Since(ta)
			}
			for len(cur) > 1 {
				nxt := make([]*Ciphertext, 0, (len(cur)+1)/2)
				for i := 0; i+1 < len(cur); i += 2 {
					ta := time.Now()
					p := eval.MulRelinNew(cur[i], cur[i+1], rlkSet)
					st.MulTime += time.Since(ta)
					mulDone++
					nxt = append(nxt, p)
				}
				if len(cur)%2 == 1 {
					nxt = append(nxt, cur[len(cur)-1])
				}
				cur = nxt
			}
			resCt[j] = cur[0]
		}
		logf("  batch %d/%d: %10v elapsed, mul-avg %v",
			j+1, ctsPerCol, time.Since(evalStart).Round(time.Millisecond),
			perOp(st.MulTime, mulDone))
	}
	st.EvalTime = time.Since(t0)
	st.MulOps, st.AddOps = expMul, expAdd
	logf("phase4 eval done: %10v | mul %v (%v/op), add %v (%v/op)",
		st.EvalTime, st.MulTime, perOp(st.MulTime, st.MulOps),
		st.AddTime, perOp(st.AddTime, st.AddOps))

	// -------- Phase 5: threshold decryption (P2 first, then P1) + decode --------
	res = make([]int64, records)
	logf("phase5 E->P1 result distribution: comm %s (%d cts x 3 polys)", fmtMiB(st.ResCtBytes), ctsPerCol)
	t0 = time.Now()
	for j := 0; j < ctsPerCol; j++ {
		ta := time.Now()
		dec.PartialDecrypt(resCt[j], sks[idP2]) // P2 stays blind: P1 share still present
		st.PdP2Time += time.Since(ta)

		ta = time.Now()
		dec.PartialDecrypt(resCt[j], sks[idP1])
		st.PdP1Time += time.Since(ta)

		ta = time.Now()
		msg := NewMessage(params)
		dec.ptxtPool.Value = resCt[j].Value["0"]
		dec.encoder.DecodeInt(dec.ptxtPool, msg.Value)
		st.DecodeTime += time.Since(ta)

		for i := 0; i < slots; i++ {
			if idx := j*slots + i; idx < records {
				res[idx] = msg.Value[i]
			}
		}
	}
	st.OnlineBytes = st.EncP1Bytes + st.EncP2Bytes + 2*st.ResCtBytes + st.ResPdBytes
	logf("phase5a P2 partial-decrypt: %10v | comm %s P1->P2 (full cts)", st.PdP2Time, fmtMiB(st.ResCtBytes))
	logf("phase5b P1 partial-decrypt: %10v | comm %s P2->P1 (2 polys/ct)", st.PdP1Time, fmtMiB(st.ResPdBytes))
	logf("phase5c P1 decode         : %10v", st.DecodeTime)

	if verify {
		for i := 0; i < records; i++ {
			s := int64(0)
			switch scenario {
			case ScenarioWeightedSum:
				for c := 0; c < k; c++ {
					s += data[c][i] * ws[c]
				}
			case ScenarioWeightedSumRowwise:
				for c := 0; c < k; c++ {
					s += data[c][i] * wdata[c][i]
				}
			case ScenarioSumProduct:
				s = 1
				for c := 0; c < k; c++ {
					s *= data[c][i] + wdata[c][i]
				}
			}
			if res[i] != s {
				st.Mismatch++
				if st.FirstMismatch == "" {
					st.FirstMismatch = fmt.Sprintf("idx=%d got=%d want=%d", i, res[i], s)
				}
			}
		}
		if st.Mismatch == 0 {
			logf("verify : OK, %d/%d records exact", records, records)
		} else {
			logf("verify : FAILED, %d/%d mismatches, first: %s", st.Mismatch, records, st.FirstMismatch)
		}
	}

	return res
}

// perOp returns the per-operation average duration, guarding against a zero
// operation count (e.g. scenario 3 with K=1 performs no multiplication).
func perOp(total time.Duration, n int) time.Duration {
	if n == 0 {
		return 0
	}
	return total / time.Duration(n)
}
