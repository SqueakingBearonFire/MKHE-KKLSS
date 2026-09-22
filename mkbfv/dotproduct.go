package mkbfv

// Parameter sets, plaintext-modulus helpers and the stats type for the
// two-party MK-BFV computation scenarios. The protocol runners themselves
// live in scenarios.go:
//
//   P1 holds d1..dK, each `records` int64 values (private).
//   P2 holds either scalars w1..wK or columns w1..wK (private).
//   Compute one of three functions of the inputs, result to P1 only.
//
// Protocol phases (all timed; communication accounted analytically as exact
// RNS serialization, i.e. 8 bytes per 53/54-bit limb per coefficient):
//   0. params/CRS generation (common randomness, seed-derivable -> 0 comm)
//   1. per-party keygen (pk + relinearization keys, broadcast once)
//   2. P1 encodes+encrypts ceil(records/N) ciphertexts per column (SIMD batching)
//   3. P2 encrypts its input (K scalar ciphertexts, or K packed columns)
//   4. evaluator: per-scenario circuit under the joint key {P1,P2}
//   5. threshold decryption: P2 partial-decrypts first (stays blind),
//      then P1 partial-decrypts and decodes the plaintext result.

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"time"

	"github.com/ldsec/lattigo/v2/rlwe"
)

// PN14QP439 is the same parameter set as the one used by the package tests:
// LogN=14, ~319-bit Q (6 limbs), logQP=439.
var PN14QP439 = ParametersLiteral{
	LogN: 14,

	Q: []uint64{
		// 5 x 53 + 1 x 54
		0x1fffffffe30001,
		0x1fffffffd10001,
		0x1fffffffbf0001,
		0x1fffffffb60001,
		0x1fffffff920001,

		0x3fffffffd60001,
	},

	QMul: []uint64{
		// 5 x 53 + 1 x 54
		0x1fffffffd80001,
		0x1fffffffc50001,
		0x1fffffffb90001,
		0x1fffffffa50001,
		0x1fffffff900001,

		0x3fffffffca0001,
	},

	P: []uint64{
		// 2 x 60
		0xffffffffffc0001, 0xfffffffff840001,
	},
	T:     65537,
	Sigma: rlwe.DefaultSigma,
}

// PN15QP660 is a LogN=15 parameter set trimmed from PN15QP880 (10 Q limbs,
// ~540-bit Q, logQP ~ 660) so that the CRS material of the two internally
// instantiated parameter sets (QP and R = Q*QMul) fits in ~8 GB of RAM.
var PN15QP660 = ParametersLiteral{
	LogN: 15,

	Q: []uint64{
		0x3fffffffd60001,
		0x3fffffff6d0001,
		0x3fffffff550001,
		0x3fffffff360001,
		0x3fffffff000001,
		0x3ffffffef40001,
		0x3ffffffed30001,
		0x3ffffffe970001,
		0x3ffffffe800001,
		0x3ffffffe410001,
	},

	QMul: []uint64{
		0x3fffffffca0001,
		0x3fffffff5d0001,
		0x3fffffff390001,
		0x3fffffff2a0001,
		0x3ffffffefa0001,
		0x3ffffffed70001,
		0x3ffffffeaa0001,
		0x3ffffffe920001,
		0x3ffffffe790001,
		0x3ffffffe320001,
	},

	P: []uint64{
		0xffffffffffc0001, 0xfffffffff840001,
	},
	T:     65537,
	Sigma: rlwe.DefaultSigma,
}

// FindPrimeT returns the smallest prime >= min with T == 1 (mod 2^16), i.e.
// NTT/batching friendly for every LogN <= 16. The BFV encoder requires
// 2N | (T-1), Message values are int64 (T < 2^63), and lattigo additionally
// requires T <= Q[0] (~2^54 for the parameter sets in this package).
func FindPrimeT(min uint64) uint64 {
	k := (min + 65535) / 65536
	for {
		T := k<<16 + 1
		if new(big.Int).SetUint64(T).ProbablyPrime(30) {
			return T
		}
		k++
	}
}

// MaxT returns the largest admissible plaintext modulus for these parameters
// (lattigo constraint: T <= Q[0]).
func MaxT(params Parameters) uint64 {
	return params.Q()[0]
}

// MinT returns a safe plaintext-modulus lower bound for signed dot products
// of K terms: decryption is exact as long as |sum_k dk[i]*wk| <= K*maxD*maxW
// < T/2; a 2x margin is applied. Saturates at MaxUint64 when the bound
// exceeds 64 bits.
func MinT(k int, maxD, maxW int64) uint64 {
	bound := new(big.Int).Mul(big.NewInt(int64(k)), big.NewInt(maxD))
	bound.Mul(bound, big.NewInt(maxW))
	bound.Mul(bound, big.NewInt(4))
	if !bound.IsUint64() {
		return math.MaxUint64
	}
	return bound.Uint64()
}

// DotProductStats holds the per-phase timings, communication volume and
// verification result of one scenario execution (RunWeightedSum /
// RunWeightedSumRowwise / RunSumProduct in scenarios.go).
type DotProductStats struct {
	// configuration
	Scenario      string
	LogN, LogQP   int
	N, QLimbs     int
	PLimbs, Beta  int
	T             uint64
	Slots         int
	CtsPerCol     int
	P2Cts         int // ciphertexts P2 uploads in phase 3
	Records, K    int
	Verbose       bool // print each phase's time & comm as soon as it completes

	// phase timings
	CRSTime                        time.Duration // params+CRS (local, no comm)
	KeygenTime                     time.Duration
	EncP1Time, EncP2Time           time.Duration
	EvalTime, MulTime, AddTime     time.Duration
	MulOps, AddOps                 int
	PdP2Time, PdP1Time, DecodeTime time.Duration

	// communication (bytes)
	PolyQ, PolyQP    uint64
	PkBytes, RlkBytes uint64
	SetupBytes       uint64
	EncP1Bytes       uint64
	EncP2Bytes       uint64
	ResCtBytes       uint64
	ResPdBytes       uint64
	OnlineBytes      uint64

	// verification
	Mismatch     int
	FirstMismatch string
}

// RunDotProduct executes scenario 1 (weighted sum, P2 holds K scalars) and
// returns the decrypted result (len == len(data[0])). Kept as a thin wrapper
// for backward compatibility with the library-level benchmark
// (dotproduct_test.go); new code should call RunWeightedSum directly.
func RunDotProduct(params Parameters, data [][]int64, ws []int64, verify bool, st *DotProductStats) (res []int64) {
	return RunWeightedSum(params, data, ws, verify, st)
}

func fmtMiB(b uint64) string { return fmt.Sprintf("%.2f MiB", float64(b)/1024/1024) }

// Print writes the per-phase timing/communication report to stdout.
func (st *DotProductStats) Print() {
	fmtMB := fmtMiB

	fmt.Printf("==============================================================\n")
	fmt.Printf("MK-BFV 2-party: %s\n", st.Scenario)
	fmt.Printf("  LogN=%d N=%d Q(%d limbs) P(%d limbs) logQP=%d beta=%d\n",
		st.LogN, st.N, st.QLimbs, st.PLimbs, st.LogQP, st.Beta)
	fmt.Printf("  T=%d (%d bits)  slots/ct=%d  cts/column=%d  records=%d columns=%d\n",
		st.T, bits.Len64(st.T), st.Slots, st.CtsPerCol, st.Records, st.K)
	fmt.Printf("  polyQ=%s polyQP=%s\n", fmtMB(st.PolyQ), fmtMB(st.PolyQP))
	fmt.Printf("--------------------------------------------------------------\n")
	fmt.Printf("phase                           | time       | comm (this node->)          \n")
	fmt.Printf("--------------------------------|------------|-----------------------------\n")
	fmt.Printf("0 params+CRS (no comm)          | %10v | -\n", st.CRSTime)
	fmt.Printf("1 keygen 2 parties (pk+rlk)     | %10v | %10s /party, %10s total (once)\n",
		st.KeygenTime, fmtMB(st.PkBytes+st.RlkBytes), fmtMB(st.SetupBytes))
	fmt.Printf("2 P1 enc+enc (%2d cts)           | %10v | %10s P1->E\n", st.K*st.CtsPerCol, st.EncP1Time, fmtMB(st.EncP1Bytes))
	fmt.Printf("3 P2 enc+enc (%2d cts)           | %10v | %10s P2->E\n", st.P2Cts, st.EncP2Time, fmtMB(st.EncP2Bytes))
	fmt.Printf("4 eval: %d MulRelin + %d Add     | %10v | -\n", st.MulOps, st.AddOps, st.EvalTime)
	fmt.Printf("    mul total / avg             | %10v |   (%v/op)\n", st.MulTime, perOp(st.MulTime, st.MulOps))
	fmt.Printf("    add total / avg             | %10v |   (%v/op)\n", st.AddTime, perOp(st.AddTime, st.AddOps))
	fmt.Printf("5 E->P1 result (%d cts x3poly)  |            | %10s E->P1\n", st.CtsPerCol, fmtMB(st.ResCtBytes))
	fmt.Printf("  5a P2 partial-decrypt         | %10v | %10s P1->P2 (full ct)\n", st.PdP2Time, fmtMB(st.ResCtBytes))
	fmt.Printf("  5b P1 partial-decrypt         | %10v | %10s P2->P1 (2 polys)\n", st.PdP1Time, fmtMB(st.ResPdBytes))
	fmt.Printf("  5c P1 decode                  | %10v | -\n", st.DecodeTime)
	fmt.Printf("--------------------------------------------------------------\n")
	if st.Mismatch > 0 {
		fmt.Printf("correctness: FAILED %d/%d mismatches, first: %s\n", st.Mismatch, st.Records, st.FirstMismatch)
	} else {
		fmt.Printf("correctness: OK (0/%d mismatches)\n", st.Records)
	}
	fmt.Printf("total comm (setup keys)        : %10s\n", fmtMB(st.SetupBytes))
	fmt.Printf("total comm (online, ext. eval.): %10s  (%.1f B/record)\n",
		fmtMB(st.OnlineBytes), float64(st.OnlineBytes)/float64(st.Records))
	fmt.Printf("total comm (online, eval=P1)   : %10s\n", fmtMB(st.EncP2Bytes+st.ResCtBytes+st.ResPdBytes))
	fmt.Printf("total time online (enc+eval+dec): %v\n",
		st.EncP1Time+st.EncP2Time+st.EvalTime+st.PdP2Time+st.PdP1Time+st.DecodeTime)
	fmt.Printf("==============================================================\n\n")
}
