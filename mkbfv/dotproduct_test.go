package mkbfv

// Benchmark for the two-party MK-BFV weighted-sum protocol; the protocol
// itself lives in dotproduct.go. CSV-driven end-to-end tool: dotproduct/.
//
//	go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn14
//	GOGC=400 go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn15

import (
	"flag"
	"math/rand"
	"testing"
	"time"
)

var dotConf = flag.String("dotconf", "pn14", "dot-product benchmark parameter set: pn14 | pn15")
var dotTMin = flag.Uint64("dottmin", 1<<46, "minimum plaintext modulus T (rounded up to NTT-friendly prime)")
var dotBound = flag.Int64("dotbound", 1<<20, "bound on |d| and |w| values")

const (
	dotRecords = 100000 // records per d column
	dotK       = 5      // number of columns / weights
)

func TestMKBFVDotProduct(t *testing.T) {

	var lit ParametersLiteral
	switch *dotConf {
	case "pn14":
		lit = PN14QP439
	case "pn15":
		lit = PN15QP660
	default:
		t.Fatalf("unknown -dotconf %s", *dotConf)
	}
	lit.T = FindPrimeT(*dotTMin)
	if lit.T > lit.Q[0] {
		t.Fatalf("T=%d exceeds Q[0]=%d (lattigo constraint T <= Q[0])", lit.T, lit.Q[0])
	}

	// -------- inputs (deterministic) --------
	rng := rand.New(rand.NewSource(0xC0FFEE))
	data := make([][]int64, dotK)
	for c := range data {
		data[c] = make([]int64, dotRecords)
		for i := range data[c] {
			data[c][i] = rng.Int63n(2**dotBound) - *dotBound
		}
	}
	ws := make([]int64, dotK)
	for c := range ws {
		ws[c] = rng.Int63n(2**dotBound) - *dotBound
	}

	// -------- Phase 0: parameters + CRS generation (local, no comm) --------
	t0 := time.Now()
	params := NewParametersFromLiteral(lit)
	st := &DotProductStats{CRSTime: time.Since(t0), Verbose: true}

	RunDotProduct(params, data, ws, true, st)
	st.Print()

	if st.Mismatch != 0 {
		t.Errorf("dot-product correctness FAILED: %d mismatches, first: %s", st.Mismatch, st.FirstMismatch)
	}
}
