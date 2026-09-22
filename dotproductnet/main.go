// dotproductnet runs the three two-party MK-BFV computation scenarios as two
// real processes talking over TCP (transport: mknet). Each party is started
// with -party 1|2; the hostfile lists the parties' listen addresses in order
// (line i = party i+1, format "ip:port"). The evaluator (-eval, default 1)
// and the result receiver (-receiver, default 1) can each be either party;
// both processes must be started with identical -scenario/-eval/-receiver/
// -conf values (cross-checked at handshake).
//
// Data comes from the same CSVs as the single-process dotproduct CLI
// (generate them there with -gen). P1 reads the d1..dK file, P2 reads the
// w1..wK file; the receiver additionally re-reads both for -verify (test
// convenience — in a real deployment the receiver only holds its own data).
//
// Usage (two terminals, or one terminal with `&`):
//
//	go run ./dotproduct -gen -scenario 1 -rows 2000 -gendir data/n1
//	printf '127.0.0.1:7001\n127.0.0.1:7002\n' > hosts.txt
//	go run ./dotproductnet -party 1 -hostfile hosts.txt -scenario 1 \
//	    -p1 data/n1/p1_data.csv -p2 data/n1/p2_weights.csv
//	go run ./dotproductnet -party 2 -hostfile hosts.txt -scenario 1 \
//	    -p1 data/n1/p1_data.csv -p2 data/n1/p2_weights.csv
//
// The result CSV is written by the receiver only (default data/net_s<scenario>_<conf>.csv).
package main

import (
	"flag"
	"fmt"
	"os"

	"mk-lattigo/mkbfv"
	"mk-lattigo/mknet"
)

func main() {
	var (
		party     = flag.Int("party", 0, "this process is party 1 or 2 (required)")
		hostfile  = flag.String("hostfile", "", "hostfile with one ip:port per line, in party order (required)")
		eval      = flag.Int("eval", 1, "evaluator party: 1 | 2")
		receiver  = flag.Int("receiver", 1, "result receiver party: 1 | 2")
		scenario  = flag.Int("scenario", 1, "computation scenario: 1 = weighted sum, 2 = row-wise weighted sum, 3 = product (d1+w1)*...*(dK+wK)")
		conf      = flag.String("conf", "pn14", "parameter set: pn14 | pn15 (single choice; both processes must match)")
		p1csv     = flag.String("p1", "data/p1_data.csv", "P1 data CSV (header d1..dK, one row per record)")
		p2csv     = flag.String("p2", "", "P2 input CSV (default: data/p2_weights.csv for scenario 1, data/p2_data.csv otherwise)")
		out       = flag.String("out", "", "result CSV written by the receiver (default: data/net_s<scenario>_<conf>.csv)")
		verify    = flag.Bool("verify", true, "receiver verifies the result against plaintext (test only; needs both CSVs locally)")
	)
	flag.Parse()

	if *party != 1 && *party != 2 {
		fmt.Fprintln(os.Stderr, "dotproductnet: -party must be 1 or 2")
		os.Exit(2)
	}
	if *hostfile == "" {
		fmt.Fprintln(os.Stderr, "dotproductnet: -hostfile is required")
		os.Exit(2)
	}
	if (*eval != 1 && *eval != 2) || (*receiver != 1 && *receiver != 2) {
		fmt.Fprintln(os.Stderr, "dotproductnet: -eval and -receiver must each be 1 or 2")
		os.Exit(2)
	}
	if *scenario != mkbfv.ScenarioWeightedSum &&
		*scenario != mkbfv.ScenarioWeightedSumRowwise &&
		*scenario != mkbfv.ScenarioSumProduct {
		fmt.Fprintf(os.Stderr, "unknown -scenario %d (want 1, 2 or 3)\n", *scenario)
		os.Exit(2)
	}

	lit, err := literalFor(*conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	hosts, err := mknet.ReadHostfile(*hostfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostfile:", err)
		os.Exit(1)
	}

	p2path := *p2csv
	if p2path == "" {
		if *scenario == mkbfv.ScenarioWeightedSum {
			p2path = "data/p2_weights.csv"
		} else {
			p2path = "data/p2_data.csv"
		}
	}
	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("data/net_s%d_%s.csv", *scenario, *conf)
	}

	cfg := mknet.Config{
		SelfIdx:  *party,
		EvalIdx:  *eval,
		RecvIdx:  *receiver,
		Scenario: *scenario,
		ConfName: *conf,
		Literal:  lit,
		Hosts:    hosts,
		P1CSV:    *p1csv,
		P2CSV:    p2path,
		OutCSV:   outPath,
		Verify:   *verify,
	}

	fmt.Printf("party %d | %s | eval=P%d recv=P%d | conf=%s\n",
		*party, mkbfv.ScenarioName(*scenario), *eval, *receiver, *conf)
	st, err := mknet.RunParty(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dotproductnet:", err)
		os.Exit(1)
	}
	if cfg.SelfIdx == cfg.RecvIdx && st.Mismatch > 0 {
		os.Exit(1)
	}
}

func literalFor(name string) (mkbfv.ParametersLiteral, error) {
	switch name {
	case "pn14":
		return mkbfv.PN14QP439, nil
	case "pn15":
		return mkbfv.PN15QP660, nil
	default:
		return mkbfv.ParametersLiteral{}, fmt.Errorf("unknown -conf %s (want pn14 | pn15)", name)
	}
}
