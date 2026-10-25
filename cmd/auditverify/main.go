// Command auditverify is the operator/auditor-facing tool for the audit
// log's tamper-evidence guarantee (internal/audit's hash chain): point it
// at any exported audit.log and it reports whether the chain is intact,
// or names the exact line/sequence number where it breaks. This is meant
// to be handed to an actual auditor, not just used internally - "run this
// against the log we gave you" is a stronger claim than "trust our
// dashboard says it's fine."
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/RinwallDev/rinwall/internal/audit"
)

func main() {
	path := flag.String("path", "audit.log", "path to the JSONL audit log to verify (ignored if -postgres-dsn is set)")
	postgresDSN := flag.String("postgres-dsn", "", "verify a Postgres-backed audit log instead of a file - set to the same state_postgres_dsn the proxy was configured with")
	asJSON := flag.Bool("json", false, "print the result as JSON instead of a human-readable summary")
	flag.Parse()

	var result audit.VerifyResult
	var err error
	if *postgresDSN != "" {
		result, err = audit.VerifyChainPostgres(*postgresDSN)
	} else {
		result, err = audit.VerifyChainFile(*path)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "auditverify: %v\n", err)
		os.Exit(2)
	}

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(result)
	} else {
		if result.OK {
			fmt.Printf("OK - hash chain intact: %d entries verified", result.EntriesChecked)
			if result.LegacyEntries > 0 {
				fmt.Printf(" (%d earlier entries predate the hash chain and were skipped, not verifiable)", result.LegacyEntries)
			}
			fmt.Println()
		} else {
			fmt.Printf("TAMPERING DETECTED at line %d", result.BrokenAtLine)
			if result.BrokenAtSeq > 0 {
				fmt.Printf(" (seq %d)", result.BrokenAtSeq)
			}
			fmt.Printf(": %s\n", result.Reason)
			fmt.Printf("%d entries verified OK before the break\n", result.EntriesChecked)
		}
	}

	if !result.OK {
		os.Exit(1)
	}
}
