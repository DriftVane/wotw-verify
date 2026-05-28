// Command wotw-verify verifies a wotw Compliance Pack offline.
//
// Usage:
//
//	wotw-verify <pack-path> [--workspace-key=<path>] [--json] [--strict] [--verbose]
//
// Exit codes:
//
//	0  chain fully verified (or verified with unattested records when
//	   --strict is not set)
//	1  chain has at least one verification failure (id hash, chain
//	   linkage, or HMAC)
//	2  malformed input (cannot parse pack, chain.jsonl, or keys.json)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/3030-Labs/wotw-verify/internal/keys"
	"github.com/3030-Labs/wotw-verify/internal/selftest"
	"github.com/3030-Labs/wotw-verify/internal/verify"
)

const usage = `wotw-verify — verify a wotw Compliance Pack offline.

Usage:
  wotw-verify <pack-path> [flags]

Flags:
  --workspace-key=<path>   path to the workspace KEK file (base64 or hex,
                           32 bytes). Required when the pack's chain
                           contains HMAC attestation records.
  --json                   emit a structured JSON report to stdout
                           (machine consumable). Default: human-readable.
  --strict                 refuse to verify any chain containing pre-G5
                           attestation records (records without hmac).
  --verbose                emit per-record outcomes in human mode.
  --self-test              run the 5 embedded fixture scenarios in a
                           temp directory and report. Useful to confirm
                           the binary works on a clean machine without
                           a real Compliance Pack. Exit 0 if all pass,
                           1 if any scenario produces the wrong verdict.
  --version                print the verifier version and exit.
  --help                   show this help and exit.

Exit codes:
  0  chain verified
  1  chain has at least one verification failure
  2  malformed input

See https://github.com/3030-Labs/wotw-verify for the full protocol.
`

func main() {
	var (
		workspaceKeyPath string
		jsonOut          bool
		strictMode       bool
		verbose          bool
		showVersion      bool
		selfTest         bool
	)

	fs := flag.NewFlagSet("wotw-verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&workspaceKeyPath, "workspace-key", "", "path to workspace KEK")
	fs.BoolVar(&jsonOut, "json", false, "emit JSON report")
	fs.BoolVar(&strictMode, "strict", false, "refuse pre-G5 chains")
	fs.BoolVar(&verbose, "verbose", false, "verbose human output")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.BoolVar(&selfTest, "self-test", false, "run embedded self-test scenarios")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf("wotw-verify %s\n", verify.ToolVersion)
		return
	}

	if selfTest {
		os.Exit(runSelfTest(jsonOut))
	}

	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	packPath := fs.Arg(0)

	var kek []byte
	if workspaceKeyPath != "" {
		k, err := keys.LoadKEKFromFile(workspaceKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wotw-verify: %v\n", err)
			os.Exit(2)
		}
		kek = k
	}

	report, err := verify.Pack(packPath, verify.Options{
		WorkspaceKEK:    kek,
		Strict:          strictMode,
		IncludeStatuses: jsonOut || verbose,
	})

	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(report)
	} else if report != nil {
		printHuman(report, verbose, err)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "wotw-verify: %v\n", err)
	}

	if report != nil {
		os.Exit(report.ExitCode)
	}
	os.Exit(2)
}

func printHuman(r *verify.Report, verbose bool, err error) {
	out := os.Stdout
	if r.ExitCode != 0 {
		out = os.Stderr
	}
	fmt.Fprintf(out, "wotw-verify %s\n", verify.ToolVersion)
	fmt.Fprintf(out, "pack:           %s\n", r.PackPath)
	if r.WorkspaceID != "" {
		fmt.Fprintf(out, "workspace_id:   %s\n", r.WorkspaceID)
	}
	fmt.Fprintf(out, "total_records:  %d\n", r.TotalRecords)
	fmt.Fprintf(out, "verified:       %d\n", r.VerifiedRecords)
	fmt.Fprintf(out, "attested:       %d\n", r.AttestedRecords)
	if r.UnattestedTotal > 0 {
		fmt.Fprintf(out, "unattested:     %d (pre-G5)\n", r.UnattestedTotal)
	}
	if r.FailedRecords > 0 {
		fmt.Fprintf(out, "failed:         %d\n", r.FailedRecords)
	}
	fmt.Fprintf(out, "strict_mode:    %v\n", r.StrictMode)
	fmt.Fprintf(out, "duration_ms:    %d\n", r.DurationMS)

	if verbose {
		fmt.Fprintln(out, "\nPer-record status:")
		for _, s := range r.Statuses {
			marker := "  ✓"
			if !s.IDOK || !s.ChainHashOK || !s.LinkageOK || (s.HMACPresent && !s.HMACOK) {
				marker = "  ✗"
			} else if !s.HMACPresent {
				marker = "  ?"
			}
			fmt.Fprintf(out, "%s  seq=%d  id=%s…  status=%s",
				marker, s.Seq, shortID(s.ID), s.AttestationStatus)
			if s.HMACKeyID != "" {
				fmt.Fprintf(out, "  key_id=%s…  key_state=%s",
					shortID(s.HMACKeyID), s.HMACKeyState)
			}
			fmt.Fprintln(out)
		}
	}

	if len(r.Errors) > 0 {
		fmt.Fprintln(out, "\nErrors:")
		for _, e := range r.Errors {
			fmt.Fprintf(out, "  seq=%d  id=%s…  %s\n", e.Seq, shortID(e.ID), e.Reason)
		}
	}

	fmt.Fprintf(out, "\nverdict:        %s\n", r.Verdict)

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nwotw-verify: %v\n", err)
	}
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func runSelfTest(jsonOut bool) int {
	results, err := selftest.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotw-verify self-test harness error: %v\n", err)
		return 2
	}
	if jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"tool":       "wotw-verify",
			"version":    verify.ToolVersion,
			"mode":       "self-test",
			"scenarios":  results,
			"all_passed": allPassed(results),
		})
	} else {
		fmt.Printf("wotw-verify %s self-test\n\n", verify.ToolVersion)
		for _, r := range results {
			marker := "✓"
			if !r.Pass() {
				marker = "✗"
			}
			fmt.Printf("  %s  %-28s  got=%s/%d  want=%s/%d\n",
				marker, r.Name, r.GotVerdict, r.GotExit, r.WantVerdict, r.WantExit)
		}
	}
	if !allPassed(results) {
		return 1
	}
	return 0
}

func allPassed(rs []selftest.Result) bool {
	for _, r := range rs {
		if !r.Pass() {
			return false
		}
	}
	return true
}
