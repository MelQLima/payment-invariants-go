package checker

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Result is the verdict of one invariant.
type Result struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Claim  string        `json:"claim"`
	Pass   bool          `json:"pass"`
	Detail string        `json:"detail"`
	Took   time.Duration `json:"took_ns"`
}

// Report is the outcome of a full run.
type Report struct {
	Target  string   `json:"target"`
	Run     string   `json:"run"`
	Results []Result `json:"results"`
}

// Failed counts violated invariants.
func (r Report) Failed() int {
	n := 0
	for _, x := range r.Results {
		if !x.Pass {
			n++
		}
	}
	return n
}

// WriteJSON writes the machine-readable report.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const (
	green = "\x1b[32m"
	red   = "\x1b[31m"
	dim   = "\x1b[2m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

// WriteText prints one line per invariant, then a summary.
func (r Report) WriteText(w io.Writer, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}
	fmt.Fprintf(w, "%s  %s  run %s\n\n", c(bold, "payment-invariants-go"), r.Target, r.Run)
	for _, x := range r.Results {
		tag := c(green, "PASS")
		if !x.Pass {
			tag = c(red, "FAIL")
		}
		fmt.Fprintf(w, " %s  %-4s %s\n", tag, x.ID, c(bold, x.Name))
		fmt.Fprintf(w, "       %s\n", c(dim, x.Claim))
		fmt.Fprintf(w, "       %s %s\n", wrapDetail(x.Detail), c(dim, fmt.Sprintf("(%d ms)", x.Took.Milliseconds())))
	}
	fmt.Fprintln(w)
	f := r.Failed()
	if f == 0 {
		fmt.Fprintf(w, "%s\n", c(green+bold, fmt.Sprintf("%d/%d invariants hold", len(r.Results), len(r.Results))))
		return
	}
	fmt.Fprintf(w, "%s\n", c(red+bold, fmt.Sprintf("%d of %d invariants VIOLATED", f, len(r.Results))))
}

func wrapDetail(s string) string { return strings.ReplaceAll(s, "\n", "\n       ") }
