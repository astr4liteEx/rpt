// Command rpt defines and enforces the rpt report format over a plain,
// git-tracked folder, and hands every verb it doesn't know to an rpt-<verb>
// plugin.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one rpt invocation and returns its exit code. Only main calls
// os.Exit, so deferred calls in verbs always run.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "usage: rpt <verb> [args]")
	return 2 // usage or config error
}
