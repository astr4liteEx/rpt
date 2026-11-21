package main

import "fmt"

// Running a plugin in the test process would replace the test binary with
// it, ending the run early and reporting the package as passed. A test
// that runs a plugin must run the built rpt instead (rptCmd).
func init() {
	execPlugin = func(bin string, _, _ []string) error {
		panic(fmt.Sprintf("a test ran plugin %s in the test process; run the built rpt (rptCmd) instead", bin))
	}
}
