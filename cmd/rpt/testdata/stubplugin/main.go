// Command stubplugin is the plugin rpt's dispatch tests run. It prints its
// arguments and RPT_* environment as JSON and exits with the code given as
// "exit=N". Installed as rpt-hang, it never answers --describe.
package main

import (
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/astr4liteEx/rpt/sdk"
)

func main() {
	if filepath.Base(os.Args[0]) == "rpt-hang" && len(os.Args) == 2 && os.Args[1] == "--describe" {
		time.Sleep(time.Hour)
	}
	sdk.Main(sdk.Plugin{
		Description: sdk.Description{Summary: "Stub plugin for tests", Usage: "rpt stub [exit=N]", Version: "0.0.1"},
		Run: func(args []string, _ io.Reader, stdout, _ io.Writer) int {
			env := map[string]string{}
			for _, kv := range os.Environ() {
				if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "RPT_") {
					env[k] = v
				}
			}
			json.MarshalWrite(stdout, map[string]any{"args": args, "env": env})
			code := 0
			for _, a := range args {
				if n, ok := strings.CutPrefix(a, "exit="); ok {
					code, _ = strconv.Atoi(n)
				}
			}
			return code
		},
	})
}
