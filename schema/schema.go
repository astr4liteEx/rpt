// Package schema holds rpt's published JSON Schemas, so rpt can resolve a
// plugin schema's $ref to one of them from memory.
package schema

import "embed"

// Files holds every *.schema.json in this folder, by file name.
//
//go:embed *.schema.json
var Files embed.FS
