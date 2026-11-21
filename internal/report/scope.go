package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/astr4liteEx/rpt/sdk"
)

// ScopeFile is the scope table's file name at the report root.
const ScopeFile = "scope.csv"

// Scope reads scope.csv. Its header row must name id and host; port and
// protocol (tcp or udp) are optional, and every other column is kept as a
// string in ScopeRow.Extra. A row needs an id and a host, and an id no
// earlier row has. A bad row doesn't stop the read: good rows are returned
// together with a joined error holding one *FileError per bad row.
func (r *Report) Scope() ([]sdk.ScopeRow, error) {
	rows, err := r.ScopeWithLines()
	for i := range rows {
		rows[i].Lines = nil
	}
	return rows, err
}

// scopeColumnsReserved are the record members rpt sets on scope records,
// so no scope.csv column may be named like one.
var scopeColumnsReserved = []string{"kind", "rev", "lines"}

// ScopeWithLines is Scope with each row's Lines set: scope.csv's absolute
// path and the line the row starts on.
func (r *Report) ScopeWithLines() ([]sdk.ScopeRow, error) {
	src, err := r.root.ReadFile(ScopeFile)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	return parseScope(src, filepath.Join(r.abs, ScopeFile))
}

// parseScope reads scope.csv's bytes as ScopeWithLines does; file is its
// absolute path, for Lines.
func parseScope(src []byte, file string) ([]sdk.ScopeRow, error) {
	cr := csv.NewReader(bytes.NewReader(src))
	header, err := cr.Read()
	if err != nil {
		return nil, &FileError{Path: ScopeFile, Line: 1, Err: fmt.Errorf("header: %w", err)}
	}
	for _, need := range []string{"id", "host"} {
		if !slices.Contains(header, need) {
			return nil, &FileError{Path: ScopeFile, Line: 1, Err: fmt.Errorf("header has no %q column", need)}
		}
	}
	for _, col := range scopeColumnsReserved {
		if slices.Contains(header, col) {
			return nil, &FileError{Path: ScopeFile, Line: 1, Err: fmt.Errorf("column %q is reserved: rpt sets it on scope records; rename the column", col)}
		}
	}
	headerText := trimEOL(src[:cr.InputOffset()])

	var (
		rows []sdk.ScopeRow
		errs []error
		seen = map[string]int{} // id -> line of the row that has it
	)
	for {
		start := cr.InputOffset()
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		line, _ := cr.FieldPos(0)
		if err != nil {
			if pe, ok := errors.AsType[*csv.ParseError](err); ok {
				line = pe.Line
			}
			errs = append(errs, &FileError{Path: ScopeFile, Line: line, Err: err})
			continue
		}
		row, err := scopeRow(header, rec)
		if err == nil {
			err = checkRow(row, seen)
		}
		if err != nil {
			errs = append(errs, &FileError{Path: ScopeFile, Line: line, Err: err})
			continue
		}
		seen[row.ID] = line
		row.Rev = rowRev(headerText, src[start:cr.InputOffset()])
		row.Lines = &sdk.ScopeLines{Row: line, File: file}
		rows = append(rows, row)
	}
	return rows, errors.Join(errs...)
}

// rowRev is a scope row's rev: over the header line and the row's own
// text, line ends left out, so edits to other rows leave it alone.
func rowRev(header, row []byte) string {
	return Rev(slices.Concat(header, []byte("\n"), trimEOL(row)))
}

// trimEOL drops a line's trailing line end.
func trimEOL(b []byte) []byte {
	return bytes.TrimRight(b, "\r\n")
}

func scopeRow(header, rec []string) (sdk.ScopeRow, error) {
	row := sdk.ScopeRow{Kind: "scope"}
	for i, col := range header {
		v := rec[i]
		switch col {
		case "id":
			row.ID = v
		case "host":
			row.Host = v
		case "port":
			if v == "" {
				continue
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return row, fmt.Errorf("port %q is not a number from 1 to 65535", v)
			}
			row.Port = p
		case "protocol":
			switch v {
			case "", "tcp", "udp":
				row.Protocol = v
			default:
				return row, fmt.Errorf("protocol %q is not tcp or udp", v)
			}
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return row, fmt.Errorf("column %q: %w", col, err)
			}
			if row.Extra == nil {
				row.Extra = map[string]jsontext.Value{}
			}
			row.Extra[col] = b
		}
	}
	return row, nil
}

// checkRow checks a parsed row against the rows before it.
func checkRow(row sdk.ScopeRow, seen map[string]int) error {
	switch {
	case row.ID == "":
		return errors.New("row has no id")
	case row.Host == "":
		return fmt.Errorf("%s has no host", row.ID)
	case seen[row.ID] > 0:
		return fmt.Errorf("%s is already the id of the row on line %d", row.ID, seen[row.ID])
	}
	return nil
}
