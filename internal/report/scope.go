package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/astr4liteEx/rpt/sdk"
)

// ScopeFile is the scope table's file name at the report root.
const ScopeFile = "scope.csv"

// Scope reads scope.csv. Its header row must name id and host; port is
// optional, and every other column is kept as a string in ScopeRow.Extra. A
// bad row doesn't stop the read: good rows are returned together with a
// joined error holding one *FileError per bad row.
func (r *Report) Scope() ([]sdk.ScopeRow, error) {
	src, err := r.root.ReadFile(ScopeFile)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
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

	var (
		rows []sdk.ScopeRow
		errs []error
	)
	for {
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
		if err != nil {
			errs = append(errs, &FileError{Path: ScopeFile, Line: line, Err: err})
			continue
		}
		rows = append(rows, row)
	}
	return rows, errors.Join(errs...)
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
