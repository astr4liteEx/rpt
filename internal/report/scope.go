package report

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Scope is scope.csv: the hosts the report's findings may be on.
type Scope struct {
	// Exists is false when the report has no scope.csv.
	Exists bool
	// Err is why the file can't be read at all, a *FileError: no header,
	// or a header without id and host. Nothing below is set then.
	Err error

	Header []string // column names, trimmed and lower-cased
	Rows   []*Row
	// RowErrs are rows that can't be read, as *FileError; the other rows
	// are still in Rows.
	RowErrs []error

	src       []byte
	headerEnd int // offset just past the header line
}

// A Row is one scope row.
type Row struct {
	ID, Host, Protocol string
	Port               int
	Extra              map[string]string // the other columns' values
	Line               int               // file line
	Start, End         int               // the row's bytes in the file, its line end included
	Rev                string
}

// reservedColumns are names rpt sets on scope records.
var reservedColumns = []string{"kind", "lines"}

var bom = []byte("\xef\xbb\xbf")

func parseScope(src []byte, exists bool) *Scope {
	s := &Scope{Exists: exists, src: src}
	if !exists {
		return s
	}
	fail := func(line int, err error) *Scope {
		return &Scope{Exists: true, Err: &FileError{Path: ScopeFile, Line: line, Err: err}, src: src}
	}
	body := bytes.TrimPrefix(src, bom)
	skip := len(src) - len(body)
	cr := csv.NewReader(bytes.NewReader(body))
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return fail(1, fmt.Errorf("header: %w", err))
	}
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(header[i]))
	}
	for _, need := range []string{"id", "host"} {
		if !slices.Contains(header, need) {
			return fail(1, fmt.Errorf("the header has no %q column", need))
		}
	}
	for _, col := range reservedColumns {
		if slices.Contains(header, col) {
			return fail(1, fmt.Errorf("the column name %q is reserved: rpt sets it on scope records", col))
		}
	}
	s.Header, s.headerEnd = header, skip+int(cr.InputOffset())
	headerText := bytes.TrimRight(src[skip:s.headerEnd], "\r\n")
	for {
		start := skip + int(cr.InputOffset())
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		line, _ := cr.FieldPos(0)
		if err == nil && len(rec) != len(header) {
			err = fmt.Errorf("the row has %d fields; the header has %d", len(rec), len(header))
		}
		var row *Row
		if err == nil {
			row, err = scopeRow(header, rec)
		}
		if err == nil {
			err = s.checkRow(row)
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.Line
			}
			s.RowErrs = append(s.RowErrs, &FileError{Path: ScopeFile, Line: line, Err: err})
			continue
		}
		row.Line, row.Start, row.End = line, start, skip+int(cr.InputOffset())
		row.Rev = Rev(slices.Concat(headerText, []byte("\n"), bytes.TrimRight(src[row.Start:row.End], "\r\n")))
		s.Rows = append(s.Rows, row)
	}
	return s
}

func scopeRow(header, rec []string) (*Row, error) {
	row := &Row{}
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
				return nil, fmt.Errorf("port %q is not a number from 1 to 65535", v)
			}
			row.Port = p
		case "protocol":
			if v != "" && v != "tcp" && v != "udp" {
				return nil, fmt.Errorf("protocol %q is not tcp or udp", v)
			}
			row.Protocol = v
		default:
			if row.Extra == nil {
				row.Extra = map[string]string{}
			}
			row.Extra[col] = v
		}
	}
	return row, nil
}

// checkRow refuses a row without an id or host, or whose id another row
// has. IDs are compared without regard to case.
func (s *Scope) checkRow(row *Row) error {
	switch {
	case row.ID == "":
		return errors.New("the row has no id")
	case row.Host == "":
		return fmt.Errorf("%s has no host", row.ID)
	}
	if other := s.find(row.ID); other != nil {
		return fmt.Errorf("%s is already the id of the row on line %d", row.ID, other.Line)
	}
	return nil
}

// find is the row whose ID matches id, case aside, or nil.
func (s *Scope) find(id string) *Row {
	for _, r := range s.Rows {
		if strings.EqualFold(r.ID, id) {
			return r
		}
	}
	return nil
}

// Row returns the row with the given ID, case aside.
func (s *Scope) Row(id string) (*Row, error) {
	if r := s.find(id); r != nil {
		return r, nil
	}
	return nil, fmt.Errorf("%w scope row: %s", ErrNotFound, id)
}
