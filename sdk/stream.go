package sdk

import (
	"bufio"
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"iter"
)

// MaxLine is the longest JSON Lines record rpt reads, in bytes.
const MaxLine = 16 << 20

// Rec is one record read from a JSON Lines stream.
type Rec struct {
	Kind string // the record's "kind", or "" when it has none
	Raw  []byte // the line exactly as received, without its line ending
	Line int    // 1-based line number in the stream
}

// LineError reports a line that is not a record: invalid JSON, JSON that is
// not an object, or a line longer than MaxLine. Records keeps reading after
// one.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
func (e *LineError) Unwrap() error { return e.Err }

var errTooLong = fmt.Errorf("line longer than %d bytes", MaxLine)

// ErrStopped comes with the error-level problem record Records stops at,
// given StopAtError.
var ErrStopped = errors.New("stopped at an error-level problem")

// A RecordsOption changes how Records reads.
type RecordsOption func(*recordsOptions)

type recordsOptions struct{ stop bool }

// StopAtError makes Records stop at the first error-level problem record:
// it yields that record with ErrStopped and nothing after it. A writer or
// renderer uses it, since it must not act on a stream an earlier stage
// found broken: it passes the record on, writes nothing, and exits 1.
// Filters and checkers read on and pass problems through.
func StopAtError() RecordsOption {
	return func(o *recordsOptions) { o.stop = true }
}

// Records reads a JSON Lines stream. It yields each record with its
// original bytes, so filters can pass through records they don't own byte
// for byte. Blank lines are skipped; lines may end in \n or \r\n, and the
// last line needs no newline. A line that isn't a record yields a
// *LineError and reading continues; a read error is yielded last.
func Records(r io.Reader, opts ...RecordsOption) iter.Seq2[Rec, error] {
	var o recordsOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(yield func(Rec, error) bool) {
		br := bufio.NewReaderSize(r, 64<<10)
		for n := 1; ; n++ {
			line, err := readLine(br)
			if err != nil && !errors.Is(err, errTooLong) && !errors.Is(err, io.EOF) {
				yield(Rec{}, fmt.Errorf("read records: %w", err))
				return
			}
			eof := errors.Is(err, io.EOF)
			switch {
			case errors.Is(err, errTooLong):
				if !yield(Rec{Line: n}, &LineError{Line: n, Err: errTooLong}) {
					return
				}
			case len(bytes.TrimSpace(line)) > 0:
				rec, recErr := parseRec(line, n)
				if recErr == nil && o.stop && rec.Kind == "problem" && isErrorProblem(rec.Raw) {
					yield(rec, ErrStopped)
					return
				}
				if !yield(rec, recErr) {
					return
				}
			}
			if eof {
				return
			}
		}
	}
}

// readLine returns the next line without its line ending. A line over
// MaxLine is discarded up to its newline and reported as errTooLong. At the
// end of the stream it returns the last line with io.EOF.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > MaxLine+2 { // +2 for a \r\n ending
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil && !errors.Is(err, io.EOF):
			return nil, err
		}
		if tooLong {
			if errors.Is(err, io.EOF) {
				return nil, errors.Join(errTooLong, io.EOF)
			}
			return nil, errTooLong
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > MaxLine {
			return nil, errTooLong
		}
		return line, err
	}
}

// parseRec checks that line is a JSON object and reads its kind.
func parseRec(line []byte, n int) (Rec, error) {
	var head map[string]jsontext.Value
	if err := json.Unmarshal(line, &head); err != nil {
		return Rec{Line: n}, &LineError{Line: n, Err: fmt.Errorf("not a record: %w", err)}
	}
	if head == nil {
		return Rec{Line: n}, &LineError{Line: n, Err: errors.New("not a record: null")}
	}
	var kind string
	if v, ok := head["kind"]; ok {
		_ = json.Unmarshal(v, &kind) // a non-string kind is no kind
	}
	return Rec{Kind: kind, Raw: line, Line: n}, nil
}

// isErrorProblem reports whether a problem record is error-level.
func isErrorProblem(raw []byte) bool {
	var p struct {
		Level Level `json:"level"`
	}
	return json.Unmarshal(raw, &p) == nil && p.Level == Error
}
