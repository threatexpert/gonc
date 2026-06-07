package apps

import (
	"bytes"
	"io"
	"testing"
)

func TestPtyshCapsOutputWriterSwallowsCapsAndEnablesResize(t *testing.T) {
	sid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	caps, err := encodePtyshCaps("0102030405060708")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var gotSID []byte
	w := newPtyshCapsOutputWriter(&out, func(s []byte) {
		gotSID = append([]byte(nil), s...)
	})

	payload := append(caps, []byte("shell output")...)
	if _, err := w.Write(payload[:5]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload[5:]); err != nil {
		t.Fatal(err)
	}

	if out.String() != "shell output" {
		t.Fatalf("output = %q", out.String())
	}
	if !bytes.Equal(gotSID, sid) {
		t.Fatalf("sid = %x", gotSID)
	}
}

func TestPtyshCapsOutputWriterPassesNonCaps(t *testing.T) {
	var out bytes.Buffer
	w := newPtyshCapsOutputWriter(&out, nil)

	if _, err := w.Write([]byte("\x1b[?25hplain")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "\x1b[?25hplain" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestPtyshResizeInputReaderConsumesResizeFrame(t *testing.T) {
	sid := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	frame := encodePtyshResize(sid, 40, 120)
	input := append([]byte("a"), frame...)
	input = append(input, []byte("b")...)

	var gotRows, gotCols int
	r := newPtyshResizeInputReader(bytes.NewReader(input), sid, func(rows, cols int) {
		gotRows = rows
		gotCols = cols
	})

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ab" {
		t.Fatalf("output = %q", out)
	}
	if gotRows != 40 || gotCols != 120 {
		t.Fatalf("resize = %dx%d", gotRows, gotCols)
	}
}

func TestPtyshResizeInputReaderPassesMismatchedSID(t *testing.T) {
	sid := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	frame := encodePtyshResize([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 40, 120)

	r := newPtyshResizeInputReader(bytes.NewReader(frame), sid, func(rows, cols int) {
		t.Fatalf("unexpected resize = %dx%d", rows, cols)
	})

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("output = %x, want %x", out, frame)
	}
}
