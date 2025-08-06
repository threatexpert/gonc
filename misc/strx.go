package misc

import (
	"bytes"
	"fmt"
	"unicode"
)

func ParseCommandLine(command string) ([]string, error) {
	var args []string
	var buffer bytes.Buffer
	var inQuotes bool
	var escape bool

	for _, r := range command {
		switch {
		case escape:
			buffer.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes && unicode.IsSpace(r):
			if buffer.Len() > 0 {
				args = append(args, buffer.String())
				buffer.Reset()
			}
		default:
			buffer.WriteRune(r)
		}
	}

	if buffer.Len() > 0 {
		args = append(args, buffer.String())
	}

	if inQuotes {
		return nil, fmt.Errorf("unclosed quote in command line")
	}

	return args, nil
}
