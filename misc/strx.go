package misc

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
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

func ParseSize(s string) (uint64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	multipliers := map[string]uint64{
		"K": 1024, "KB": 1024,
		"M": 1024 * 1024, "MB": 1024 * 1024,
		"G": 1024 * 1024 * 1024, "GB": 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			v := strings.TrimSuffix(s, suffix)
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return 0, err
			}
			return n * mult, nil
		}
	}
	return strconv.ParseUint(s, 10, 64)
}
