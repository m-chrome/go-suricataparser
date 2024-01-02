package suricataparser

import (
	"errors"
	"strings"
)

type Reference struct {
	Type string
	Ref  string
}

// ParseReference from raw string
func ParseReference(reference string) (*Reference, error) {
	if reference == "" {
		return nil, errors.New("reference is never empty")
	}
	parts := strings.SplitN(reference, ",", 2)
	if len(parts) != 2 {
		return nil, errors.New("reference should be type,ref")
	}
	return &Reference{Type: parts[0], Ref: parts[1]}, nil
}
