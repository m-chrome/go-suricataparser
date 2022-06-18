package suricataparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionString(t *testing.T) {
	opt := NewOption("gid", "1")
	assert.Equal(t, "gid:1;", opt.String())

	opt = NewEmptyOption("http_uri")
	assert.Equal(t, "http_uri;", opt.String())
}
