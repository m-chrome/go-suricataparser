package suricataparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleString(t *testing.T) {
	raw := "# alert tcp any any -> any any (sid:1; classtype:trojan;)"
	r, err := ParseRule(raw)
	require.NoError(t, err)
	assert.Equal(t, raw, r.String())
}

func TestGetOptions(t *testing.T) {
	raw := "# alert tcp any any -> any any (sid:1; classtype:trojan; http_uri; metadata: severity low;)"
	r, err := ParseRule(raw)
	require.NoError(t, err)
	opts := r.GetOptions("http_uri")
	assert.Len(t, opts, 1)
}

func TestBuildRule(t *testing.T) {
	opts := []*Option{
		{"http_uri", ""},
		{"sid", "1"},
	}
	r := NewRule(true, "alert", "any any -> any any", "", opts)
	require.NotNil(t, r)
	assert.Equal(t, "alert any any -> any any (http_uri; sid:1;)", r.raw)
}

func TestParseRuleWithNMetadata(t *testing.T) {
	raw := "# alert tcp any any -> any any (sid:1; " +
		"classtype:trojan; http_uri; metadata: severity low; metadata: severity low;)"
	r, err := ParseRule(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"severity low",
		"severity low",
	}, r.Metadata.Items())
}
