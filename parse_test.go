package suricataparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule(t *testing.T) {
	rawRule := "alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; gid:1; http_uri; msg:\"message\";)"
	rule, err := ParseRule(rawRule)
	require.NoError(t, err)
	assert.True(t, rule.Enabled)
	assert.Equal(t, rule.Sid(), int64(1))
	assert.Equal(t, rule.Gid(), int64(1))
	assert.Equal(t, rule.Rev(), int64(1))
	assert.Equal(t, "http any any -> [1.1.1.1, 1.1.1.2] any", rule.Header())
	assert.Equal(t, "message", rule.Msg())
	assert.Equal(t, "alert", rule.Action())
	assert.Len(t, rule.Options, 5)
}

func TestDisabledRule(t *testing.T) {
	rawRule := "# alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; gid:1; http_uri; msg:\"message\";)"
	rule, err := ParseRule(rawRule)
	require.NoError(t, err)
	assert.False(t, rule.Enabled)
}

func TestDoubleCommentedRule(t *testing.T) {
	rawRule := "alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; gid:1; http_uri; msg:\"message\";)"
	disabledRule := "## " + rawRule
	rule, err := ParseRule(disabledRule)
	require.NoError(t, err)
	assert.False(t, rule.Enabled)
	assert.Equal(t, rawRule, rule.raw)
}

func TestWithLists(t *testing.T) {
	rawRule := "alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; gid:1; http_uri; msg:\"message\";)"
	rule, err := ParseRule(rawRule)
	require.NoError(t, err)
	assert.True(t, rule.Enabled)
	assert.Equal(t, "alert", rule.Action())
	assert.Equal(t, "http any any -> [1.1.1.1, 1.1.1.2] any", rule.Header())
}

func TestWithBrokenOptions(t *testing.T) {
	rawRule := "alert tcp any any -> any any (sid:1)"
	_, err := ParseRule(rawRule)
	require.Error(t, err)
}

func TestRuleWithWrongAction(t *testing.T) {
	_, err := ParseRule("dig tcp any any - any any (sid:1;)")
	require.Error(t, err)
}

func TestNotRule(t *testing.T) {
	_, err := ParseRule("# This is suricata rule")
	require.Error(t, err)
}

func TestWithInvalidHeader(t *testing.T) {
	_, err := ParseRule("alert (sid:1;)")
	require.Error(t, err)
}

func TestWithColonInOptions(t *testing.T) {
	raw := "alert tcp any any -> any any (msg:\"Message: text\";)"
	r, err := ParseRule(raw)
	require.NoError(t, err)
	assert.Equal(t, "Message: text", r.Msg())
}

func TestWithEmptyOptions(t *testing.T) {
	_, err := ParseRule("alert tcp any any -> any any ()")
	require.Error(t, err)
}

func TestParseFile(t *testing.T) {
	rules, err := ParseFile("test/test.rules")
	require.NoError(t, err)
	assert.Len(t, rules, 2)
	_, err = ParseFile("test/fantastic.rules")
	require.Error(t, err)
}
