package suricataparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetadata(t *testing.T) {
	m, err := ParseMetadata("malware_family Crypton, malware_family Nemesis")
	require.NoError(t, err)
	assert.Len(t, m.Items(), 2)
	_, err = ParseMetadata("")
	require.Error(t, err)
}

func TestToString(t *testing.T) {
	expectedMetadata := "malware_family Crypton, malware_family Nemesis"
	m, err := ParseMetadata(expectedMetadata)
	require.NoError(t, err)
	assert.Equal(t, expectedMetadata, m.String())
}

func TestAddMeta(t *testing.T) {
	m, err := ParseMetadata("malware_family Crypton, malware_family Nemesis")
	require.NoError(t, err)
	m.AddMeta("former_category", "TROJAN")
	assert.Len(t, m.items, 3)
}

func TestPopMeta(t *testing.T) {
	m, err := ParseMetadata("malware_family Crypton, malware_family Nemesis")
	require.NoError(t, err)

	// pop key not in meta
	m.PopMeta("key")
	assert.Len(t, m.items, 2)

	// pop key in meta
	m.PopMeta("malware_family")
	assert.Len(t, m.items, 0)
}

func TestMerge(t *testing.T) {
	m1, err := ParseMetadata("malware_family Crypton, malware_family Nemesis")
	require.NoError(t, err)
	m2, err := ParseMetadata("malware_family Crypton, malware_family Nemesis")
	require.NoError(t, err)
	assert.Len(t, m1.Items(), 2)
	m1.Merge(*m2)
	assert.Len(t, m1.Items(), 4)
}
