package suricataparser

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionString(t *testing.T) {
	opt := NewOption("gid", "1")
	assert.Equal(t, "gid:1;", opt.String())
}

func TestNewEmptyOption(t *testing.T) {
	opt := NewEmptyOption("http_uri")
	assert.Equal(t, "http_uri;", opt.String())
}

func TestNewMsgOption(t *testing.T) {
	opt := NewMsgOption("ET MALWARE Win32/RecordBreaker CnC Checkin")
	assert.Equal(t, OptMsg, opt.Name)
	assert.Equal(t, "\"ET MALWARE Win32/RecordBreaker CnC Checkin\"", opt.Value)
}

func ExampleNewOption() {
	fmt.Println(NewOption("rev", "1"))
	// Output: rev:1;
}

func ExampleNewEmptyOption() {
	fmt.Println(NewEmptyOption("http_uri"))
	// Output: http_uri;
}

func ExampleNewMsgOption() {
	fmt.Println(NewMsgOption("ET MALWARE Win32/RecordBreaker CnC Checkin"))
	// Output: msg:"ET MALWARE Win32/RecordBreaker CnC Checkin";
}
