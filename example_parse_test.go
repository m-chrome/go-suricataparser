package suricataparser_test

import (
	"fmt"

	"github.com/m-chrome/go-suricataparser"
)

func ExampleParseRule() {
	rule, _ := suricataparser.ParseRule(
		"alert http any any -> [1.1.1.1] any (sid:1; rev:1; gid:1; http_uri; msg:\"message\";)")
	fmt.Println(rule)
	fmt.Println(rule.Enabled)
	fmt.Println(rule.Sid())
	fmt.Println(rule.Rev())
	fmt.Println(rule.Msg())
	fmt.Println(rule.Action())
	fmt.Println(rule.Header())
	opts := rule.GetOptions("http_uri")
	fmt.Println(opts[0])
	rule.Enabled = false
	fmt.Println(rule.Enabled)
	fmt.Println(rule)
	// Output:
	// alert http any any -> [1.1.1.1] any (sid:1; rev:1; gid:1; http_uri; msg:"message";)
	// true
	// 1
	// 1
	// message
	// alert
	// http any any -> [1.1.1.1] any
	// http_uri;
	// false
	// # alert http any any -> [1.1.1.1] any (sid:1; rev:1; gid:1; http_uri; msg:"message";)
}

func ExampleParseFile() {
	rules, _ := suricataparser.ParseFile("test/test.rules")
	fmt.Println(len(rules))
	// Output:
	// 2
}
