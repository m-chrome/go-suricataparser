Suricata rule parser
==============

Pure Golang port of [py-suricataparser](https://github.com/m-chrome/py-suricataparser) with same functions.

## Installation

go-suricataparser supports Go 1.18 or higher.

```shell
go get https://github.com/m-chrome/go-suricataparser
```

## Usage

```go
package main

import (
	"fmt"
	
	"github.com/m-chrome/go-suricataparser"
)

func main() {
	// Parse rules file
	rules, _ := suricataparser.ParseFile("suricata.rules")
	for _, r := range rules {
		fmt.Println(r)
	}
	
	// Parse rule from string
	rule, _ := suricataparser.ParseRule("alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; gid:1; http_uri; msg:"message";)")
	fmt.Println(rule)
	
	// Disable rule
	rule.Enabled = false
	fmt.Println(rule)
}
```
