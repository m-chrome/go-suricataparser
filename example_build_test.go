package suricataparser_test

import (
	"fmt"

	"github.com/m-chrome/go-suricataparser"
)

func ExampleNewRule() {
	sidOpt := suricataparser.NewOption(suricataparser.OptSid, "1")
	msgOpt := suricataparser.NewMsgOption("description")
	httpMethodOpt := suricataparser.NewEmptyOption("http.method")
	opts := []*suricataparser.Option{
		&sidOpt,
		{Name: suricataparser.OptRev, Value: "1"},
		&httpMethodOpt,
		&msgOpt,
	}
	rule := suricataparser.NewRule(
		false, "alert", "http $HOME_NET any -> $EXTERNAL_NET any",
		"", opts)
	fmt.Println(rule)
	// Output:
	// # alert http $HOME_NET any -> $EXTERNAL_NET any (sid:1; rev:1; http.method; msg:"description";)
}
