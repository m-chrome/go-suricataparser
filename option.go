package suricataparser

import "fmt"

const (
	OptClasstype = "classtype"
	OptGid       = "gid"
	OptMetadata  = "metadata"
	OptMsg       = "msg"
	OptRev       = "rev"
	OptSid       = "sid"
	OptReference = "reference"
)

// Option stores parsed option from rule - https://suricata.readthedocs.io/en/latest/rules/intro.html#rule-options
type Option struct {
	Name  string
	Value string
}

func (o Option) String() string {
	if o.Value == "" {
		return fmt.Sprintf("%s;", o.Name)
	}
	return fmt.Sprintf("%s:%s;", o.Name, o.Value)
}

// NewOption returns rule metadata option
func NewOption(name, value string) Option {
	return Option{Name: name, Value: value}
}

// NewEmptyOption returns rule metadata option with empty value
func NewEmptyOption(name string) Option {
	return Option{Name: name, Value: ""}
}

// NewMsgOption returns rule message description option
func NewMsgOption(message string) Option {
	return Option{Name: OptMsg, Value: fmt.Sprintf("\"%s\"", message)}
}
