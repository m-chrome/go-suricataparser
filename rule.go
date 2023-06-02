package suricataparser

import (
	"fmt"
	"strconv"
	"strings"
)

// Rule stores parsed suricata rule - https://suricata.readthedocs.io/en/latest/rules/intro.html#rules-format
type Rule struct {
	Enabled  bool
	action   string
	header   string
	Options  []*Option
	Metadata *Metadata

	sid       int64
	gid       int64
	rev       int64
	classtype string
	msg       string

	// raw rule representation
	raw string
}

func (r *Rule) String() string {
	ruleStr := ""
	if !r.Enabled {
		ruleStr += "# "
	}
	ruleStr += r.raw
	return ruleStr
}

// Sid - rule ID - https://suricata.readthedocs.io/en/latest/rules/meta.html#sid-signature-id
func (r *Rule) Sid() int64 {
	return r.sid
}

// Gid - group ID - https://suricata.readthedocs.io/en/latest/rules/meta.html#gid-group-id
func (r *Rule) Gid() int64 {
	return r.gid
}

// Msg - rule description - https://suricata.readthedocs.io/en/latest/rules/meta.html#msg-message
func (r *Rule) Msg() string {
	return r.msg
}

// Rev rule revision (version) - https://suricata.readthedocs.io/en/latest/rules/meta.html#rev-revision
func (r *Rule) Rev() int64 {
	return r.rev
}

// ClassType rule class type - https://docs.suricata.io/en/latest/rules/meta.html#classtype
func (r *Rule) ClassType() string {
	return r.classtype
}

// Header defines the protocol, IP addresses, ports and direction of the rule
func (r *Rule) Header() string {
	return r.header
}

// Action from rule - https://suricata.readthedocs.io/en/latest/rules/intro.html#action
func (r *Rule) Action() string {
	return r.action
}

func (r *Rule) GetOptions(name string) []*Option {
	opts := make([]*Option, 0)
	for _, opt := range r.Options {
		if opt.Name == name {
			opts = append(opts, opt)
		}
	}
	return opts
}

func (r *Rule) buildRawRule() {
	rawRule := fmt.Sprintf("%s %s ", r.action, r.header)
	var opts []string
	for _, opt := range r.Options {
		opts = append(opts, opt.String())
	}
	rawRule += fmt.Sprintf("(%s)", strings.Join(opts, " "))
	r.raw = rawRule
}

func (r *Rule) fillFromOptions() {
	for _, opt := range r.Options {
		if opt.Name == OptMsg {
			r.msg = strings.Trim(opt.Value, "\"")
		}
		if opt.Name == OptSid {
			r.sid, _ = strconv.ParseInt(opt.Value, 10, 64)
		}
		if opt.Name == OptGid {
			r.gid, _ = strconv.ParseInt(opt.Value, 10, 64)
		}
		if opt.Name == OptRev {
			r.rev, _ = strconv.ParseInt(opt.Value, 10, 64)
		}
		if opt.Name == OptClasstype {
			r.classtype = opt.Value
		}
		if opt.Name == OptMetadata {
			r.fillMetadata(opt.Value)
		}
	}
}

func (r *Rule) fillMetadata(rawMetadata string) {
	parsed, _ := ParseMetadata(rawMetadata)
	r.Metadata.Merge(*parsed)
}

func NewRule(enabled bool, action, header, raw string, options []*Option) *Rule {
	rule := Rule{
		Enabled:  enabled,
		action:   action,
		header:   header,
		Options:  options,
		raw:      raw,
		Metadata: NewMetadata(),
	}

	if raw != "" {
		rule.fillFromOptions()
	} else {
		rule.buildRawRule()
	}
	return &rule
}
