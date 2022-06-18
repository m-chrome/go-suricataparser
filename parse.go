package suricataparser

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strings"
)

var ruleRegExp = regexp.MustCompile("^(?P<enabled>#)*[\\s#]*(?P<raw>(?P<header>[^()]+)\\((?P<options>.*)\\)$)")

func parseOptions(buffer string) ([]*Option, error) {
	if buffer == "" {
		return nil, errors.New("options string is empty")
	}

	if !strings.HasSuffix(buffer, ";") {
		return nil, errors.New("options must have semicolon in end")
	}

	buffer = strings.Trim(buffer, " ")
	parts := strings.Split(buffer, ";")
	parts = parts[:len(parts)-1]
	var options []*Option
	optionStr := ""
	for _, part := range parts {
		optionStr += part
		if strings.HasSuffix(part, "\\") {
			optionStr += ";"
			continue
		}
		name := ""
		value := ""
		if strings.Contains(optionStr, ":") {
			optParts := strings.SplitN(optionStr, ":", 2)
			if len(optParts) != 2 {
				return nil, errors.New("can not parse rule")
			}
			name = strings.Trim(optParts[0], " ")
			value = strings.Trim(optParts[1], " ")
		} else {
			name = strings.Trim(optionStr, " ")
		}
		options = append(options, &Option{name, value})
		optionStr = ""
	}

	return options, nil
}

// ParseRule from raw string
func ParseRule(buffer string) (*Rule, error) {
	matches := ruleRegExp.FindAllSubmatch([]byte(buffer), -1)
	if matches == nil || (len(matches) != 1 && len(matches[0]) != 5) {
		return nil, errors.New("can not parse rule")
	}

	submatches := matches[0]

	// is rule enabled
	enabledMatch := submatches[1]
	var enabled bool
	if strings.HasPrefix(string(enabledMatch), "#") {
		enabled = false
	} else {
		enabled = true
	}

	// parse fullHeader
	headerMatch := submatches[3]
	fullHeader := strings.Trim(string(headerMatch), " ")
	headerParts := strings.SplitN(fullHeader, " ", 2)
	if len(headerParts) != 2 {
		return nil, errors.New("wrong header")
	}

	action := headerParts[0]
	if action != "alert" && action != "drop" &&
		action != "pass" && action != "reject" &&
		action != "rejectsrc" && action != "rejectdst" &&
		action != "rejectboth" {
		return nil, errors.New("wrong rule action")
	}

	header := headerParts[1]

	// raw rule
	raw := string(submatches[2])

	// rule options
	optionsMatch := submatches[4]
	options, err := parseOptions(string(optionsMatch))
	if err != nil {
		return nil, err
	}

	return NewRule(enabled, action, header, raw, options), nil
}

// ParseFile with rules from filesystem
func ParseFile(path string) ([]*Rule, error) {
	readFile, err := os.Open(path)
	defer readFile.Close()
	if err != nil {
		return nil, err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	buffer := ""
	var rules []*Rule
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if strings.HasSuffix(line, "\\") {
			buffer += line[:len(line)-1]
			continue
		}
		// it's ok to ignore parse errors
		rule, _ := ParseRule(buffer + line)
		if rule != nil {
			rules = append(rules, rule)
		}
		buffer = ""
	}
	return rules, nil
}
