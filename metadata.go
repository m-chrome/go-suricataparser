package suricataparser

import (
	"errors"
	"fmt"
	"strings"
)

// Metadata stores parsed meta values - https://suricata.readthedocs.io/en/latest/rules/meta.html#metadata
type Metadata struct {
	items []string
}

func (m *Metadata) String() string {
	return strings.Join(m.items, ", ")
}

func (m *Metadata) AddMeta(key, value string) {
	m.AddItem(fmt.Sprintf("%s %s", key, value))
}

func (m *Metadata) AddItem(item string) {
	m.items = append(m.items, item)
}

func (m *Metadata) PopMeta(key string) {
	var newItems []string
	for _, meta := range m.items {
		if !strings.HasPrefix(meta, key) {
			newItems = append(newItems, meta)
		}
	}
	m.items = newItems
}

func (m *Metadata) Merge(metadata Metadata) {
	for _, item := range metadata.Items() {
		m.AddItem(item)
	}
}

func (m *Metadata) Items() []string {
	return m.items
}

// NewMetadata returns empty Metadata
func NewMetadata() *Metadata {
	return &Metadata{[]string{}}
}

// ParseMetadata from raw string
func ParseMetadata(metadata string) (*Metadata, error) {
	if metadata == "" {
		return nil, errors.New("metadata never empty")
	}
	return &Metadata{items: strings.Split(metadata, ", ")}, nil
}
