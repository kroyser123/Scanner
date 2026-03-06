package scanner

import (
	"fmt"
	"regexp"
)

type Pattern struct {
	ID       string
	Name     string
	Level    Level
	Keywords []string
	Regex    *regexp.Regexp
}

// NewPattern - создаёт паттерн с проверкой ошибки
func NewPattern(id, name string, level Level, keywords []string, regexStr string) (*Pattern, error) {
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, fmt.Errorf("ошибка в паттерне %s: %v", id, err)
	}

	return &Pattern{
		ID:       id,
		Name:     name,
		Level:    level,
		Keywords: keywords,
		Regex:    re,
	}, nil
}

// MustNewPattern - создаёт паттерн, паникует при ошибке
func MustNewPattern(id, name string, level Level, keywords []string, regexStr string) *Pattern {
	pattern, err := NewPattern(id, name, level, keywords, regexStr)
	if err != nil {
		panic(err)
	}
	return pattern
}
