package scanner

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cloudflare/ahocorasick"
)

// Scanner - главная структура
type Scanner struct {
	patterns   []*Pattern
	keywordMap map[string][]*Pattern
	matcher    *ahocorasick.Matcher
	keywords   []string
}

// NewScanner - создаёт новый сканер
func NewScanner() (*Scanner, error) {
	// Собираем все паттерны
	allPatterns := append(HighPatterns, MediumPatterns...)
	allPatterns = append(allPatterns, LowPatterns...)

	// Строим карту ключевых слов
	keywordMap := make(map[string][]*Pattern)
	var allKeywords []string

	for _, p := range allPatterns {
		for _, kw := range p.Keywords {
			if _, exists := keywordMap[kw]; !exists {
				keywordMap[kw] = []*Pattern{}
				allKeywords = append(allKeywords, kw)
			}
			keywordMap[kw] = append(keywordMap[kw], p)
		}
	}

	// Создаём matcher из cloudflare
	matcher := ahocorasick.NewStringMatcher(allKeywords)

	return &Scanner{
		patterns:   allPatterns,
		keywordMap: keywordMap,
		matcher:    matcher,
		keywords:   allKeywords,
	}, nil
}

// ScanFile - сканирует один файл
func (s *Scanner) ScanFile(filePath string) ([]*FindingResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return s.ScanContent(content, filePath), nil
}

// ScanContent - сканирует содержимое с энтропией
func (s *Scanner) ScanContent(content []byte, filePath string) []*FindingResult {
	var findings []*FindingResult
	seenMatches := make(map[string]bool)

	indices := s.matcher.Match(content)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.keywords) {
			continue
		}

		keyword := s.keywords[idx]
		patterns := s.keywordMap[keyword]
		if patterns == nil {
			continue
		}

		keywordBytes := []byte(keyword)
		searchPos := 0

		for {
			pos := bytes.Index(content[searchPos:], keywordBytes)
			if pos < 0 {
				break
			}

			realPos := searchPos + pos

			start := max(0, realPos-200)
			end := min(len(content), realPos+300)
			context := content[start:end]

			for _, pattern := range patterns {
				matches := pattern.Regex.FindAll(context, -1)

				for _, matchBytes := range matches {
					matchStr := string(matchBytes)

					matchPos := start + bytes.Index(context, matchBytes)
					lineNum, lineContent := findLine(content, matchPos)

					// Применяем энтропию для корректировки уровня
					adjustedLevel, _ := AdjustLevelByEntropy(
						pattern.Level,
						matchStr,
						lineContent,
					)

					// Дедупликация с учетом позиции
					key := fmt.Sprintf("%s:%s:%d", pattern.ID, matchStr, matchPos)
					if seenMatches[key] {
						continue
					}
					seenMatches[key] = true

					finding := &FindingResult{
						Level:       adjustedLevel,
						Line:        lineNum,
						FilePath:    filePath,
						PatternName: pattern.Name,
						Match:       matchStr,
						Context:     lineContent,
					}

					findings = append(findings, finding)
				}
			}

			searchPos = realPos + 1
		}
	}

	return findings
}

// ScanDirectory - сканирует директорию
func (s *Scanner) ScanDirectory(root string, excludeDirs []string) []*FindingResult {
	var findings []*FindingResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}

		for _, exclude := range excludeDirs {
			if strings.Contains(path, exclude) {
				return nil
			}
		}

		if isBinary(path) {
			return nil
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			fileFindings, _ := s.ScanFile(path)

			mu.Lock()
			findings = append(findings, fileFindings...)
			mu.Unlock()
		}()

		return nil
	})

	wg.Wait()
	return findings
}

// ========== ФУНКЦИИ ЭНТРОПИИ ==========
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Словарь для подсчета частоты каждого символа
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// AdjustLevelByEntropy корректирует уровень опасности на основе энтропии и контекста
func AdjustLevelByEntropy(originalLevel Level, match string, context string) (Level, float64) {
	// Вычисляем энтропию
	entropy := ShannonEntropy(match)
	adjustedLevel := originalLevel
	confidence := 1.0
	switch {
	case entropy > 4.5:
		// Очень высокая энтропия - похоже на настоящий секрет
		confidence *= 1.2

	case entropy > 3.5:
		// Средняя энтропия
		confidence *= 1.0
		if adjustedLevel == LevelHigh {
			adjustedLevel = LevelMedium
		}

	case entropy > 2.5:
		// Низкая энтропия
		confidence *= 0.7
		if adjustedLevel == LevelHigh {
			adjustedLevel = LevelMedium
		} else if adjustedLevel == LevelMedium {
			adjustedLevel = LevelLow
		}

	default:
		confidence *= 0.3
		adjustedLevel = LevelNoThreat
	}

	// 2. Проверка на тестовые индикаторы в контексте
	testIndicators := []string{
		"test", "example", "sample", "demo", "dummy",
		"your_", "xxx", "***", "____", "placeholder",
		"change_me", "replace_me", "fixme", "todo",
		"localhost", "127.0.0.1", "0.0.0.0",
	}

	lowerContext := strings.ToLower(context)
	for _, ind := range testIndicators {
		if strings.Contains(lowerContext, ind) {
			confidence *= 0.5
			// Понижаем уровень на одну ступень
			switch adjustedLevel {
			case LevelHigh:
				adjustedLevel = LevelMedium
			case LevelMedium:
				adjustedLevel = LevelLow
			case LevelLow:
				adjustedLevel = LevelNoThreat
			}
			break
		}
	}

	// 3. Проверка на официальные примеры
	knownExamples := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"sk_test_", "pk_test_",
		"YOUR_API_KEY", "CHANGEME",
	}

	for _, ex := range knownExamples {
		if strings.Contains(match, ex) {
			confidence *= 0.3
			adjustedLevel = LevelNoThreat
			break
		}
	}

	// 4. Проверка на длину строки
	if len(match) < 8 {
		confidence *= 0.3
		if adjustedLevel != LevelNoThreat {
			adjustedLevel = LevelLow
		}
	}

	// Ограничиваем confidence от 0 до 1
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.1 {
		confidence = 0.1
	}

	return adjustedLevel, confidence
}

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

// findLine находит номер строки и её содержимое по позиции
func findLine(content []byte, matchPos int) (int, string) {
	lines := bytes.Split(content, []byte{'\n'})
	pos := 0

	for i, line := range lines {
		if matchPos >= pos && matchPos <= pos+len(line) {
			return i + 1, string(line)
		}
		pos += len(line) + 1
	}
	return 1, ""
}

// isBinary проверяет, является ли файл бинарным по расширению
func isBinary(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".pdf": true, ".zip": true, ".tar": true,
		".gz": true, ".exe": true, ".dll": true, ".so": true,
		".pyc": true, ".class": true,
	}
	return binaryExts[ext]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
