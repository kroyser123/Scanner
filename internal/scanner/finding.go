// finding.go
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// ОСНОВНЫЕ ТИПЫ И КОНСТАНТЫ
// ============================================================================

type Level string

const (
	LevelHigh     Level = "HIGH"
	LevelMedium   Level = "MEDIUM"
	LevelLow      Level = "LOW"
	LevelNoThreat Level = "NO_THREAT"
)

type FindingResult struct {
	Level       Level  `json:"level"`
	Line        int    `json:"line"`
	FilePath    string `json:"file_path"`
	PatternName string `json:"pattern_name"`
	Match       string `json:"match"`
	Context     string `json:"context"`
}

func (f *FindingResult) String() string {
	levelMarker := map[Level]string{
		LevelHigh:     "[HIGH]",
		LevelMedium:   "[MEDIUM]",
		LevelLow:      "[LOW]",
		LevelNoThreat: "[NO_THREAT]",
	}

	result := fmt.Sprintf("%s %s\n", levelMarker[f.Level], f.PatternName)
	result += fmt.Sprintf("   File: %s:%d\n", f.FilePath, f.Line)
	result += fmt.Sprintf("   Match: %q\n", f.Match)
	result += fmt.Sprintf("   Context: %s\n", f.Context)
	return result
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ЭКСПОРТА
// ============================================================================

// getLevelMarker возвращает текстовый маркер для уровня
func getLevelMarker(level Level) string {
	switch level {
	case LevelHigh:
		return "[HIGH]"
	case LevelMedium:
		return "[MEDIUM]"
	case LevelLow:
		return "[LOW]"
	default:
		return "[NO_THREAT]"
	}
}

// SaveResultsToTXT сохраняет массив находок в текстовый файл
//
// Параметры:
//   - findings: слайс с результатами сканирования
//   - outputPath: путь к файлу (например, "txt/report.txt")
//
// Возвращает:
//   - error: nil если успешно, иначе ошибка
func SaveResultsToTXT(findings []*FindingResult, outputPath string) error {
	// Создаём папку, если её нет
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Создаём файл для записи
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", outputPath, err)
	}
	defer file.Close()

	// Заголовок отчёта
	_, err = fmt.Fprintln(file, "================================================================")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "SECRET SCANNER REPORT — %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "================================================================")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "")
	if err != nil {
		return err
	}

	// Если ничего не найдено
	if len(findings) == 0 {
		_, err = fmt.Fprintln(file, "No secrets detected. Clean.")
		return err
	}

	// Статистика по уровням
	byLevel := make(map[Level]int)
	for _, f := range findings {
		byLevel[f.Level]++
	}

	_, err = fmt.Fprintf(file, "Summary: %d potential leaks found\n", len(findings))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "   HIGH: %d\n", byLevel[LevelHigh])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "   MEDIUM: %d\n", byLevel[LevelMedium])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(file, "   LOW: %d\n", byLevel[LevelLow])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "----------------------------------------------------------------")
	if err != nil {
		return err
	}

	// Каждая находка
	for i, f := range findings {
		_, err = fmt.Fprintf(file, "\n[%d] %s %s\n", i+1, getLevelMarker(f.Level), f.PatternName)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(file, "    File: %s:%d\n", f.FilePath, f.Line)
		if err != nil {
			return err
		}
		// Экранируем кавычки в найденном значении
		escapedMatch := strings.ReplaceAll(f.Match, `"`, `'`)
		_, err = fmt.Fprintf(file, "    Match: \"%s\"\n", escapedMatch)
		if err != nil {
			return err
		}
		// Очищаем контекст от переносов строк
		cleanContext := strings.ReplaceAll(f.Context, "\n", " ")
		cleanContext = strings.ReplaceAll(cleanContext, "\r", "")
		_, err = fmt.Fprintf(file, "    Context: %s\n", cleanContext)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(file, "    ----------------------------------------------------------------")
		if err != nil {
			return err
		}
	}

	// Футер отчёта
	_, err = fmt.Fprintln(file, "")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "================================================================")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, "End of report")
	if err != nil {
		return err
	}

	return nil
}

// SaveResultsToTXTWithStats — расширенная версия с временем выполнения
func SaveResultsToTXTWithStats(findings []*FindingResult, outputPath string, scanDuration time.Duration) error {
	// Сохраняем базовый отчёт
	if err := SaveResultsToTXT(findings, outputPath); err != nil {
		return err
	}

	// Открываем файл в режиме добавления
	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Дописываем время выполнения
	_, err = fmt.Fprintf(file, "\nScan duration: %v\n", scanDuration)
	return err
}

func SaveToJSON(findings []*FindingResult, filename string) error {
	type JSONOutput struct {
		Timestamp   string           `json:"timestamp"`
		TotalIssues int              `json:"total_issues"`
		Findings    []*FindingResult `json:"findings"`
	}

	// Создаём вывод
	output := JSONOutput{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		TotalIssues: len(findings),
		Findings:    findings,
	}
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("ошибка создания JSON: %v", err)
	}
	err = os.MkdirAll("reports", 0755)
	if err != nil {
		return fmt.Errorf("ошибка создания папки reports: %v", err)
	}

	filePath := fmt.Sprintf("reports/%s", filename)

	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("ошибка записи файла: %v", err)
	}

	fmt.Printf(" JSON отчёт сохранён: %s\n", filePath)
	return nil
}
