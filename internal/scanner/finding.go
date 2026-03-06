package scanner

import (
	"fmt"
)

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
	levelColor := map[Level]string{
		LevelHigh:     "🔴",
		LevelMedium:   "🟡",
		LevelLow:      "🟢",
		LevelNoThreat: "⚪️",
	}

	return fmt.Sprintf("%s [%s] %s\n",
		levelColor[f.Level],
		f.Level,
		f.PatternName,
	) + fmt.Sprintf("   Файл: %s:%d\n", f.FilePath, f.Line) +
		fmt.Sprintf("   Найдено: %q\n", f.Match) +
		fmt.Sprintf("   Контекст: %s\n", f.Context)
}
