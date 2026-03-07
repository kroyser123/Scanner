package main

import (
	"Scanner/internal/scanner"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CLI struct {
	TargetDir  string
	RunScan    bool
	Verbose    bool
	Extensions string
	OutputFile string
}

// parseFlags регистрирует и разбирает флаги командной строки

func parseFlags() (*CLI, error) {
	targetDir := flag.String("dir", "", "Путь к директории для сканирования (обязательно)")
	runScan := flag.Bool("scan", false, "Запустить сканирование (установите true для начала работы)")
	verbose := flag.Bool("v", false, "Подробный вывод (режим отладки)")
	extensions := flag.String("ext", "go,py,js,ts,yaml,yml,env,conf", "Фильтр расширений через запятую")
	outputFile := flag.String("out", "", "Файл для сохранения отчета")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Сканер уязвимостей (CLI v1.0)\n\n")
		fmt.Fprintf(os.Stderr, "Использование:\n  %s -dir <path> -scan [опции]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Обязательные флаги:\n  -dir string  Путь к директории\n  -scan        Запуск сканирования\n")
		fmt.Fprintf(os.Stderr, "Опции:\n  -v           Подробный лог\n  -ext string  Фильтр расширений\n  -out string  Вывод в файл\n")
	}

	flag.Parse()

	if *targetDir == "" {
		return nil, fmt.Errorf("флаг -dir является обязательным")
	}

	// Валидация пути
	if _, err := os.Stat(*targetDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("директория не найдена: %s", *targetDir)
	}

	return &CLI{
		TargetDir:  filepath.Clean(*targetDir),
		RunScan:    *runScan,
		Verbose:    *verbose,
		Extensions: *extensions,
		OutputFile: *outputFile,
	}, nil

}

func main() {
	// 1. Парсинг CLI
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("❌ Ошибка: %v", err)
	}

	// 2. Проверка флага запуска
	if !cfg.RunScan {
		fmt.Println("⚠️ Сканер не запущен. Добавьте флаг -scan для начала работы.")
		flag.Usage()
		return
	}

	if cfg.Verbose {
		log.Printf("[CLI] Конфигурация: %+v", cfg)
	}

	// 3. Инициализация бизнес-логики (делегирование)
	// Вся логика создания паттернов и Aho-Corasick находится ВНУТРИ scanner.New()
	log.Println("🔧 Инициализация движка анализа...")

	sc, err := scanner.New(cfg.Verbose)
	if err != nil {
		log.Fatalf("❌ Ошибка инициализации сканера: %v", err)
	}
	defer sc.Close() // Освобождение ресурсов, если нужно

	// 4. Сбор списка файлов
	allowedExts := parseExtensions(cfg.Extensions)
	files, err := collectFiles(cfg.TargetDir, allowedExts)
	if err != nil {
		log.Fatalf("❌ Ошибка обхода файловой системы: %v", err)
	}

	if cfg.Verbose {
		log.Printf("[CLI] Найдено файлов: %d", len(files))
	}

	// 5. Выполнение сканирования (делегирование)
	log.Printf("🔍 Сканирование: %s", cfg.TargetDir)
	start := time.Now()

	var allFindings []scanner.FindingResult
	for _, file := range files {
		findings, err := sc.ScanFile(file)
		if err != nil {
			if cfg.Verbose {
				log.Printf("[WARN] Пропуск %s: %v", file, err)
			}
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	elapsed := time.Since(start)
	log.Printf("🏁 Завершено за %s", elapsed.Round(time.Millisecond))

	// 6. Вывод результатов
	printReport(allFindings, cfg.OutputFile, cfg.TargetDir)

	// 7. Exit code для CI/CD
	if len(allFindings) > 0 {
		os.Exit(1)
	}
}

// --- Вспомогательные функции (утилиты, не бизнес-логика) ---

func parseExtensions(input string) map[string]bool {
	if input == "" {
		return nil
	}
	exts := make(map[string]bool)
	for _, e := range strings.Split(input, ",") {
		e = strings.TrimSpace(e)
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		exts[strings.ToLower(e)] = true
	}
	return exts
}

func collectFiles(root string, allowed map[string]bool) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		// Пропуск служебных папок
		if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if allowed == nil || allowed[ext] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func printReport(findings []scanner.FindingResult, outFile, baseDir string) {
	if len(findings) == 0 {
		fmt.Println(" Уязвимости не обнаружены.")
		return
	}

	fmt.Printf("\n🚨 Найдено проблем: %d\n", len(findings))
	fmt.Println(strings.Repeat("=", 80))

	for _, f := range findings {
		relPath, _ := filepath.Rel(baseDir, f.FilePath)
		fmt.Printf("[%s] %s\n   └─ %s:%d\n   └─ %s\n\n",
			f.Level, f.PatternName, relPath, f.Line, f.Match)
	}

	if outFile != "" {
		// TODO: Реализовать запись в файл при необходимости
		log.Printf("📄 Отчет сохранен: %s", outFile)
	}
}
