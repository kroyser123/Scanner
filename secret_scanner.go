// secret_scanner.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"secret_scanner/internal/scanner"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		runWithFlags()
	} else {
		runInteractive()
	}
}

// runWithFlags — режим работы с флагами командной строки
func runWithFlags() {
	// Парсинг аргументов
	target := flag.String("target", ".", "Путь для сканирования")
	exclude := flag.String("exclude", ".git,node_modules,vendor", "Исключенные папки (через запятую)")
	level := flag.String("level", "all", "Фильтр по уровню: HIGH, MEDIUM, LOW, all")
	jsonOutput := flag.String("json", "", "Имя JSON файла для сохранения")
	output := flag.String("output", "", "Путь к файлу отчёта (например, txt/report.txt)")
	flag.Parse()

	startTime := time.Now()
	fmt.Println("Initializing scanner engine...")

	s, err := scanner.NewScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}

	// Формируем список исключённых папок
	excludeDirs := parseExcludeList(*exclude)

	// Запускаем сканирование
	findings := s.ScanDirectory(*target, excludeDirs)

	// Фильтрация по уровню опасности
	var filtered []*scanner.FindingResult
	for _, f := range findings {
		if *level == "all" || string(f.Level) == *level {
			filtered = append(filtered, f)
		}
	}

	// Определяем путь для сохранения отчёта
	outputPath := determineOutputPath(*output)
	if *jsonOutput != "" {
		err := scanner.SaveToJSON(filtered, *jsonOutput)
		if err != nil {
			fmt.Printf("Ошибка сохранения JSON: %v\n", err)
		}
	}
	printResults(findings, filtered, startTime, outputPath)
}

// runInteractive — интерактивный режим работы
func runInteractive() {
	reader := bufio.NewReader(os.Stdin)

	// Запрашиваем директорию для сканирования
	targetDir := promptForDirectory(reader)

	// Спрашиваем, сохранять ли результаты
	outputPath := promptForSave(reader)

	// Подтверждение запуска
	if !promptForConfirmation(reader) {
		fmt.Println("Scanning cancelled by user.")
		os.Exit(0)
	}

	fmt.Println("\nInitializing scanner engine...")

	s, err := scanner.NewScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()

	// Исключаем стандартные папки + папку с отчётами
	excludeDirs := []string{".git", "node_modules", "vendor", "txt"}
	findings := s.ScanDirectory(targetDir, excludeDirs)
	fmt.Print("\nSave results to JSON? (yes/no): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer == "yes" || answer == "y" || answer == "да" || answer == "д" {
		fmt.Print("Enter filename (default: scan_result.json): ")
		filename, _ := reader.ReadString('\n')
		filename = strings.TrimSpace(filename)
		if filename == "" {
			filename = "scan_result.json"
		}
		if !strings.HasSuffix(strings.ToLower(filename), ".json") {
			filename += ".json"
		}
		err := scanner.SaveToJSON(findings, filename)
		if err != nil {
			fmt.Printf("Ошибка сохранения JSON: %v\n", err)
		}
	}

	printResults(findings, findings, startTime, outputPath)
}

// parseExcludeList разбирает строку исключений в слайс
func parseExcludeList(exclude string) []string {
	parts := strings.Split(exclude, ",")
	result := make([]string, 0, len(parts)+1)

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}

	// Всегда исключаем папку с отчётами
	result = appendIfMissing(result, "txt")

	return result
}

// appendIfMissing добавляет элемент в слайс, если его там ещё нет
func appendIfMissing(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// determineOutputPath определяет путь для файла отчёта
func determineOutputPath(output string) string {
	if output != "" {
		return output
	}
	// Генерируем имя файла с датой и временем
	return fmt.Sprintf("txt/scan_%s.txt", time.Now().Format("20060102_150405"))
}

// promptForDirectory запрашивает у пользователя путь для сканирования
func promptForDirectory(reader *bufio.Reader) string {
	for {
		fmt.Print("Enter directory to scan: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Invalid input. Please try again.")
			continue
		}

		targetDir := strings.TrimSpace(strings.Trim(input, `"'`))

		if targetDir == "" {
			fmt.Println("Path cannot be empty")
			continue
		}

		info, err := os.Stat(targetDir)
		if err != nil {
			fmt.Printf("Directory not found: %s\n", targetDir)
			continue
		}

		if !info.IsDir() {
			fmt.Printf("Not a directory: %s\n", targetDir)
			continue
		}

		return targetDir
	}
}

// promptForSave спрашивает, сохранять ли результаты в файл
func promptForSave(reader *bufio.Reader) string {
	fmt.Print("\nSave results to file? (yes/no): ")
	input, _ := reader.ReadString('\n')
	saveResults := strings.ToLower(strings.TrimSpace(input))

	if saveResults == "yes" || saveResults == "y" || saveResults == "да" || saveResults == "д" {
		return fmt.Sprintf("txt/scan_%s.txt", time.Now().Format("20060102_150405"))
	}
	return ""
}

// promptForConfirmation запрашивает подтверждение запуска сканирования
func promptForConfirmation(reader *bufio.Reader) bool {
	for {
		fmt.Print("Ready to scan? (yes/no): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		confirm := strings.ToLower(strings.TrimSpace(strings.Trim(input, `"'`)))

		switch confirm {
		case "yes", "y", "да", "д":
			return true
		case "no", "n", "нет", "н":
			return false
		default:
			fmt.Printf("Command not recognized: '%s'. Please enter 'yes' or 'no'.\n", confirm)
		}
	}
}

// printResults выводит результаты в консоль и сохраняет в файл
func printResults(allFindings, filtered []*scanner.FindingResult, startTime time.Time, outputPath string) {
	// Вывод найденных проблем
	if len(filtered) == 0 {
		fmt.Println("\nNo secrets found.")
	} else {
		fmt.Printf("\nFound %d issues:\n\n", len(filtered))
		for _, f := range filtered {
			fmt.Print(f.String())
			fmt.Println()
		}
	}

	// Сохранение в файл, если указан путь
	if outputPath != "" {
		fmt.Printf("\nSaving results to: %s ... ", outputPath)
		err := scanner.SaveResultsToTXT(allFindings, outputPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Println("Done.")
		}
	}

	// Статистика по уровням
	stats := make(map[scanner.Level]int)
	for _, f := range allFindings {
		stats[f.Level]++
	}

	fmt.Println("\nSTATISTICS BY LEVEL:")
	fmt.Printf("    %s: %d\n", scanner.LevelHigh, stats[scanner.LevelHigh])
	fmt.Printf("    %s: %d\n", scanner.LevelMedium, stats[scanner.LevelMedium])
	fmt.Printf("    %s: %d\n", scanner.LevelLow, stats[scanner.LevelLow])
	fmt.Printf("    %s: %d\n", scanner.LevelNoThreat, stats[scanner.LevelNoThreat])
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Duration: %v\n", time.Since(startTime))

	// Ожидание нажатия Enter перед выходом
	waitForExit()

	// Код выхода для CI/CD: 1 если найдены критические уязвимости
	if stats[scanner.LevelHigh] > 0 {
		os.Exit(1)
	}
}

// waitForExit ожидает нажатия Enter перед завершением программы
func waitForExit() {
	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
