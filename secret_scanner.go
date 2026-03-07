package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"Scanner/internal/scanner" // ✅ Проверьте, что имя модуля совпадает с go.mod
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// 1. Запрос пути
	var targetDir string
	for {
		fmt.Print("Enter directory: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			// Обработка ошибки чтения (например, закрытие потока)
			os.Exit(1)
		}
		targetDir = strings.TrimSpace(strings.Trim(input, `"'`))

		// Проверка 1: Пустой ввод
		if targetDir == "" {
			fmt.Println("❌ Path cannot be empty")
			continue // ↺ Повторяем запрос
		}

		// Проверка 2: Существует ли путь
		info, err := os.Stat(targetDir)
		if err != nil {
			fmt.Println("❌ Directory not found:", targetDir)
			continue // ↺ Повторяем запрос
		}

		// Проверка 3: Является ли путь директорией
		if !info.IsDir() {
			fmt.Println("❌ Not a directory:", targetDir)
			continue // ↺ Повторяем запрос
		}

		// ✅ Все проверки пройдены
		break // → Выход из цикла
	}

	// 2. Запрос подтверждения
	fmt.Print("Ready to scan? (Yes/No): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))

	// Если пользователь не подтвердил — выходим
	if confirm != "yes" && confirm != "y" {
		os.Exit(0)
	}

	// 3. ОТПРАВКА ДАННЫХ В СКАНЕР
	// Передаем ровно два значения, как вы и хотели:
	// 1. true  -> сигнал "можешь начинать работу"
	// 2. targetDir -> путь, который нужно проверить
	// Функция вернет true, если нашла уязвимости, и false, если чисто.

	// Примечание: Для этого в scanner.go должна быть функция Run(true, path)
	found := scanner.Run(true, targetDir)

	// 4. Тихий выход на основе результата
	// 1 = уязвимости найдены, 0 = чисто
	if found {
		os.Exit(1)
	}
	os.Exit(0)
}
