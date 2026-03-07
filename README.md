# Secret Scanner

Инструмент для поиска секретов и конфиденциальной информации в коде.

## Возможности

- Быстрый поиск с использованием алгоритма Ахо-Корасик
- Точная проверка через регулярные выражения
- Фильтрация ложных срабатываний через энтропию
- Цветной вывод с уровнями опасности
- Два режима работы: CLI и интерактивный
- **Экспорт результатов в два формата:**
  - `reports/` — JSON для разработчиков и интеграций
  - `txt/` — читаемый текстовый формат с результатами

## Установка

```bash
git clone https://github.com/yourusername/secret-scanner.git
cd secret-scanner
Использование
Режим командной строки
bash
# Сканировать конкретную папку
go run main.go -target ./project

# Только HIGH уровень
go run main.go -target . -level HIGH

# Исключить папки
go run main.go -target . -exclude ".git,node_modules,vendor"

# Сохранить результат в JSON
go run main.go -target . -json result.json

# Все параметры вместе
go run main.go -target ./project -level HIGH -json report.json
Интерактивный режим
bash
go run main.go
Программа последовательно запросит:

Путь для сканирования

Сохранение в JSON (опционально)

Имя файла для сохранения

Подтверждение запуска

Результаты сохраняются автоматически:

📁 reports/ — JSON файлы для разработчиков

📁 txt/ — текстовые отчёты с результатами

Уровни опасности
Уровень	Описание
HIGH	Критические секреты (доступ к деньгам/серверам)
MEDIUM	API ключи, вебхуки
LOW	Тестовые данные, локальные ключи
NO_THREAT	Публичные ключи, примеры
Пример работы
bash
$ go run main.go -target ./test-project

Found 3 issues:

HIGH [AWS Access Key]
   Файл: .env:15
   Найдено: "AKIAIOSFODNN7EXAMPLE"
   Контекст: aws_access_key_id=AKIAIOSFODNN7EXAMPLE

MEDIUM [Google Maps Key]
   Файл: config.js:23
   Найдено: "AIzaSyDf09dEeR9cK7l7o0X8v9yW0q1r2s3t4u5v6"
   Контекст: ?key=AIzaSyDf09dEeR9cK7l7o0X8v9yW0q1r2s3t4u5v6

LOW [Stripe Test Key]
   Файл: tests/test.js:42
   Найдено: "какой то ключ гит не пропускает пушить с ним"
   Контекст: stripe_key = "какой то ключ гит не пропускает пушить с ним"

STATISTICS BY LEVEL:
    HIGH: 1
    MEDIUM: 1
    LOW: 1
    NO_THREAT: 0
────────────────────────────────────────
Duration: 25.5ms

📄 JSON отчёт сохранён: reports/scan_result.json
📄 Текстовый отчёт сохранён: txt/scan_20240307_150405.txt
Форматы вывода
JSON (для разработчиков)
json
{
  "timestamp": "2024-03-07 15:04:05",
  "total_issues": 2,
  "findings": [
    {
      "level": "HIGH",
      "line": 15,
      "file_path": ".env",
      "pattern_name": "AWS Access Key",
      "match": "AKIAIOSFODNN7EXAMPLE",
      "context": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
    }
  ]
}
TXT (читаемый формат)
================================================================
SECRET SCANNER REPORT — 2026-03-07 21:30:46
================================================================

Summary: 51 potential leaks found
   HIGH: 0
   MEDIUM: 0
   LOW: 15

----------------------------------------------------------------

[1] [NO_THREAT] AWS Access Key ID
    File: README.md:61
    Match: "AKIAIOSFODNN7EXAMPLE"
    Context:    Найдено: "AKIAIOSFODNN7EXAMPLE"
    ----------------------------------------------------------------

[2] [NO_THREAT] Stripe Test Key
    File: README.md:71
    Match: "какой то ключ гит не пропускает пушить с ним"
    Context:    Найдено: "какой то ключ гит не пропускает пушить с ним"
    ----------------------------------------------------------------

Как это работает
Ахо-Корасик — находит все ключевые слова за один проход по файлу

Regexp — проверяет точный формат найденных потенциальных секретов

Энтропия — отсеивает тестовые данные и примеры

Экспорт — результаты сохраняются в двух форматах:

reports/ — JSON для дальнейшей обработки

txt/ — читаемые отчёты для просмотра

Структура проекта
text
secret-scanner/
├── main.go                    # точка входа
├── internal/
│   └── scanner/
│       ├── finding.go        # структура результата
│       ├── pattern.go        # шаблоны секретов
│       ├── patterns_high.go   # HIGH паттерны
│       ├── patterns_medium.go # MEDIUM паттерны
│       ├── patterns_low.go    # LOW паттерны
│       └── scanner.go         # ядро с Ахо-Корасик
├── reports/                   # JSON отчёты для разработчиков
└── txt/                       # Текстовые отчёты
