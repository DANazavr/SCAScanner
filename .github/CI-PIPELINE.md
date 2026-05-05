# CI/CD Pipeline Documentation

## GitHub Actions Workflows

### 1. **scan-vulnerabilities.yml** - Основной workflow сканирования

Этот workflow автоматически запускается при каждом:

- **Push** в ветки `main` или `develop`
- **Pull Request** в ветки `main` или `develop`

#### Что он делает:

1. **Checkout code** - Загружает исходный код
2. **Set up Go** - Устанавливает Go 1.24.0
3. **Build SCAScanner** - Собирает бинарник программы
4. **Run vulnerability scan** - Запускает полное сканирование:
   - Сканирует зависимости проекта
   - Ищет уязвимости (CVE)
   - Генерирует JSON отчет
   - Генерирует HTML отчет
5. **Upload scan reports** - Загружает отчеты как артефакты (хранятся 30 дней)
6. **Check for critical vulnerabilities** - Проверяет наличие критических уязвимостей:
   - ❌ Если найдены CRITICAL - workflow падает
   - ⚠️ Если найдены HIGH - выводит предупреждение
   - ✅ Если всё хорошо - успех
7. **Comment PR** - Автоматически комментирует PR с результатами сканирования

#### Где найти отчеты:

- Перейдите на вкладку **Actions** в репозитории
- Выберите последний запуск workflow
- Скачайте артефакт `vulnerability-reports`
- Откройте `report.html` в браузере или посмотрите `report.json`

---

### 2. **analyze-results.yml** - Детальный анализ

Дополнительный workflow для анализа результатов сканирования при обнаружении проблем.

---

## Как работает статус Merge

| Результат сканирования    | Статус PR  | Действие        |
| ------------------------- | ---------- | --------------- |
| ✅ Нет уязвимостей        | ✅ Pass    | Можно мердить   |
| ⚠️ HIGH/MEDIUM уязвимости | ⚠️ Warning | Нужен review    |
| ❌ CRITICAL уязвимости    | ❌ Fail    | Запретить merge |

---

## Запуск локально

Если нужно протестировать сканирование локально:

```bash
# Собрать программу
go build -v -o scascanner ./cmd/scascanner/main.go

# Запустить сканирование текущего проекта
./scascanner -p . -o ./reports -f json

# Или с HTML отчетом
./scascanner -p . -o ./reports -f html
```

---

## Настройка для других языков

В workflow можно изменить команду сканирования, чтобы сканировать только нужные языки:

```bash
# Только Go зависимости
./scascanner -p . -o scan-reports -l go -f json

# Только Python
./scascanner -p . -o scan-reports -l python -f json

# Только Node.js
./scascanner -p . -o scan-reports -l node -f json

# Все языки (по умолчанию)
./scascanner -p . -o scan-reports -l all -f json
```

Отредактируйте `.github/workflows/scan-vulnerabilities.yml` строку с `Run vulnerability scan`.

---

## Окружение при запуске в CI

Если используется Redis для кэширования CVE:

1. Добавьте в GitHub Secrets переменную окружения
2. Или отключите Redis в конфигурации проекта

Текущая конфигурация работает без Redis (локальный кэш).

---

## Решение проблем

### Workflow не запускается

- Убедитесь, что файлы находятся в `.github/workflows/`
- Проверьте синтаксис YAML (используйте https://www.yamllint.com/)

### Ошибка "go: command not found"

- Проверьте версию Go в `go.mod` (текущая: 1.24.0)

### Отчеты не загружаются

- Проверьте, что путь `scan-reports/` правильный
- Убедитесь, что программа генерирует отчеты
