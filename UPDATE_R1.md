# Обновление R1 и переоформление отчёта

Версия 0.1.0rc2, 14.10.2026. Работает из консоли Ubuntu/WSL. Python >=3.11; автоматические тесты выполнены на Python 3.12.14. Пользователь подтвердил один запуск rc1 на 3.14.4; полная совместимость 3.14 не заявляется.

## 1 Распаковка в Windows

Сохраните pdscan-0.1.0rc2.zip в C:\pdscan-r1. Откройте PowerShell:

```powershell
Expand-Archive -LiteralPath 'C:\pdscan-r1\pdscan-0.1.0rc2.zip' -DestinationPath 'C:\pdscan-r1\update-rc2'
```

## 2 Установка в Ubuntu WSL

```bash
mkdir -p ~/projects
cp -r /mnt/c/pdscan-r1/update-rc2/pdscan-0.1.0rc2 ~/projects/
cd ~/projects/pdscan-0.1.0rc2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index dist/pdscan-0.1.0rc2-py3-none-any.whl
pdscan --version
pdscan doctor
```

Ожидаемая версия — 0.1.0rc2. Старое окружение и отчёты остаются в прежней папке. Если установка не завершилась успешно, следующие шаги не выполняйте.

## 3 Переоформление уже полученного отчёта

Сеть не используется. Исходный report.json и прежний report.html не меняются.

```bash
old_report="$HOME/projects/pdscan-0.1.0rc1/reports/ifors-20261014-130817"
pdscan render "$old_report/report.json" --output "$old_report/report-readable.html"
explorer.exe "$(wslpath -w "$old_report")"
```

Откройте report-readable.html. При повторном переоформлении выберите другое имя или явно добавьте --overwrite к команде render. Старые результаты, цвет и статус partial сохраняются. Если контекст не был записан в rc1, обновление честно укажет, что уточнить причину невозможно.

## 4 Новый запуск при необходимости

```bash
report_dir="$PWD/reports/ifors-$(date +%Y%m%d-%H%M%S)"
pdscan scan https://i.fors.ru/ --output "$report_dir"
scan_code=$?
printf 'Код завершения: %s\n' "$scan_code"
explorer.exe "$(wslpath -w "$report_dir")"
```

0 — без технических замечаний; 1 — с замечаниями; 2 — ошибка; 3 — неполная проверка; 130 — отмена. Откройте report.html.

## 5 Чтение отчёта

Сначала смотрите итог и причины неполноты, затем замечания и отдельные проверки. Код правила ведёт к справочнику ниже. Найденные элементы сгруппированы в таблицы. Зелёный цвет не является подтверждением соответствия законодательству.

В rc2 доработано представление отчёта. Правовые блоки из спецификации 1.2 ещё не реализованы. Анализ содержания документов и сверка с РКН остаются в будущих релизах.
