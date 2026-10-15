# Обновление до исправленного R2 0.2.0rc2

Старую папку rc1 и отчёты сохраните. Новая версия устанавливается рядом, в отдельное окружение.

1. Сохраните ZIP в Downloads Windows. Выполните в PowerShell:

```powershell
Expand-Archive -LiteralPath 'C:\Users\user\Downloads\pdscan-0.2.0rc2.zip' -DestinationPath 'C:\pdscan-r2-rc2'
wsl
```

2. В Ubuntu/WSL деактивируйте старое окружение командой `deactivate`, если оно активно. Затем:

```bash
mkdir -p ~/projects
cp -r /mnt/c/pdscan-r2-rc2/pdscan-0.2.0rc2 ~/projects/
cd ~/projects/pdscan-0.2.0rc2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index dist/pdscan-0.2.0rc2-py3-none-any.whl
python -m pip install "playwright==1.64.0"
pdscan --version
pdscan doctor --browser
```

Ожидаемая версия — `0.2.0rc2`. Chromium от rc1 может сохраниться в общем кэше пользователя WSL. Если диагностика показывает отсутствие браузера/системных библиотек:

```bash
python -m playwright install --with-deps chromium
pdscan doctor --browser
```

3. После успешного запуска браузера в диагностике выполните проверку:

```bash
report_r2="$PWD/reports/ifors-r2-rc2-$(date +%Y%m%d-%H%M%S)"
pdscan scan https://i.fors.ru/ --mode combined --browser-pages 1 --browser-time-limit 300 --browser-max-requests 300 --browser-total-mib 100 --browser-attempt-mib 25 --browser-response-mib 8 --output "$report_r2" --stdout path
scan_code=$?
printf 'Код завершения: %s\n' "$scan_code"
explorer.exe "$(wslpath -w "$report_r2")"
```

В `report.html` проверьте новые столбцы причин и невыполненных действий, диагностику элементов, нормативную таблицу. Отдельный отчёт R1 находится в подпапке `r1`.

Код 3 остаётся возможным при неподдержанном интерфейсе, неизвестном MIME и других ограничениях. Исправление не должно искусственно превращать их в зелёный результат. Сохраните новый архив отчёта для разбора. Подробное объяснение синтаксиса всех команд — в README.md. Повторно создавать окружение при каждом запуске не нужно: достаточно `cd` и `source .venv/bin/activate`.
