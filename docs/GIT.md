# Git-репозиторий

Основной репозиторий: https://github.com/DGabdrakhimov/ScanerPDn
Ветка разработки: `main`. Текущая версия пакета: `0.1.0rc1`.

```bash
git clone https://github.com/DGabdrakhimov/ScanerPDn.git
cd ScanerPDn
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Установка из исходников требует получения инструментов сборки из pyproject.toml. Для автономной установки используйте wheel из ранее предоставленного ZIP.

Исходная локальная история выпуска и локальный тег v0.1.0rc1 сохранены в Git bundle внутри ZIP. Публикация через GitHub API создаёт отдельные коммиты с тем же кодом; локальные SHA из архива не являются SHA удалённого репозитория. Удалённый тег этой публикацией не создаётся.

Wheel и ZIP не коммитятся. В репозитории находятся исходники, тесты, документация, Dockerfile и синтетический демонстрационный отчёт. Перед Docker build сначала соберите wheel в dist согласно README.
