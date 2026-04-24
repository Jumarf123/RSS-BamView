# RSS-BamView / Update 22.04.2026

<p align="center">
  <a href="#ru"><img alt="Русский" src="https://img.shields.io/badge/Русский-Read-1f6feb?style=for-the-badge" /></a>
  <a href="#en"><img alt="English" src="https://img.shields.io/badge/English-Read-1f6feb?style=for-the-badge" /></a>
</p>

<p align="center">
  <a href="https://github.com/Jumarf123/RSS-BamView/releases/download/1.0/RSS-BamView.exe">
    <img alt="Download RSS-BamView" src="https://img.shields.io/badge/Скачать%20%2F%20Download-RSS--BamView.exe-2ea043?style=for-the-badge&logo=github&logoColor=white" />
  </a>
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-2ea043?style=flat-square" />
  <img alt="GUI" src="https://img.shields.io/badge/Type-GUI%20Utility-0969da?style=flat-square" />
  <img alt="BAM" src="https://img.shields.io/badge/Source-BAM%20%2F%20DAM-8250df?style=flat-square" />
  <img alt="YARA-X" src="https://img.shields.io/badge/Scanner-YARA--X-b7410e?style=flat-square" />
  <img alt="Languages" src="https://img.shields.io/badge/UI-RU%20%2B%20EN-5865F2?style=flat-square" />
</p>

<p align="center">
  Утилита с графическим интерфейсом для просмотра <b>BAM/DAM</b> записей Windows и проверки связанных файлов через <b>YARA-X</b>.
</p>

---

## Navigation

* [Русский](#ru)
* [English](#en)

---

<a name="ru"></a>

## Русский

### Что это

`RSS-BamView` — это GUI-утилита для анализа записей BAM/DAM в Windows 10/11 и проверки найденных файлов по YARA-X правилам.

Программа показывает записи в удобной таблице, нормализует пути вида `\Device\HarddiskVolume...` в обычные пути дисков, проверяет цифровую подпись файлов, отображает удалённые записи и помогает искать следы выключения, включения или изменения BAM/DAM.

---

### Возможности

* Просмотр BAM/DAM записей в таблице
* Нормальное отображение Unicode-путей
* Преобразование NT device paths в пути дисков:

  * `C:\...`
  * `D:\...`
  * `E:\...`
  * и другие доступные диски
* Проверка файлов через YARA-X
* Проверка цифровой подписи файла
* Фильтры:

  * Not Signed only
  * YARA only
  * Deleted only
* Поиск по имени файла, пути, YARA, SID и статусам
* Окно `INFO` с информацией о BAM/DAM:

  * состояние служб
  * ключи реестра
  * события Service Control Manager
  * Security audit
  * Sysmon
  * PowerShell logging
  * следы очистки журналов
* Масштабирование интерфейса через `Ctrl +`, `Ctrl -`, `Ctrl + Mouse Wheel`

---

### Быстрый старт

Запустите файл:

```powershell
.\RSS-BamView.exe
```

или просто откройте:

```text
RSS-BamView.exe
```

Приложение запрашивает права администратора автоматически.

---

### Требования

* Windows 10 / 11
* Права администратора

---

### Скачать

* **Download:**
  [https://github.com/Jumarf123/RSS-BamView/releases/download/1.0/RSS-BamView.exe](https://github.com/Jumarf123/RSS-BamView/releases/download/1.0/RSS-BamView.exe)

---

### Discord

https://discord.gg/residencescreenshare

---

<a name="en"></a>

## English

### What it is

`RSS-BamView` is a GUI utility for inspecting Windows 10/11 BAM/DAM records and scanning related files with YARA-X rules.

The tool displays records in a convenient table, normalizes paths such as `\Device\HarddiskVolume...` into regular drive paths, checks file signatures, marks deleted files, and helps investigate BAM/DAM disable, enable, restart, and registry-change traces.

---

### Features

* BAM/DAM records table
* Correct Unicode path display
* NT device path conversion to drive paths:

  * `C:\...`
  * `D:\...`
  * `E:\...`
  * and other available drives
* File scanning with YARA-X
* YARA rule names shown on detection
* Digital signature status
* Filters:

  * Not Signed only
  * YARA only
  * Deleted only
* Search by file name, path, YARA, SID, and status
* `INFO` window with BAM/DAM details:

  * service state
  * registry roots
  * Service Control Manager events
  * Security audit
  * Sysmon
  * PowerShell logging
  * event log clearing traces
* UI zoom via `Ctrl +`, `Ctrl -`, `Ctrl + Mouse Wheel`
---

### Quick start

Run:

```powershell
.\RSS-BamView.exe
```

or simply open:

```text
RSS-BamView.exe
```

The application requests administrator privileges automatically.

---

### Requirements

* Windows 10 / 11
* Administrator privileges

---

### Download

* **Download:**
  [https://github.com/Jumarf123/RSS-BamView/releases/download/1.0/RSS-BamView.exe](https://github.com/Jumarf123/RSS-BamView/releases/download/1.0/RSS-BamView.exe)

---

### Discord

https://discord.gg/residencescreenshare
