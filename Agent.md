# IBM Security Bulletin CVE Scraper — IBM HTTP Server Agent 指南

> 此文件定義了 IBM HTTP Server Security Bulletin CVE 爬蟲專案的
> **完整規格、架構、實作模式、IBM HTTP Server 特有格式與注意事項**。

---

## 專案目標

開發一支 Python 程式，使用 **Selenium + ChromeDriver**，自動從 IBM Support 網站爬取
IBM HTTP Server 的 Security Bulletin，篩選高風險 CVE（CVSS ≥ 7.0），
並輸出 **Bootstrap 5 + DataTables** 的 HTML 報表。

---

## 執行方式

```bash
pip install -r requirements.txt
python3 scraper.py                          # 預設：最近 30 天，CVSS >= 7.0
python3 scraper.py --days 90               # 最近 90 天
python3 scraper.py --days 90 --min-cvss 9.0 # 只取 Critical
python3 scraper.py --no-headless --verbose  # 顯示瀏覽器（除錯用，建議首次執行）
python3 scraper.py --output output/my.html  # 自訂輸出路徑
```

輸出報表預設檔名格式：`output/report-YYYY-MM-DD-HHMMss.html`

---

## 篩選條件（AND）

1. Severity 為 **High** 或 **Critical**（來自清單頁）
2. Publish Date 在 **N 天**內（`--days` 參數，預設 30）
3. CVSS Base Score **>= 7.0**（`--min-cvss` 參數，預設 7.0，來自內頁）

---

## 專案結構

```
ihs-high-cve/
├── scraper.py          # 主程式：CLI 參數、主流程、WebDriver 初始化
├── crawler.py          # 清單頁爬蟲：爬取 IBM Security Bulletin 搜尋結果
├── bulletin_parser.py  # 內頁解析：CVSS、版本範圍、Fixpack、Fix List 日期爬取
├── report.py           # HTML 報表生成器
├── models.py           # 資料結構定義（dataclass）
├── requirements.txt    # 依賴套件
└── output/             # 輸出目錄
```

> ⚠️ **命名注意**：內頁解析模組**必須命名為 `bulletin_parser.py`**，不能命名為 `parser.py`。
> `parser` 是 Python 標準函式庫的內建模組，命名衝突會導致 `ModuleNotFoundError`。
> `scraper.py` 中以 `import bulletin_parser as detail_parser` 方式引入。

---

## requirements.txt

```
selenium
beautifulsoup4
lxml
python-dateutil
```

> **注意**：不使用 `webdriver-manager`，改用 Selenium 4.6+ 內建的 selenium-manager
> 自動下載 ChromeDriver。Chrome binary 需自行偵測路徑（見 scraper.py 說明）。

---

## IBM HTTP Server 版本線規則（核心概念）

IBM HTTP Server 版本號格式為 `主.次.修.微`，**主版本號決定版本線**：

| 版本線 | 規則 | 範例 |
|--------|------|------|
| **V9** | 主版本 = 9 | `9.0.5.28`、`9.0.5.29` |
| **V8.5** | 主版本 = 8 | `8.5.5.31`、`8.5.5.32` |

---

## 產品適配說明（欄位對應）

### 1. crawler.py — 搜尋 URL

```python
# IBM HTTP Server（目前設定）
SEARCH_URL = "https://www.ibm.com/support/pages/bulletin/search/?q=IBM%20HTTP%20Server"
```

### 2. bulletin_parser.py — 版本號 Regex

```python
# IBM HTTP Server（主版本號分類）
RE_IHS_VERSION     = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")
RE_IHS_V9_VERSION  = re.compile(r"\b(9\.\d+\.\d+\.\d+)\b")   # 主版本=9
RE_IHS_V85_VERSION = re.compile(r"\b(8\.\d+\.\d+\.\d+)\b")   # 主版本=8
```

### 3. bulletin_parser.py — Bulletin 類型判斷

```python
# 偵測依據：Affected Products 表格與 Remediation 段落中出現的版本號
# v9:   只有 V9 版本（9.x.x.x）
# v85:  只有 V8.5 版本（8.x.x.x）
# both: 同時含有 V9 與 V8.5
```

### 4. bulletin_parser.py — Remediation 解析關鍵字

IBM HTTP Server Bulletin 實際頁面格式（典型）：
```
For IBM HTTP Server V9.0:
  Apply Fix Pack 9.0.5.28 or a later Fix Pack
    or apply Interim Fix PH71670

For IBM HTTP Server V8.5:
  Apply Fix Pack 8.5.5.31 or a later Fix Pack
    or apply Interim Fix PH71671
```

舊格式（保留相容）：
```
IBM HTTP Server version V9.0
IBM HTTP Server version V8.5
```

### 5. bulletin_parser.py — Affected Versions 格式

IBM HTTP Server Bulletin 實際頁面格式：
```
"IBM HTTP Server"                      ← 產品名行
"9.0.0.0 through 9.0.5.27"            ← 範圍格式（使用 "through"）
"IBM HTTP Server"                      ← 下一個產品名
"8.5.5.0 through 8.5.5.30"
```

### 6. bulletin_parser.py — Fix List URL 表

```python
FIX_LIST_URLS = {
    "9.0": "https://www.ibm.com/support/pages/ibm-http-server-fix-list",
    "8.5": "https://www.ibm.com/support/pages/ibm-http-server-fix-list",
}
```

V9（9.x.x.x）和 V8.5（8.x.x.x）共用同一個 Fix List 頁面。

### 7. models.py — 欄位命名（語意對應）

```python
# 欄位沿用 lts/cd 命名，語意對應如下：
ifix_lts / ifix_lts_url           # V9（9.0.x.x）的 iFix
ifix_cd  / ifix_cd_url            # V8.5（8.5.x.x）的 iFix
fixpack_lts / fixpack_date_lts    # V9 的 Fixpack 版本與日期
fixpack_cd  / fixpack_date_cd     # V8.5 的 Fixpack 版本與日期
```

### 8. report.py — 報表標題與欄位標籤

```python
# 頁頭標題
"IBM HTTP Server — High-Risk CVE Report"

# 表格欄 2 標題
"Affected IHS Version"

# iFix 欄前綴
"V9: PHXXXXX"  / "V8.5: PHYYYYY"

# Fixpack 版本標籤
V9 藍色：lts-tag  → "V9: 9.0.5.28"
V8.5 綠色：cd-tag → "V8.5: 8.5.5.31"

# Fixpack 日期標籤
V9 藍色：lts-date-tag   → "V9: 2026/06/24"
V8.5 綠色：cd-date-tag  → "V8.5: 3Q2026"
```

---

## models.py — 資料結構

```python
from dataclasses import dataclass, field
from typing import List


@dataclass
class CveDetail:
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = ""   # Critical >= 9.0, High >= 7.0


@dataclass
class SecurityBulletin:
    # IBM HTTP Server 欄位說明：
    #   ifix_lts / fixpack_lts / fixpack_date_lts → V9（9.0.x.x）
    #   ifix_cd  / fixpack_cd  / fixpack_date_cd  → V8.5（8.5.x.x）

    # 欄位 1
    title: str = ""
    bulletin_url: str = ""
    # 欄位 2：受影響版本範圍（多行，每行一個版本線）
    affected_versions: str = ""
    # 欄位 3
    cve_id: str = ""
    # 欄位 4
    severity: str = ""
    # 欄位 5
    publish_date: str = ""
    # 欄位 6
    cvss_score: float = 0.0
    # 欄位 7：iFix（V9 / V8.5）
    ifix_lts: str = ""         # V9 iFix（例如 "PH71670"）
    ifix_lts_url: str = ""
    ifix_cd: str = ""          # V8.5 iFix（例如 "PH71671"）
    ifix_cd_url: str = ""
    # 欄位 8：Fixpack Version（多行字串，每行一個版本）
    fixpack_lts: str = ""   # V9 版本，例如 "9.0.5.28"
    fixpack_cd: str = ""    # V8.5 版本，例如 "8.5.5.31"
    # 欄位 9：Fixpack Release Date（多行字串，與 fixpack 行數對應）
    fixpack_date_lts: str = ""  # V9 日期
    fixpack_date_cd: str = ""   # V8.5 日期
    # 內部欄位
    _list_severity: str = ""
    cve_details: List[CveDetail] = field(default_factory=list)
```

---

## scraper.py — 主程式

### CLI 參數

| 參數 | 預設值 | 說明 |
|------|--------|------|
| `--days` | `30` | 爬取最近 N 天 |
| `--output` | `None`（自動產生含時間戳記的檔名） | 輸出路徑 |
| `--no-headless` | `False` | 顯示瀏覽器視窗 |
| `--min-cvss` | `7.0` | CVSS 篩選門檻 |
| `--verbose` / `-v` | `False` | Debug 詳細訊息 |

### 主流程

```
Step 1: crawler.fetch_bulletin_list(driver, days)
        → 回傳 list[dict]，每筆含 title, url, cve_ids, severity, publish_date

Step 2: for each item:
            bulletin = bulletin_parser.parse_bulletin_detail(driver, item)
            rows = bulletin_parser.expand_bulletin_to_rows(bulletin, min_cvss)

Step 3: 依 CVSS 分數降冪排序

Step 4: report.generate_html(rows, output_path, days, min_cvss)
```

每筆內頁解析之間加入 **1.5 秒延遲**，避免 rate limiting。

---

## crawler.py — 清單頁爬蟲

### 已知頁面結構（IBM Security Bulletin 搜尋頁通用）

- **搜尋 URL**：`https://www.ibm.com/support/pages/bulletin/search/?q=IBM%20HTTP%20Server`
- **Table ID**：`plc--results-table`（DataTable，已靜態嵌入 HTML）
- **Table 欄位（0-based）**：
  - `td[0]`：Security Bulletin 標題 + `href`（相對路徑，需加 `https://www.ibm.com`）
  - `td[1]`：Product（忽略）
  - `td[2]`：CVE ID（含 MITRE 連結）
  - `td[3]`：Severity（High / Critical / Medium / Low）
  - `td[4]`：Publish date（格式 `YYYY-MM-DD`）
- **同一篇 Bulletin 可能佔多列**（每個 CVE 一列），需以 URL 為 key 合併

---

## bulletin_parser.py — 內頁解析

### 正規表示式常數

```python
RE_CVE             = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
RE_IFIX            = re.compile(r"\b((?:PH|PI|PM|PK|PT|IT|IF)\d{5,})\b", re.IGNORECASE)
RE_IHS_VERSION     = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")
RE_IHS_V9_VERSION  = re.compile(r"\b(9\.\d+\.\d+\.\d+)\b")
RE_IHS_V85_VERSION = re.compile(r"\b(8\.\d+\.\d+\.\d+)\b")
RE_VERSION_RANGE   = re.compile(
    r"(\d{1,2}\.\d+\.\d+(?:\.\d+)?)\s+(?:through|to)\s+(\d{1,2}\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
RE_APPLY_FP        = re.compile(
    r"(?:Apply\b.+?|Apply\s+IBM\s+HTTP\s+Server\s+)(\d{1,2}\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
```

> ⚠️ IBM HTTP Server 的 iFix 前綴為 **`PH`**（例如 `PH71670`）。

### IBM HTTP Server Bulletin 頁面文字結構

```
Vulnerability Details
CVEID:
CVE-2026-XXXX
CVSS Base score:
9.3             ← 緊接的非空行是分數
...

Affected Products and Versions
Affected Product(s)
Version(s)
IBM HTTP Server          ← 產品名行
9.0.0.0 through 9.0.5.27 ← 範圍格式（使用 "through"）
IBM HTTP Server
8.5.5.0 through 8.5.5.30

Remediation/Fixes
For IBM HTTP Server V9.0:
  Apply Fix Pack 9.0.5.28 or a later Fix Pack
    or apply Interim Fix PH71670
For IBM HTTP Server V8.5:
  Apply Fix Pack 8.5.5.31 or a later Fix Pack
    or apply Interim Fix PH71671
```

### Fix List 日期爬取

Fix List 頁面（V9 與 V8.5 在同一頁），從表格中查詢對應版本的日期。
支援多種日期格式：
- `DD Mon YYYY`（例如 `24 Jun 2026`）
- `YYYY/MM/DD` 或 `YYYY-MM-DD`
- `Month DD, YYYY`（例如 `June 24, 2026`）
- 季度目標（例如 `3Q2026`）

---

## report.py — HTML 報表

### 表格欄位（9 欄，依序）

| # | 欄位名稱 | 內容說明 |
|---|---------|---------|
| 1 | Security Bulletin | 標題 + 原始頁面連結 |
| 2 | Affected IHS Version | 版本範圍字串（每行 `<br>` 分隔） |
| 3 | CVE-ID | 連結至 `https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}` |
| 4 | Severity | Critical（紅色）/ High（橙色）Bootstrap badge |
| 5 | Publish Date | 日期字串 |
| 6 | CVSS Base Score | 顏色標籤：≥9.0 紅色、7.0-8.9 橙色 |
| 7 | iFix | V9/V8.5 各自連結（`V9: PHXXXXX` / `V8.5: PHYYYYY`） |
| 8 | Fixpack Version | 多行：每行一個版本，V9 藍色標籤、V8.5 綠色標籤 |
| 9 | Fixpack Release Date | 多行：與 Fixpack 行數一一對應的 GA 日期 |

---

## 重要注意事項

### 1. 模組命名衝突（必讀）
內頁解析模組**必須命名為 `bulletin_parser.py`**，不能命名為 `parser.py`。

### 2. Chrome Binary 路徑
WSL / Linux 環境中 Chrome 可能在 Selenium 快取而非系統 PATH，
必須實作自動偵測邏輯，否則會出現 `cannot find Chrome binary` 錯誤。

### 3. Select2 下拉元件
每頁筆數的 `<select>` 是隱藏的（class `select2-hidden-accessible`），
必須用 JavaScript 設定 `selectedIndex` 並觸發 `change` event。

### 4. IHS 頁面 "through" 格式
Affected Versions 表格版本範圍格式使用 **`through`**（例如 `9.0.0.0 through 9.0.5.27`）。
`RE_VERSION_RANGE` 同時支援 `through` 與 `to` 兩種。

### 5. 欄位命名語意說明
程式碼內部欄位名稱沿用 `lts/cd`，對應 IHS 語意如下：
- `ifix_lts` / `fixpack_lts` / `fixpack_date_lts` → **V9**（9.0.x.x）
- `ifix_cd`  / `fixpack_cd`  / `fixpack_date_cd`  → **V8.5**（8.5.x.x）

### 6. Fix List URL 路由
V9（9.x.x.x）和 V8.5（8.x.x.x）共用同一 Fix List URL：
`https://www.ibm.com/support/pages/ibm-http-server-fix-list`

---

## 資料來源

- **IBM Security Bulletins 搜尋**：`https://www.ibm.com/support/pages/bulletin/search/`
- **CVE 詳細資訊**：`https://cve.mitre.org/`
- **IBM HTTP Server Fix List**：`https://www.ibm.com/support/pages/ibm-http-server-fix-list`

---

*此文件基於 IBM HTTP Server CVE Scraper 專案實作所整理（從 IBM MQ 版本移植）。
如 IBM 網站改版則相關 selector 可能需要重新確認，建議加 `--no-headless --verbose` 確認解析結果。*
