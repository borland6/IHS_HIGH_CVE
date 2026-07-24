# IBM HTTP Server High-Risk CVE Scraper

自動從 IBM Support 網站擷取 IBM HTTP Server 的 Security Bulletin，
篩選高風險 CVE（CVSS ≥ 7.0），並生成 Bootstrap 響應式 HTML 報表。

---

## 功能特色

- 🔍 **自動爬取** IBM Security Bulletin 搜尋頁，支援多頁分頁
- 🎯 **雙重篩選**：Severity（High / Critical）且 Publish Date 在指定天數內
- 📊 **個別 CVE 展開**：一篇 Bulletin 含多個 CVE 時，各自獨立列出
- 🏷️ **版本線識別**：依主版本號區分 V9（9.x.x.x）與 V8.5（8.x.x.x）
- 🔧 **多版本線 Fixpack 解析**：V9 / V8.5 各自獨立解析
- 📅 **Fixpack Release Date**：自動從 IBM HTTP Server Fix List 頁面查詢各版本的 GA 日期
- 📄 **Bootstrap 5 + DataTables**：可排序、可搜尋、RWD 響應式 HTML 報表
- 🕒 **時間戳記檔名**：每次執行自動產生含日期時間的報表檔名

---

## 報表欄位

| # | 欄位 | 說明 |
|---|------|------|
| 1 | Security Bulletin | 標題（含原始頁面連結） |
| 2 | Affected IHS Version | 受影響版本範圍，例如 `9.0.0.0 – 9.0.5.27 V9`（每個版本線一行） |
| 3 | CVE-ID | 連結至 MITRE CVE 資料庫 |
| 4 | Severity | Critical（紅色）/ High（橙色）顏色標示 |
| 5 | Publish Date | 公告發布日期 |
| 6 | CVSS Base Score | 顏色標籤：Critical ≥ 9.0（紅）、High ≥ 7.0（橙） |
| 7 | iFix | V9 / V8.5 各自的 Interim Fix 編號（含連結） |
| 8 | Fixpack Version | V9 / V8.5 各自的 Fixpack 版本號 |
| 9 | Fixpack Release Date | V9 / V8.5 各自的 GA 日期（從 Fix List 頁面自動查詢） |

---

## IBM HTTP Server 版本線規則

| 版本線 | 主版本號規則 | 範例 |
|--------|-------------|------|
| **V9** | 主版本 = 9 | `9.0.5.28`、`9.0.5.29` |
| **V8.5** | 主版本 = 8 | `8.5.5.31`、`8.5.5.32` |

---

## Fixpack Release Date 資料來源

| 版本線 | Fix List URL |
|--------|-------------|
| V9 & V8.5 | https://www.ibm.com/support/pages/ibm-http-server-fix-list |

Fix List 頁面結果會被快取，同一 URL 在單次執行中只爬取一次。

---

## 環境需求

- **Python** 3.10+
- **Google Chrome**（或 Chromium）已安裝
- ChromeDriver 由 Selenium Manager（Selenium 4.6+）自動管理

---

## 安裝

```bash
# 1. 複製或下載此專案
git clone <repo-url>
cd ihs-high-cve

# 2. 安裝 Python 套件
pip install -r requirements.txt
```

### requirements.txt

```
selenium
beautifulsoup4
lxml
python-dateutil
```

---

## 使用方式

### 基本執行（預設：最近 30 天）

```bash
python3 scraper.py
```

### 常用指令

```bash
# 爬取最近 90 天
python3 scraper.py --days 90

# 只擷取 Critical（CVSS ≥ 9.0）
python3 scraper.py --min-cvss 9.0

# 最近 60 天 + 顯示瀏覽器視窗（除錯用）
python3 scraper.py --days 60 --no-headless

# 指定輸出路徑
python3 scraper.py --output output/ihs-cve-report.html

# 顯示詳細執行過程（建議首次執行時使用）
python3 scraper.py --days 60 --verbose
```

### 所有參數

```
usage: scraper.py [-h] [--days N] [--output FILE] [--no-headless]
                   [--min-cvss SCORE] [--verbose]

options:
  --days N          爬取最近 N 天內的公告（預設: 30）
  --output FILE     輸出 HTML 報表路徑（預設: output/report-YYYY-MM-DD-HHMMss.html）
  --no-headless     顯示瀏覽器視窗（除錯用，預設為 headless 模式）
  --min-cvss SCORE  CVSS Base Score 最低門檻（預設: 7.0）
  --verbose, -v     顯示詳細 debug 訊息
```

---

## 輸出範例

執行後產生含時間戳記的 HTML 報表，例如：

```
output/report-2026-07-17-161732.html
```

報表頂部顯示統計摘要（Total / Critical / High 筆數），
表格支援點擊欄位標題排序、搜尋框即時篩選。

---

## 專案結構

```
ihs-high-cve/
├── scraper.py          # 主程式：CLI 參數、主流程、WebDriver 初始化
├── crawler.py          # 清單頁爬蟲：爬取搜尋結果、處理分頁
├── bulletin_parser.py  # 內頁解析：CVSS、版本範圍、Fixpack、Fix List 日期爬取
├── report.py           # HTML 報表生成器（Bootstrap 5 + DataTables）
├── models.py           # 資料結構定義（SecurityBulletin、CveDetail dataclass）
├── requirements.txt    # Python 相依套件
└── output/             # 輸出目錄（報表檔案）
```

---

## 執行流程

```
Step 1  開啟 IBM Security Bulletin 搜尋頁（?q=IBM%20HTTP%20Server）
        設定每頁顯示 50 筆，擷取清單資料
        篩選：Severity = High/Critical 且 Publish Date 在 N 天內

Step 2  逐一進入每篇 Bulletin 內頁
        解析各 CVE 的 CVSS Base Score
        解析 Affected Products / Versions：
          - 輸出範圍格式，例如「9.0.0.0 – 9.0.5.27 V9」
        解析 Remediation 段落（支援下列格式）：
          - 子段落標題：「For IBM HTTP Server V9.0:」或「For IBM HTTP Server V8.5:」
          - 版本行：「Apply Fix Pack 9.0.5.28 or a later Fix Pack」
          - Interim Fix：「or apply Interim Fix PH71670」
        從 IBM HTTP Server Fix List 頁面爬取各 Fixpack 的 GA 日期（有快取）

Step 3  將含多個 CVE 的 Bulletin 展開為多筆輸出列
        依 CVSS 分數降冪排序

Step 4  生成 HTML 報表至 output/ 目錄
```

---

## 常見問題

**Q：執行後報表是空的**

- 嘗試增加 `--days` 天數（預設 30 天，若近期無 High/Critical 公告會是空的）
- 加入 `--no-headless` 確認瀏覽器是否能正常載入 IBM 網站

**Q：出現 `cannot find Chrome binary` 錯誤**

程式會自動偵測以下路徑，確認 Chrome 或 Chromium 已安裝：
- 系統 PATH（`google-chrome`、`chromium` 等）
- `~/.cache/selenium/chrome/linux64/*/chrome`
- `~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`

**Q：Fixpack Version 欄位顯示正確但 Release Date 為空**

IBM HTTP Server Fix List 頁面可能暫時無法存取，或該版本尚未列在 Fix List 中。
可搭配 `--verbose` 查看 Fix List 爬取的詳細 log。

---

## 資料來源

- **IBM Security Bulletins**：https://www.ibm.com/support/pages/bulletin/search/?q=IBM%20HTTP%20Server
- **CVE 詳細資訊**：https://cve.mitre.org/
- **IBM HTTP Server Fix List**：https://www.ibm.com/support/pages/ibm-http-server-fix-list
