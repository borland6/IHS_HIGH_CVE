"""
bulletin_parser.py — IBM HTTP Server Security Bulletin 內頁解析器

基於實際頁面結構（IBM Security Bulletin 通用格式）：

頁面文字結構（get_text 後）:
  Vulnerability Details
  CVEID:
  CVE-2026-XXXX
  ...
  CVSS Base score:
  9.3                        ← 直接是數字
  CVSS Vector:
  ...
  （下一個 CVE 重複以上結構）

  Affected Products and Versions
  Affected Product(s)   Version(s)
  IBM HTTP Server       9.0.0.0 through 9.0.5.27
  IBM HTTP Server       8.5.5.0 through 8.5.5.30

  Remediation/Fixes
  ...
  For IBM HTTP Server V9.0:
    Apply Fix Pack 9.0.5.28 or a later Fix Pack
      or apply Interim Fix PH71670
  For IBM HTTP Server V8.5:
    Apply Fix Pack 8.5.5.31 or a later Fix Pack
      or apply Interim Fix PH71671

IBM HTTP Server 版本線規則（主版本號判斷）：
  V9.0（9.0.x.x）：主版本 = 9
  V8.5（8.5.x.x）：主版本 = 8

Fixpack Release Date 取得方式：
  優先從 Bulletin 頁面的 "targeted availability" 直接解析。
  若無則 fallback 至 IBM HTTP Server Fix List 頁面：
    V9  → https://www.ibm.com/support/pages/fix-list-ibm-http-server-version-90
    V8.5 → https://www.ibm.com/support/pages/fix-list-ibm-http-server-version-85
"""

import logging
import re
import time
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from models import SecurityBulletin, CveDetail

logger = logging.getLogger(__name__)

WAIT_TIMEOUT = 20

# ──────────────────────────────────────────────────────────────
# 正規表示式常數
# ──────────────────────────────────────────────────────────────

RE_CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# IBM HTTP Server / WAS 的 iFix 前綴為 PH（保留 IT/PI/PM 作 fallback）
RE_IFIX = re.compile(r"\b((?:PH|PI|PM|PK|PT|IT|IF)\d{5,})\b", re.IGNORECASE)

RE_QUARTER = re.compile(r"\b([1-4]Q\s*\d{4})\b", re.IGNORECASE)

# IBM HTTP Server 版本號：N.N.N.N（主版本 9 或 8）
RE_IHS_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")

# V9：主版本 = 9（例如 9.0.5.28）
RE_IHS_V9_VERSION = re.compile(r"\b(9\.\d+\.\d+\.\d+)\b")

# V8.5：主版本 = 8（例如 8.5.5.31）
RE_IHS_V85_VERSION = re.compile(r"\b(8\.\d+\.\d+\.\d+)\b")

# Apply Fix Pack / Apply IBM HTTP Server 解析（版本號在同一行）
RE_APPLY_FP = re.compile(
    r"(?:Apply\b.+?|Apply\s+IBM\s+HTTP\s+Server\s+)(\d{1,2}\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

# Fix List URL 對應表（V9 / V8.5 各自獨立頁）
FIX_LIST_URLS: Dict[str, str] = {
    "9.0": "https://www.ibm.com/support/pages/fix-list-ibm-http-server-version-90",
    "8.5": "https://www.ibm.com/support/pages/fix-list-ibm-http-server-version-85",
}

# ──────────────────────────────────────────────────────────────
# 輔助函式
# ──────────────────────────────────────────────────────────────

def _severity_from_score(score: float) -> str:
    """依 CVSS 分數計算 Severity（Critical >= 9.0, High >= 7.0）。"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return ""


def _is_v9_version(version: str) -> bool:
    """判斷版本號是否為 V9（主版本 = 9，例如 9.0.5.28）。"""
    parts = version.split(".")
    return len(parts) == 4 and parts[0] == "9"


def _is_v85_version(version: str) -> bool:
    """判斷版本號是否為 V8.5（主版本 = 8，例如 8.5.5.31）。"""
    parts = version.split(".")
    return len(parts) == 4 and parts[0] == "8"


def _major_minor(version: str) -> str:
    """取版本號的「主.次」部分，例如 '9.0.5.28' → '9.0'，'8.5.5.31' → '8.5'。"""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return ""


def _wait_for_page_load(driver, timeout: int = WAIT_TIMEOUT):
    """等待內頁主要內容載入。"""
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "article, main, .ibm-content, #content, body")
            )
        )
        time.sleep(1.5)
    except TimeoutException:
        logger.warning("等待頁面載入逾時，嘗試繼續解析")


# ──────────────────────────────────────────────────────────────
# CVE 詳細資訊解析
# ──────────────────────────────────────────────────────────────

def _parse_cve_details(lines: List[str], vd_start: int, vd_end: int) -> List[CveDetail]:
    """
    從 Vulnerability Details 區段解析每個 CVE 的 ID 與 CVSS Base Score。

    頁面文字結構（每個 CVE 區塊）：
      CVEID:
      CVE-XXXX-YYYY
      DESCRIPTION:
      ...
      CVSS Base score:
      9.3              ← 緊接在 "CVSS Base score:" 下一個非空行就是分數
      CVSS Vector:
      ...
    """
    details: List[CveDetail] = []
    vd_lines = lines[vd_start:vd_end]

    current_cve = ""
    expect_score = False  # 下一個數字行是 CVSS Score

    for line in vd_lines:
        stripped = line.strip()
        if not stripped:
            continue

        # 偵測 CVE ID 行
        cve_match = RE_CVE.fullmatch(stripped.upper())
        if cve_match:
            if current_cve and not any(d.cve_id == current_cve for d in details):
                details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))
            current_cve = stripped.upper()
            expect_score = False
            continue

        # 偵測 "CVSS Base score:" 標記
        if re.match(r"CVSS\s+Base\s+score\s*:?$", stripped, re.IGNORECASE):
            expect_score = True
            continue

        # 讀取 CVSS 分數
        if expect_score and current_cve:
            try:
                score = float(stripped)
                severity = _severity_from_score(score)
                details.append(CveDetail(
                    cve_id=current_cve,
                    cvss_score=score,
                    severity=severity,
                ))
                logger.debug("  CVE %s → CVSS %.1f (%s)", current_cve, score, severity)
                current_cve = ""
                expect_score = False
            except ValueError:
                pass
            continue

    if current_cve and not any(d.cve_id == current_cve for d in details):
        details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))

    return details


def _fallback_parse_cve_details(text: str, cve_ids: List[str]) -> List[CveDetail]:
    """當找不到 Vulnerability Details 段落時，直接從全文抓取每個 CVE 的 CVSS。"""
    details: List[CveDetail] = []
    upper_text = text.upper()
    for cve_id in cve_ids:
        idx = upper_text.find(cve_id.upper())
        score = 0.0
        if idx != -1:
            window = text[idx:idx + 1200]
            m = re.search(
                r"CVSS\s*Base\s*score\s*:?[\s\n]*([0-9]+(?:\.[0-9])?)",
                window, re.IGNORECASE
            )
            if m:
                score = float(m.group(1))
        details.append(CveDetail(
            cve_id=cve_id.upper(),
            cvss_score=score,
            severity=_severity_from_score(score)
        ))
    return details


# ──────────────────────────────────────────────────────────────
# Bulletin 類型判斷（V9 / V8.5 / both）
# ──────────────────────────────────────────────────────────────

def _detect_bulletin_type(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    偵測 Bulletin 類型：
      - "v9"  ：只有 V9 版本（9.x.x.x）
      - "v85" ：只有 V8.5 版本（8.x.x.x）
      - "both"：同時包含 V9 與 V8.5
    """
    search_end = min(rem_start + 60, len(lines)) if rem_start != -1 else aff_start + 60
    combined_text = "\n".join(lines[aff_start:search_end])

    has_v9 = bool(RE_IHS_V9_VERSION.search(combined_text))
    has_v85 = bool(RE_IHS_V85_VERSION.search(combined_text))

    if rem_start != -1:
        rem_text = "\n".join(lines[rem_start:rem_start + 80])
        if re.search(r"\bV9\b|V9\.0", rem_text, re.IGNORECASE):
            has_v9 = True
        if re.search(r"\bV8\.5\b|V8\b", rem_text, re.IGNORECASE):
            has_v85 = True

    if has_v9 and has_v85:
        return "both"
    if has_v85:
        return "v85"
    return "v9"


def _fallback_detect_bulletin_type(page_text: str, title: str) -> str:
    """當 Affected Products 區段不存在時，從全文判斷公告類型。"""
    has_v9 = bool(RE_IHS_V9_VERSION.search(page_text))
    has_v85 = bool(RE_IHS_V85_VERSION.search(page_text))
    if has_v9 and has_v85:
        return "both"
    if has_v85:
        return "v85"
    return "v9"


# ──────────────────────────────────────────────────────────────
# Affected Versions 解析
# ──────────────────────────────────────────────────────────────

# 版本範圍格式：N.N.N.N through/to N.N.N.N（IHS 頁面通常用 "through"）
RE_VERSION_RANGE = re.compile(
    r"(\d{1,2}\.\d+\.\d+(?:\.\d+)?)\s+(?:through|to)\s+(\d{1,2}\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

# 不納入的產品關鍵字（IBM HTTP Server 頁面通常無需過濾元件，但保留基本設定）
EXCLUDED_PRODUCT_KEYWORDS: List[str] = []


def _is_excluded_product(product_line: str) -> bool:
    """
    判斷該產品行是否為不需納入的元件。
    IBM HTTP Server 頁面一般不需過濾，保留此函式作為擴充點。
    """
    lower = product_line.lower()
    if "except" in lower:
        return False
    return any(kw in lower for kw in EXCLUDED_PRODUCT_KEYWORDS)


def _parse_affected_versions(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    從 Affected Products and Versions 表格解析受影響的 IHS 版本範圍。

    IBM HTTP Server Bulletin 表格文字結構（get_text 後）：
      Affected Products and Versions
      Affected Product(s)
      Version(s)
      IBM HTTP Server                 ← 產品名行
      9.0                             ← 短版本（實際頁面格式）
      IBM HTTP Server
      8.5

    或完整範圍格式（較少見）：
      IBM HTTP Server
      9.0.0.0 through 9.0.5.27

    回傳格式（每個版本線一行，換行符分隔）：
      "9.0 V9\n8.5 V8.5"
    或
      "9.0.0.0 – 9.0.5.27 V9\n8.5.5.0 – 8.5.5.30 V8.5"
    """
    aff_end = rem_start if rem_start > aff_start else aff_start + 80
    aff_lines = lines[aff_start:aff_end]

    ranges: List[str] = []
    skip_next_version = False  # 上一行是需要跳過的產品，版本行也跳過

    i = 0
    while i < len(aff_lines):
        line = aff_lines[i].strip()
        i += 1

        if not line:
            continue

        # 偵測產品名行（包含 "IBM HTTP Server" 且不是表頭）
        if re.match(r"IBM\s+HTTP\s+Server\b", line, re.IGNORECASE):
            skip_next_version = _is_excluded_product(line)
            continue

        # 若上一個產品需要跳過，也跳過此版本行
        if skip_next_version:
            skip_next_version = False
            continue

        # 嘗試解析版本範圍格式 "X.X.X.X through/to X.X.X.X"
        m = RE_VERSION_RANGE.search(line)
        if m:
            start_ver = m.group(1)
            end_ver = m.group(2)
            if start_ver.count(".") == 2:
                start_ver = start_ver + ".0"
            ranges.append(f"{start_ver} – {end_ver}")
            continue

        # 四碼純版本號行（沒有 through/to），例如 "9.0.5.28"
        m_full = re.match(r"^(\d{1,2}\.\d+\.\d+\.\d+)$", line)
        if m_full:
            ranges.append(m_full.group(1))
            continue

        # ── 短版本號行（IHS 實際頁面格式）──
        # 例如 "9.0"、"8.5"（表格 Version(s) 欄只有主版本）
        m_short = re.match(r"^(9\.0|8\.5)$", line)
        if m_short:
            ranges.append(m_short.group(1))
            continue

    return "\n".join(ranges) if ranges else ""


def _fallback_find_affected_versions(text: str) -> str:
    """當找不到 Affected Products 區段時，從全文抓受影響版本（範圍格式）。"""
    ranges: List[str] = []
    seen: set = set()

    for m in RE_VERSION_RANGE.finditer(text):
        start_ver = m.group(1)
        end_ver = m.group(2)
        if start_ver.count(".") == 2:
            start_ver = start_ver + ".0"
        key = end_ver
        if key in seen:
            continue
        seen.add(key)
        ranges.append(f"{start_ver} – {end_ver}")

    return "\n".join(ranges) if ranges else ""


# ──────────────────────────────────────────────────────────────
# iFix URL 查找
# ──────────────────────────────────────────────────────────────

def _find_first_url_for_ifix(soup: BeautifulSoup, label: str) -> str:
    """從 soup 中找指定 iFix 編號的超連結。"""
    if not label:
        return ""
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True)
        if label.upper() in text.upper() or label.upper() in href.upper():
            return href
    return ""


# ──────────────────────────────────────────────────────────────
# Fix List 頁面爬取（Fixpack Release Date）
# ──────────────────────────────────────────────────────────────

# 快取：{ url → { version_str → date_str } }
_fix_list_cache: Dict[str, Dict[str, str]] = {}


def _fetch_fix_list_dates(driver, url: str) -> Dict[str, str]:
    """
    爬取 IBM HTTP Server Fix List 頁面，回傳 { version_str → ga_date } 字典。

    Fix List 頁面（V9 與 V8.5 在同一頁），含有版本號與 GA Date 資訊。
    策略：找含版本號的儲存格，取同列的日期欄。
    """
    if url in _fix_list_cache:
        logger.debug("  Fix List 快取命中: %s", url)
        return _fix_list_cache[url]

    logger.info("  爬取 Fix List 頁面: %s", url)
    result: Dict[str, str] = {}

    try:
        driver.get(url)
        _wait_for_page_load(driver)
        soup = BeautifulSoup(driver.page_source, "lxml")

        month_map = {
            "jan": "01", "feb": "02", "mar": "03", "apr": "04",
            "may": "05", "jun": "06", "jul": "07", "aug": "08",
            "sep": "09", "oct": "10", "nov": "11", "dec": "12",
        }

        def _parse_date_str(s: str) -> str:
            """把各種日期字串轉成 YYYY/MM/DD 或原樣回傳。"""
            # "Fix release date: 16 June 2026" 或 "16 June 2026"
            dm = re.search(
                r"\b(\d{1,2})\s+"
                r"(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
                r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
                r"\s+(\d{4})\b",
                s, re.IGNORECASE
            )
            if dm:
                mon = month_map.get(dm.group(2)[:3].lower(), "01")
                return f"{dm.group(3)}/{mon}/{int(dm.group(1)):02d}"
            # "June 16, 2026"
            dm2 = re.search(
                r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
                r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
                r"\s+(\d{1,2}),?\s+(\d{4})\b",
                s, re.IGNORECASE
            )
            if dm2:
                mon = month_map.get(dm2.group(1)[:3].lower(), "01")
                return f"{dm2.group(3)}/{mon}/{int(dm2.group(2)):02d}"
            # YYYY/MM/DD 或 YYYY-MM-DD
            dm3 = re.search(r"\b(\d{4}[/\-]\d{2}[/\-]\d{2})\b", s)
            if dm3:
                return dm3.group(1).replace("-", "/")
            # 季度 3Q2026
            dm4 = RE_QUARTER.search(s)
            if dm4:
                return dm4.group(1)
            return ""

        # IHS Fix List 頁面實際格式（2026-07 確認）：
        #   每個 Fix Pack 用一個 <table>，格式如下：
        #   Table row 0, cell 0: "IBM HTTP Server 9.0.5.28"（版本標題）
        #   Table row 1, cell 0: "Download Fix Pack 9.0.5.28 Fix release date: 16 June 2026 ..."
        #
        # 策略：逐 table 掃描，從版本標題行取版本號，從 "Fix release date:" 行取日期

        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            ver_in_table = ""
            for row in rows:
                cells = row.find_all(["td", "th"])
                if not cells:
                    continue
                cell0_text = cells[0].get_text(" ", strip=True)

                # 格式一：版本標題行 "IBM HTTP Server X.Y.Z.W"（獨立 cell，無日期）
                ver_match = re.search(r"IBM\s+HTTP\s+Server\s+(\d{1,2}\.\d+\.\d+\.\d+)", cell0_text)
                if ver_match and len(cells) <= 2:
                    ver_in_table = ver_match.group(1)
                    # 若同一行也有日期（少數情況）
                    date_found = _parse_date_str(cell0_text)
                    if not date_found and len(cells) > 1:
                        date_found = _parse_date_str(cells[1].get_text(" ", strip=True))
                    if ver_in_table and date_found:
                        result[ver_in_table] = date_found
                        logger.debug("    Fix List: %s → %s", ver_in_table, date_found)
                    continue

                # 格式二：資訊行 "Download Fix Pack X.Y.Z.W Fix release date: DD Month YYYY"
                if "Fix release date:" in cell0_text or "release date" in cell0_text.lower():
                    ver_m2 = re.search(r"(\d{1,2}\.\d+\.\d+\.\d+)", cell0_text)
                    ver_key = ver_m2.group(1) if ver_m2 else ver_in_table
                    date_found = _parse_date_str(cell0_text)
                    if ver_key and date_found:
                        result[ver_key] = date_found
                        logger.debug("    Fix List: %s → %s", ver_key, date_found)
                    continue

                # 格式三：表格欄位格式（備用）
                ver_m3 = re.search(r"(\d{1,2}\.\d+\.\d+\.\d+)", cell0_text)
                if ver_m3:
                    ver = ver_m3.group(1)
                    date_found = ""
                    for cell in cells:
                        date_found = _parse_date_str(cell.get_text(" ", strip=True))
                        if date_found:
                            break
                    if date_found:
                        result[ver] = date_found
                        logger.debug("    Fix List: %s → %s", ver, date_found)

        if not result:
            logger.warning("  Fix List 頁面未解析到版本日期: %s", url)

    except Exception as e:
        logger.error("  爬取 Fix List 頁面失敗 (%s): %s", url, e)

    _fix_list_cache[url] = result
    return result


def _get_fixpack_date(driver, version: str) -> str:
    """
    根據 fixpack 版本號，從對應的 Fix List 頁面取得 Release Date。

    V9（9.x.x.x）  → FIX_LIST_URLS["9.0"]
    V8.5（8.x.x.x）→ FIX_LIST_URLS["8.5"]
    """
    if not version:
        return ""
    mm = _major_minor(version)
    url = FIX_LIST_URLS.get(mm)

    if not url:
        logger.debug("  無對應 Fix List URL: version=%s major_minor=%s", version, mm)
        return ""

    dates = _fetch_fix_list_dates(driver, url)
    date = dates.get(version, "")
    if date:
        logger.info("  Fixpack Release Date: %s → %s", version, date)
    else:
        logger.debug("  Fix List 找不到版本 %s 的日期", version)
    return date


# ──────────────────────────────────────────────────────────────
# Remediation 解析（多版本線 V9 / V8.5）
# ──────────────────────────────────────────────────────────────

def _parse_remediation(lines: List[str], rem_start: int) -> Dict:
    """
    從 Remediation 段落解析所有版本線的 iFix 編號與 Fixpack 版本。

    IBM HTTP Server Remediation 段落格式（典型）：
      For IBM HTTP Server V9.0:
        Apply Fix Pack 9.0.5.28 or a later Fix Pack
          or apply Interim Fix PH71670
      For IBM HTTP Server V8.5:
        Apply Fix Pack 8.5.5.31 or a later Fix Pack
          or apply Interim Fix PH71671

    舊格式（保留相容）：
      "IBM HTTP Server version V9.0"
      "IBM HTTP Server version V8.5"

    回傳結果：
      fixpack_lts：多行字串，每行 "version"（V9 版本列表，對應 ifix_lts）
      fixpack_cd ：多行字串，每行 "version"（V8.5 版本列表，對應 ifix_cd）
      ifix_lts, ifix_cd：最先找到的 iFix 編號
    注意：此處沿用 lts/cd 欄位名稱，語意對應 V9/V8.5。
    """
    result = {
        "ifix_lts": "", "ifix_lts_url": "",   # V9 的 iFix
        "ifix_cd": "", "ifix_cd_url": "",      # V8.5 的 iFix
        "fixpack_lts": "",    # V9 的 fixpack 版本（多行）
        "fixpack_cd": "",     # V8.5 的 fixpack 版本（多行）
        "fixpack_date_lts": "",  # V9 的 release date（多行）
        "fixpack_date_cd": "",   # V8.5 的 release date（多行）
    }

    rem_lines = lines[rem_start:]

    # ── 找出所有版本子段落的起始行 ──
    # IBM HTTP Server Bulletin 實際頁面格式（2026-07 確認）：
    #   "For IBM HTTP Server used by IBM WebSphere Application Server:"  ← 外層大段落
    #   "For V9.0.0.0 through 9.0.5.28:"   ← V9 子段落標題
    #   "· Upgrade to minimal fix pack levels ... apply the Interim Fix that resolves"
    #   "PH71594"                            ← iFix 編號在獨立一行！
    #   "--OR--"
    #   "· Apply Fix Pack 9.0.5.29 or later (targeted availability 3Q2026)."
    #   "For V8.5.0.0 through 8.5.5.29:"   ← V8.5 子段落標題
    #   ...
    section_starts: List[int] = []
    for i, l in enumerate(rem_lines):
        stripped_l = re.sub(r"^[-–·\s]+", "", l)
        # 格式 1：For V9.x.x.x ... 或 For V8.5.x.x ...
        if re.match(r"For\s+V\d", stripped_l, re.IGNORECASE):
            section_starts.append(i)
        # 格式 2：For IBM HTTP Server V9.0: 或 For IBM HTTP Server V8.5:
        elif (re.match(r"For\s+IBM\s+HTTP\s+Server\s+V\d", stripped_l, re.IGNORECASE)):
            section_starts.append(i)
        # 格式 3：IBM HTTP Server version V9.0（舊格式相容）
        elif re.match(r"IBM\s+HTTP\s+Server\s+version\b", stripped_l, re.IGNORECASE):
            section_starts.append(i)

    # ── 若無明確子段落，從全段落按版本號型態分類抓取 ──
    if not section_starts:
        v9_versions: List[str] = []
        v85_versions: List[str] = []
        v9_ifix = ""
        v85_ifix = ""
        v9_dates: List[str] = []
        v85_dates: List[str] = []

        for idx, line in enumerate(rem_lines[:100]):
            # Apply Fix Pack X.Y.Z.W or later (targeted availability XQ20XX)
            m_apply = re.search(
                r"Apply\s+Fix\s+Pack\s+(\d{1,2}\.\d+\.\d+\.\d+)[^(]*"
                r"(?:\(targeted\s+availability\s+([^)]+)\))?",
                line, re.IGNORECASE
            )
            if m_apply:
                ver = m_apply.group(1)
                date = (m_apply.group(2) or "").strip()
                if _is_v9_version(ver) and ver not in v9_versions:
                    v9_versions.append(ver)
                    v9_dates.append(date)
                elif _is_v85_version(ver) and ver not in v85_versions:
                    v85_versions.append(ver)
                    v85_dates.append(date)

            # iFix：行尾的 iFix 編號，或獨立行緊跟在 "Interim Fix that resolves" 後
            if re.search(r"interim.?fix", line, re.IGNORECASE):
                ifix_in_line = RE_IFIX.findall(line)
                ifix_next_line = ""
                if not ifix_in_line and idx + 1 < len(rem_lines):
                    nxt = rem_lines[idx + 1].strip()
                    if RE_IFIX.fullmatch(nxt.upper()):
                        ifix_next_line = nxt.upper()
                ifix_found = ifix_in_line[0].upper() if ifix_in_line else ifix_next_line
                if ifix_found:
                    if not v9_ifix:
                        v9_ifix = ifix_found
                    elif not v85_ifix:
                        v85_ifix = ifix_found

        result["fixpack_lts"] = "\n".join(v9_versions)
        result["fixpack_cd"] = "\n".join(v85_versions)
        result["fixpack_date_lts"] = "\n".join(v9_dates)
        result["fixpack_date_cd"] = "\n".join(v85_dates)
        result["ifix_lts"] = v9_ifix
        result["ifix_cd"] = v85_ifix
        return result

    # ── 逐一解析每個子段落 ──
    v9_versions: List[str] = []
    v85_versions: List[str] = []
    v9_ifix = ""
    v85_ifix = ""
    v9_dates: List[str] = []
    v85_dates: List[str] = []

    for sec_idx, sec_start in enumerate(section_starts):
        sec_end = section_starts[sec_idx + 1] if sec_idx + 1 < len(section_starts) else sec_start + 20
        sec_lines = rem_lines[sec_start:sec_end]
        sec_header = sec_lines[0] if sec_lines else ""

        # 判斷此子段落屬於 V9 還是 V8.5（由標題行判斷）
        # 標題範例：
        #   "For V9.0.0.0 through 9.0.5.28:"  → V9
        #   "For V8.5.0.0 through 8.5.5.29:"  → V8.5
        #   "For IBM HTTP Server V9.0:"        → V9
        #   "For IBM HTTP Server V8.5:"        → V8.5
        header_has_v9 = bool(re.search(
            r"V9\b|V9\.0|For\s+V9\.|version\s+9\.", sec_header, re.IGNORECASE
        ))
        header_has_v85 = bool(re.search(
            r"V8\.5\b|For\s+V8\.\d|version\s+8\.", sec_header, re.IGNORECASE
        ))

        # 若標題無明確標記，從版本號判斷
        if not header_has_v9 and not header_has_v85:
            header_has_v9 = bool(RE_IHS_V9_VERSION.search(sec_header))
            header_has_v85 = bool(RE_IHS_V85_VERSION.search(sec_header))

        # ── 抓 Fixpack 版本與 targeted availability ──
        sec_joined = " ".join(sec_lines[1:])
        for line in list(sec_lines[1:]) + [sec_joined]:
            # 格式：Apply Fix Pack X.Y.Z.W or later (targeted availability XQ20XX)
            m_apply = re.search(
                r"Apply\s+Fix\s+Pack\s+(\d{1,2}\.\d+\.\d+\.\d+)[^(]*"
                r"(?:\(targeted\s+availability\s+([^)]+)\))?",
                line, re.IGNORECASE
            )
            if not m_apply:
                # 備援：X.Y.Z.W or later (targeted availability XQ20XX)
                m_apply = re.search(
                    r"(\d{1,2}\.\d+\.\d+\.\d+)\s+or\s+(?:a\s+)?later[^(]*"
                    r"(?:\(targeted\s+availability\s+([^)]+)\))?",
                    line, re.IGNORECASE
                )
            if m_apply:
                ver = m_apply.group(1)
                date = (m_apply.group(2) or "").strip()
                if header_has_v9 and not header_has_v85:
                    if ver not in v9_versions:
                        v9_versions.append(ver)
                        v9_dates.append(date)
                elif header_has_v85 and not header_has_v9:
                    if ver not in v85_versions:
                        v85_versions.append(ver)
                        v85_dates.append(date)
                else:
                    if _is_v9_version(ver) and ver not in v9_versions:
                        v9_versions.append(ver)
                        v9_dates.append(date)
                    elif _is_v85_version(ver) and ver not in v85_versions:
                        v85_versions.append(ver)
                        v85_dates.append(date)

        # ── 抓 iFix ──
        # IHS 頁面實際格式：iFix 編號在 "Interim Fix that resolves" 行的「下一行」（獨立行）
        ifix = _extract_ifix_ihs(sec_lines)
        if ifix:
            if header_has_v9 and not v9_ifix:
                v9_ifix = ifix
            elif header_has_v85 and not v85_ifix:
                v85_ifix = ifix
            elif not v9_ifix:
                v9_ifix = ifix
            elif not v85_ifix:
                v85_ifix = ifix

    result["fixpack_lts"] = "\n".join(v9_versions)
    result["fixpack_cd"] = "\n".join(v85_versions)
    result["fixpack_date_lts"] = "\n".join(v9_dates)
    result["fixpack_date_cd"] = "\n".join(v85_dates)
    result["ifix_lts"] = v9_ifix
    result["ifix_cd"] = v85_ifix
    return result


def _extract_ifix(lines: List[str]) -> str:
    """從文字行列中抓取第一個 iFix 編號（支援同行與換行兩種格式）。"""
    for idx, line in enumerate(lines):
        if re.search(r"interim.?fix", line, re.IGNORECASE):
            ifix = RE_IFIX.findall(line)
            if ifix:
                return ifix[0].upper()
            if idx + 1 < len(lines):
                ifix_next = RE_IFIX.fullmatch(lines[idx + 1].strip().upper())
                if ifix_next:
                    return lines[idx + 1].strip().upper()
    return ""


def _extract_ifix_ihs(lines: List[str]) -> str:
    """
    IBM HTTP Server 實際頁面格式：iFix 編號在獨立一行，緊跟在含 "resolves" 的行後面。

    格式範例：
      "· Upgrade to minimal fix pack levels ... apply the Interim Fix that resolves"
      "PH71594"   ← 獨立一行，無其他文字
      "--OR--"

    同時相容 iFix 編號在同行的格式（fallback）。
    """
    for idx, line in enumerate(lines):
        # 優先：含 "resolves" 且下一行是純 iFix 編號（IHS 實際格式）
        if re.search(r"resolves\s*$", line.strip(), re.IGNORECASE):
            if idx + 1 < len(lines):
                nxt = lines[idx + 1].strip()
                if RE_IFIX.fullmatch(nxt.upper()):
                    return nxt.upper()
        # 次要：含 "interim fix" 且同行或下一行有 iFix 編號
        if re.search(r"interim.?fix", line, re.IGNORECASE):
            ifix = RE_IFIX.findall(line)
            if ifix:
                return ifix[0].upper()
            if idx + 1 < len(lines):
                nxt = lines[idx + 1].strip()
                if RE_IFIX.fullmatch(nxt.upper()):
                    return nxt.upper()
    return ""


# ──────────────────────────────────────────────────────────────
# 主解析函式
# ──────────────────────────────────────────────────────────────

def parse_bulletin_detail(driver, bulletin_dict: Dict) -> SecurityBulletin:
    """
    進入 Security Bulletin 內頁，解析：
      1. 每個 CVE 各自的 CVSS Base Score（存入 cve_details）
      2. Affected Products 段落：受影響 IHS 版本範圍
      3. Remediation 段落：iFix、各版本線 Fixpack 版本
      4. Fix List 頁面：各 Fixpack 版本的 Release Date

    回傳的 SecurityBulletin.cve_details 包含所有 CVE 的詳細資訊。
    主程式（scraper.py）負責將其展開為多筆輸出列。

    注意：欄位沿用 lts/cd 命名，語意對應如下：
      ifix_lts / fixpack_lts / fixpack_date_lts → V9（9.x.x.x）
      ifix_cd  / fixpack_cd  / fixpack_date_cd  → V8.5（8.x.x.x）
    """
    url = bulletin_dict.get("url", "")
    title = bulletin_dict.get("title", "")
    cve_ids_from_list = bulletin_dict.get("cve_ids", [])
    list_severity = bulletin_dict.get("severity", "")
    publish_date = bulletin_dict.get("publish_date", "")

    logger.info("解析內頁: %s", url)

    bulletin = SecurityBulletin(
        title=title,
        bulletin_url=url,
        publish_date=publish_date,
        _list_severity=list_severity,
    )

    try:
        driver.get(url)
        _wait_for_page_load(driver)
        soup = BeautifulSoup(driver.page_source, "lxml")
        text = soup.get_text(separator="\n", strip=True)
        lines = [l.strip() for l in text.split("\n")]

        # 找各段落位置
        vd_start = next(
            (i for i, l in enumerate(lines) if "Vulnerability Details" in l), -1
        )
        aff_start = next(
            (i for i, l in enumerate(lines) if "Affected Products and Versions" in l), -1
        )
        rem_start = next(
            (i for i, l in enumerate(lines) if re.match(r"Remediation(?:/Fixes)?", l, re.IGNORECASE)), -1
        )

        if vd_start == -1:
            logger.warning("  找不到 Vulnerability Details 段落")
        if rem_start == -1:
            logger.warning("  找不到 Remediation 段落")

        vd_end = rem_start if rem_start > vd_start else len(lines)

        # 1. 解析每個 CVE 的 CVSS Score
        if vd_start != -1:
            bulletin.cve_details = _parse_cve_details(lines, vd_start, vd_end)
        elif cve_ids_from_list:
            bulletin.cve_details = _fallback_parse_cve_details(text, cve_ids_from_list)

        if bulletin.cve_details:
            logger.info(
                "  解析到 %d 個 CVE: %s",
                len(bulletin.cve_details),
                [(d.cve_id, d.cvss_score) for d in bulletin.cve_details]
            )

        if not bulletin.cve_details and cve_ids_from_list:
            for cid in cve_ids_from_list:
                bulletin.cve_details.append(CveDetail(cve_id=cid, cvss_score=0.0))
            logger.debug("  使用清單頁 CVE IDs 作為 fallback")

        # 2. 偵測 Bulletin 類型（v9 / v85 / both）
        if aff_start != -1 or rem_start != -1:
            bulletin_type = _detect_bulletin_type(
                lines,
                aff_start if aff_start != -1 else rem_start,
                rem_start
            )
        else:
            bulletin_type = _fallback_detect_bulletin_type(text, title)
        logger.info("  Bulletin 類型: %s", bulletin_type)

        # 3. 解析 Affected Versions
        if aff_start != -1:
            bulletin.affected_versions = _parse_affected_versions(lines, aff_start, rem_start)
        else:
            bulletin.affected_versions = _fallback_find_affected_versions(text)
        logger.info("  Affected Versions: %s", bulletin.affected_versions.replace('\n', ' | '))

        # 4. 解析 Remediation（多版本線 iFix + Fixpack + targeted availability）
        if rem_start != -1:
            fix_info = _parse_remediation(lines, rem_start)

            # lts 欄位對應 V9，cd 欄位對應 V8.5
            bulletin.ifix_lts = fix_info["ifix_lts"]
            bulletin.ifix_cd = fix_info["ifix_cd"]
            bulletin.fixpack_lts = fix_info["fixpack_lts"]
            bulletin.fixpack_cd = fix_info["fixpack_cd"]

            # 取 iFix URL
            bulletin.ifix_lts_url = _find_first_url_for_ifix(soup, bulletin.ifix_lts)
            bulletin.ifix_cd_url = _find_first_url_for_ifix(soup, bulletin.ifix_cd)

            logger.info("  V9  fixpacks: %s", bulletin.fixpack_lts.replace('\n', ', '))
            logger.info("  V8.5 fixpacks: %s", bulletin.fixpack_cd.replace('\n', ', '))

            # 5. Fixpack Release Date：優先使用 Bulletin 頁面直接解析的 targeted availability，
            #    若為空則 fallback 至 Fix List 頁面查詢
            bulletin.fixpack_date_lts = fix_info.get("fixpack_date_lts", "")
            bulletin.fixpack_date_cd = fix_info.get("fixpack_date_cd", "")

            # Fallback：Bulletin 頁面未取到日期時，才去爬 Fix List
            if not bulletin.fixpack_date_lts.strip():
                v9_dates = []
                for ver in bulletin.fixpack_lts.split("\n"):
                    ver = ver.strip()
                    if ver:
                        v9_dates.append(_get_fixpack_date(driver, ver))
                    else:
                        v9_dates.append("")
                bulletin.fixpack_date_lts = "\n".join(v9_dates)

            if not bulletin.fixpack_date_cd.strip():
                v85_dates = []
                for ver in bulletin.fixpack_cd.split("\n"):
                    ver = ver.strip()
                    if ver:
                        v85_dates.append(_get_fixpack_date(driver, ver))
                    else:
                        v85_dates.append("")
                bulletin.fixpack_date_cd = "\n".join(v85_dates)

            logger.info("  V9  dates: %s", bulletin.fixpack_date_lts.replace('\n', ', '))
            logger.info("  V8.5 dates: %s", bulletin.fixpack_date_cd.replace('\n', ', '))

    except Exception as e:
        logger.error("解析內頁失敗 (%s): %s", url, e, exc_info=True)

    return bulletin


# ──────────────────────────────────────────────────────────────
# 展開多 CVE → 多筆輸出列
# ──────────────────────────────────────────────────────────────

def expand_bulletin_to_rows(bulletin: SecurityBulletin, min_cvss: float = 7.0) -> List[SecurityBulletin]:
    """
    將一個 SecurityBulletin（含多個 CVE）展開為多筆輸出列。
    每筆各對應一個 CVE，共用 Bulletin、iFix、Fixpack 等欄位。
    只保留 CVSS >= min_cvss 的 CVE（CVSS=0 且 list severity=High/Critical 的也保留）。
    """
    rows = []

    for detail in bulletin.cve_details:
        if detail.cvss_score >= min_cvss or (
            detail.cvss_score == 0.0
            and bulletin._list_severity.lower() in {"high", "critical"}
        ):
            if detail.cvss_score > 0:
                severity = detail.severity or _severity_from_score(detail.cvss_score)
            else:
                severity = bulletin._list_severity

            row = SecurityBulletin(
                title=bulletin.title,
                bulletin_url=bulletin.bulletin_url,
                affected_versions=bulletin.affected_versions,
                cve_id=detail.cve_id,
                severity=severity,
                publish_date=bulletin.publish_date,
                cvss_score=detail.cvss_score,
                ifix_lts=bulletin.ifix_lts,
                ifix_lts_url=bulletin.ifix_lts_url,
                ifix_cd=bulletin.ifix_cd,
                ifix_cd_url=bulletin.ifix_cd_url,
                fixpack_lts=bulletin.fixpack_lts,
                fixpack_date_lts=bulletin.fixpack_date_lts,
                fixpack_cd=bulletin.fixpack_cd,
                fixpack_date_cd=bulletin.fixpack_date_cd,
            )
            rows.append(row)

    if not rows and bulletin._list_severity.lower() in {"high", "critical"}:
        rows.append(SecurityBulletin(
            title=bulletin.title,
            bulletin_url=bulletin.bulletin_url,
            affected_versions=bulletin.affected_versions,
            cve_id="",
            severity=bulletin._list_severity,
            publish_date=bulletin.publish_date,
            cvss_score=0.0,
            ifix_lts=bulletin.ifix_lts,
            ifix_lts_url=bulletin.ifix_lts_url,
            ifix_cd=bulletin.ifix_cd,
            ifix_cd_url=bulletin.ifix_cd_url,
            fixpack_lts=bulletin.fixpack_lts,
            fixpack_date_lts=bulletin.fixpack_date_lts,
            fixpack_cd=bulletin.fixpack_cd,
            fixpack_date_cd=bulletin.fixpack_date_cd,
        ))

    return rows
