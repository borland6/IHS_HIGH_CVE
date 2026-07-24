from dataclasses import dataclass, field
from typing import List


@dataclass
class CveDetail:
    """單一 CVE 的詳細資訊（從內頁 Vulnerability Details 解析）。"""
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = ""   # 由 cvss_score 計算：Critical>=9.0, High>=7.0


@dataclass
class SecurityBulletin:
    """
    IBM Security Bulletin 資料模型。
    一筆 = 一個 CVE（一篇 Bulletin 含多 CVE 時，展開為多筆輸出）。

    IBM HTTP Server 欄位說明：
      ifix_lts / fixpack_lts / fixpack_date_lts → V9（9.0.x.x）
      ifix_cd  / fixpack_cd  / fixpack_date_cd  → V8.5（8.5.x.x）
    """

    # 欄位 1：Security Bulletin 標題與連結
    title: str = ""
    bulletin_url: str = ""

    # 欄位 2：受影響版本（來自內頁 Affected Products and Versions）
    affected_versions: str = ""

    # 欄位 3：單一 CVE ID（展開後每筆一個）
    cve_id: str = ""

    # 欄位 4：Severity（由 CVSS 計算）
    severity: str = ""

    # 欄位 5：Publish Date（來自清單頁）
    publish_date: str = ""

    # 欄位 6：CVSS Base Score（來自內頁，各 CVE 各自的分數）
    cvss_score: float = 0.0

    # 欄位 7：iFix — V9 與 V8.5 各自的編號與連結
    ifix_lts: str = ""        # V9 iFix 編號（例如 "PH71670"）
    ifix_lts_url: str = ""
    ifix_cd: str = ""         # V8.5 iFix 編號（例如 "PH71671"）
    ifix_cd_url: str = ""

    # 欄位 8：Fixpack Version — V9 與 V8.5 各自的完整版本號
    fixpack_lts: str = ""     # V9 版本（例如 "9.0.5.28"）
    fixpack_cd: str = ""      # V8.5 版本（例如 "8.5.5.31"）

    # 欄位 9：Fixpack Release Date — V9 與 V8.5 各自的 targeted availability
    fixpack_date_lts: str = ""  # V9 日期（例如 "2026/06/24" 或 "3Q2026"）
    fixpack_date_cd: str = ""   # V8.5 日期

    # 內部欄位：來自清單頁的原始 severity（作為 fallback）
    _list_severity: str = ""

    # 內部欄位：Bulletin 包含的所有 CVE 詳細資訊（展開前使用）
    cve_details: List[CveDetail] = field(default_factory=list)
