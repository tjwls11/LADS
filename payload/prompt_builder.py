from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


# 프롬프트 템플릿 파일 읽음
@lru_cache(maxsize=None)
def _load_prompt(name: str) -> str:
    path = PROMPT_DIR / name
    return path.read_text(encoding="utf-8").strip()


# 템플릿 파일이 없을 때 기본 문구 반환
def _load_prompt_or_default(name: str, default: str) -> str:
    try:
        return _load_prompt(name)
    except FileNotFoundError:
        return default.strip()


SYSTEM_PROMPT = _load_prompt_or_default(
    "common.txt",
    """
    You are a payload mutation assistant for authorized defensive web security testing.
    Output only TYPE | PATTERN_FAMILY | PAYLOAD lines.
    """,
)


# 취약점 분류에 맞는 mutation 방향 프롬프트 선택
def _select_type_prompt(vuln_type: str) -> str:
    vt = (vuln_type or "").lower()
    if vt.startswith("sqli_"):
        return _load_prompt_or_default("sqli_mutation.txt", "Preserve SQL injection intent.")
    if vt.startswith("xss_"):
        return _load_prompt_or_default("xss_mutation.txt", "Preserve XSS intent.")
    return "Preserve the vulnerability intent from the baseline payloads."


# LLM에 전달할 구조적 입력 컨텍스트 추출
def _build_structural_context(point: dict[str, Any]) -> dict[str, Any]:
    list_keys = {"value_examples", "options", "option_examples", "url_examples"}
    keys = [
        "group_key",
        "param",
        "location",
        "method",
        "field_type",
        "value_shape",
        "enctype",
        "base_value",
        "value_examples",
        "options",
        "option_examples",
        "url_examples",
        "db",
        "note",
    ]
    return {key: point.get(key, [] if key in list_keys else "") for key in keys}


# baseline payload 목록을 행 단위 텍스트로 변환
def _format_baseline_payloads(baseline_payloads: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for idx, item in enumerate(baseline_payloads, start=1):
        ptype = str(item.get("type") or "UNKNOWN").upper()
        family = str(item.get("family") or f"baseline_{idx}")
        payload = str(item.get("payload") or "")
        if not payload:
            continue
        lines.append(f"{idx}. {ptype} | {family} | {payload}")
    return "\n".join(lines) if lines else "No baseline payloads were provided."


# 구조적 컨텍스트와 baseline payload를 조립해 최종 user prompt 생성
def build_mutation_prompt(
    point: dict[str, Any],
    vuln_type: str,
    baseline_payloads: list[dict[str, Any]],
    count: int = 7,
) -> str:
    type_prompt = _select_type_prompt(vuln_type)
    context_json = json.dumps(_build_structural_context(point), ensure_ascii=False, indent=2)
    baseline_text = _format_baseline_payloads(baseline_payloads)

    return f"""Mutation direction:
{type_prompt}

Vulnerability type:
{vuln_type}

Structural context:
{context_json}

Baseline payloads:
{baseline_text}

Task:
Generate {count} context-adapted mutations from the baseline payloads.
Keep the same attack intent as the baseline payloads.
Do not introduce unrelated payload families.
Prefer variants that can survive the shown location, method, field_type, value_shape, and enctype.

Output format:
TYPE | PATTERN_FAMILY | PAYLOAD"""
