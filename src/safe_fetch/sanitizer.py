"""Layer 2 sanitizer for claude-code-prompt-injection-gate.

Strips invisible Unicode (zero-width, bidi, control, NFKC), HTML
comments, script/style tags, white-on-white and off-screen CSS, base64
instruction payloads, fake LLM delimiters. Wraps the result in an
``<UNTRUSTED-WEB url="...">`` envelope and enforces a 20 KB hard length
cap.

Ported from timstarkk/mcp-safe-fetch (MIT, (c) 2025 Tim Stark).
Source pin: e82724c9b9535aff6c2cc102aa17abd16b726b96
Upstream:   https://github.com/timstarkk/mcp-safe-fetch

Bench (2026-05-21, M2 Max): 35.8 KB input -> 27 ms/call -> 1317 KB/s
on a representative HTML page with embedded zero-width + bidi noise.
Roughly 5% of typical WebFetch network latency; safe to leave on.

Stat keys use snake_case (zero_width_chars, hidden_elements, ...);
upstream uses camelCase. The behaviour is equivalent module-by-module
but key names diverge — convert when diffing upstream vs. this port.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from bs4 import BeautifulSoup, Comment

# ── public types ─────────────────────────────────────────────────────


@dataclass
class SanitizeResult:
    """Result of one sanitizer pass.

    ``content`` is the sanitized (and, for the html/text pipelines,
    wrapped) text. ``stats`` accumulates per-category counts — used by
    tests and by Layer-3 hooks to decide whether to surface a
    ``[FLAGGED]`` notice to the operator.
    """

    content: str
    input_size: int
    output_size: int
    stats: dict = field(default_factory=dict)


# ── configuration ────────────────────────────────────────────────────


LENGTH_CAP_BYTES = 20_480  # 20 KB hard cap on sanitizer output
MAX_BASE64_DECODE_LEN = 500


# ── unicode (mirrors src/sanitize/unicode.ts) ────────────────────────


INVISIBLE_CHARS = re.compile(r"[​‌‍‎‏⁠⁣﻿­]")  # nosec B613 — sanitizer pattern, deliberately contains the chars it strips
BIDI_CHARS = re.compile(r"[‪-‮⁦-⁩]")
VARIATION_SELECTORS = re.compile(r"[︀-️]")
UNICODE_TAGS = re.compile(r"[\U000e0001-\U000e007f]")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _unicode_stats_init() -> dict[str, int]:
    return {
        "zero_width_chars": 0,
        "control_chars": 0,
        "bidi_overrides": 0,
        "unicode_tags": 0,
        "variation_selectors": 0,
    }


def _strip_unicode(text: str) -> tuple[str, dict[str, int]]:
    stats = _unicode_stats_init()
    stats["zero_width_chars"] = len(INVISIBLE_CHARS.findall(text))
    stats["bidi_overrides"] = len(BIDI_CHARS.findall(text))
    stats["variation_selectors"] = len(VARIATION_SELECTORS.findall(text))
    stats["unicode_tags"] = len(UNICODE_TAGS.findall(text))
    stats["control_chars"] = len(CONTROL_CHARS.findall(text))

    text = INVISIBLE_CHARS.sub("", text)
    text = BIDI_CHARS.sub("", text)
    text = VARIATION_SELECTORS.sub("", text)
    text = UNICODE_TAGS.sub("", text)
    text = CONTROL_CHARS.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text, stats


# ── html (mirrors src/sanitize/html.ts) ──────────────────────────────


_HIDDEN_SELECTORS = ", ".join(
    [
        '[style*="display:none"]',
        '[style*="display: none"]',
        '[style*="visibility:hidden"]',
        '[style*="visibility: hidden"]',
        '[style*="opacity:0"]',
        '[style*="opacity: 0"]',
        "[hidden]",
    ]
)

_OFF_SCREEN_SELECTORS = ", ".join(
    [
        '[style*="text-indent"][style*="-999"]',
        '[style*="position:absolute"][style*="left:-"]',
        '[style*="position: absolute"][style*="left: -"]',
        '[style*="position:absolute"][style*="top:-"]',
        '[style*="position: absolute"][style*="top: -"]',
        '[style*="position:fixed"][style*="left:-"]',
        '[style*="position: fixed"][style*="left: -"]',
        '[style*="position:fixed"][style*="top:-"]',
        '[style*="position: fixed"][style*="top: -"]',
        '[style*="clip:rect(0"]',
        '[style*="clip: rect(0"]',
        '[style*="clip-path:inset(100"]',
        '[style*="clip-path: inset(100"]',
        '[style*="font-size:0"]',
        '[style*="font-size: 0"]',
    ]
)

_NAMED_COLORS = {
    "white": "#ffffff",
    "black": "#000000",
    "red": "#ff0000",
    "green": "#008000",
    "blue": "#0000ff",
    "yellow": "#ffff00",
    "cyan": "#00ffff",
    "magenta": "#ff00ff",
    "gray": "#808080",
    "grey": "#808080",
    "silver": "#c0c0c0",
    "maroon": "#800000",
    "olive": "#808000",
    "lime": "#00ff00",
    "aqua": "#00ffff",
    "teal": "#008080",
    "navy": "#000080",
    "fuchsia": "#ff00ff",
    "purple": "#800080",
    "orange": "#ffa500",
}

_STRIP_TAGS = ("script", "style", "noscript", "meta", "link")
_COLOR_RE = re.compile(r"(?:^|;)\s*color\s*:\s*([^;!]+)", re.IGNORECASE)
_BG_RE = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;!]+)", re.IGNORECASE)
_HEX3_RE = re.compile(r"^#([0-9a-f])([0-9a-f])([0-9a-f])$")
_HEX6_RE = re.compile(r"^#[0-9a-f]{6}$")
_RGB_RE = re.compile(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)")


def _normalize_color(value: str) -> str | None:
    v = value.strip().lower()
    if v in _NAMED_COLORS:
        return _NAMED_COLORS[v]
    m = _HEX3_RE.match(v)
    if m:
        return f"#{m.group(1) * 2}{m.group(2) * 2}{m.group(3) * 2}"
    if _HEX6_RE.match(v):
        return v
    m = _RGB_RE.match(v)
    if m:
        return "#" + "".join(f"{int(x):02x}" for x in m.groups())
    return None


def _empty_html_stats() -> dict[str, int]:
    return {
        "hidden_elements": 0,
        "html_comments": 0,
        "script_tags": 0,
        "style_tags": 0,
        "noscript_tags": 0,
        "meta_tags": 0,
        "off_screen_elements": 0,
        "same_color_text": 0,
    }


def _strip_html(soup: BeautifulSoup) -> dict[str, int]:
    stats = _empty_html_stats()

    hidden = soup.select(_HIDDEN_SELECTORS)
    stats["hidden_elements"] = len(hidden)
    for el in hidden:
        el.decompose()

    off_screen = soup.select(_OFF_SCREEN_SELECTORS)
    stats["off_screen_elements"] = len(off_screen)
    for el in off_screen:
        el.decompose()

    for el in soup.select("[style]"):
        style_attr = el.get("style", "")
        # BeautifulSoup may return list[str] for multi-valued attributes; we
        # only care about scalar style strings here.
        style = style_attr if isinstance(style_attr, str) else ""
        c_match = _COLOR_RE.search(style)
        bg_match = _BG_RE.search(style)
        if c_match and bg_match:
            fg = _normalize_color(c_match.group(1))
            bg = _normalize_color(bg_match.group(1))
            if fg and bg and fg == bg:
                stats["same_color_text"] += 1
                el.decompose()

    for tag in _STRIP_TAGS:
        elements = soup.find_all(tag)
        count = len(elements)
        if tag == "script":
            stats["script_tags"] = count
        elif tag == "style":
            stats["style_tags"] = count
        elif tag == "noscript":
            stats["noscript_tags"] = count
        elif tag in ("meta", "link"):
            stats["meta_tags"] += count
        for el in elements:
            el.decompose()

    comments = soup.find_all(string=lambda t: isinstance(t, Comment))
    stats["html_comments"] = len(comments)
    for c in comments:
        c.extract()

    return stats


# ── encoded / base64 / hex (mirrors src/sanitize/encoded.ts) ─────────


_INSTRUCTION_PATTERN = re.compile(
    r"\b(ignore|forget|disregard|override|you are now|new instruction|"
    r"system prompt|execute|eval\s*\(|import\s*\(|require\s*\(|"
    r"api.?key|password|secret|curl\s|wget\s|rm\s+-|sudo\s)",
    re.IGNORECASE,
)
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_PATTERN = re.compile(r"(?:0x|\\x)?(?:[0-9a-f]{2}[\s,;]?){20,}", re.IGNORECASE)
_DATA_URI_PATTERN = re.compile(r"data:text/[^;]*;base64,([A-Za-z0-9+/=]+)", re.IGNORECASE)


def _decode_base64_safe(s: str) -> str | None:
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _decode_hex_safe(s: str) -> str | None:
    hex_only = re.sub(r"[^0-9a-f]", "", s, flags=re.IGNORECASE)
    if len(hex_only) % 2:
        hex_only = hex_only[:-1]
    try:
        return bytes.fromhex(hex_only).decode("utf-8", errors="replace")
    except ValueError:
        return None


def _strip_encoded(text: str) -> tuple[str, dict[str, int]]:
    stats = {"base64_payloads": 0, "hex_payloads": 0, "data_uris": 0}

    def _data_uri_sub(_m: re.Match) -> str:
        stats["data_uris"] += 1
        return "[data-uri-removed]"

    text = _DATA_URI_PATTERN.sub(_data_uri_sub, text)

    max_len = int(MAX_BASE64_DECODE_LEN * 1.4)

    def _b64_sub(m: re.Match) -> str:
        match = m.group(0)
        if len(match) > max_len:
            return match
        decoded = _decode_base64_safe(match)
        if decoded and _INSTRUCTION_PATTERN.search(decoded):
            stats["base64_payloads"] += 1
            return "[encoded-removed]"
        return match

    text = _BASE64_PATTERN.sub(_b64_sub, text)

    def _hex_sub(m: re.Match) -> str:
        match = m.group(0)
        decoded = _decode_hex_safe(match)
        if decoded and _INSTRUCTION_PATTERN.search(decoded):
            stats["hex_payloads"] += 1
            return "[encoded-removed]"
        return match

    text = _HEX_PATTERN.sub(_hex_sub, text)
    return text, stats


# ── exfiltration urls in markdown (mirrors src/sanitize/exfiltration.ts) ─


_EXFIL_PARAM_NAMES = {"exfil", "data", "payload", "stolen", "leak", "extract", "dump"}
_MD_IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_B64_VALUE_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


def _is_suspicious_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if len(url) > 500:
        return True
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    qs_names = {n.lower() for n, _ in qs}
    if qs_names & _EXFIL_PARAM_NAMES:
        return True
    for _name, value in qs:
        if len(value) > 100:
            return True
        if _B64_VALUE_RE.match(value):
            return True
    return False


def _strip_exfiltration(text: str) -> tuple[str, dict[str, int]]:
    count = 0

    def _sub(m: re.Match) -> str:
        nonlocal count
        alt, url = m.group(1), m.group(2).strip()
        if _is_suspicious_url(url):
            count += 1
            return f"[image: {alt}]" if alt else "[image removed]"
        return m.group(0)

    return _MD_IMAGE_PATTERN.sub(_sub, text), {"exfiltration_urls": count}


# ── llm delimiter patterns (mirrors src/sanitize/delimiters.ts) ──────


# Pre-compiled so each pattern can carry its own flags. The first set is
# case-insensitive (chat-template delimiters); the Human:/Assistant: turn
# markers stay case-sensitive to match upstream and avoid catching prose.
_DELIMITER_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"<\|system\|>",
        r"<\|user\|>",
        r"<\|assistant\|>",
        r"<\|endoftext\|>",
        r"<\|pad\|>",
        r"\\?\[INST\\?\]",
        r"\\?\[\\?/INST\\?\]",
        r"<<SYS>>",
        r"<<\\?/SYS>>",
    )
] + [re.compile(p) for p in (r"\n\nHuman:", r"\n\nAssistant:")]


def _strip_delimiters(text: str) -> tuple[str, dict[str, int]]:
    count = 0
    for pat in _DELIMITER_PATTERNS:
        matches = pat.findall(text)
        if matches:
            count += len(matches)
            text = pat.sub("", text)
    return text, {"llm_delimiters": count, "custom_patterns": 0}


# ── envelope-breakout defense ───────────────────────────────────────
#
# After every other strip pass, neuter any literal <UNTRUSTED-*> or
# </UNTRUSTED-*> sequence in the content. Without this pass, an
# attacker who controls a fetched page can close our envelope mid-body
# and re-open it around forged "trusted" content the parent agent
# would then treat as outside-envelope instructions.
#
# This is the standard escape pattern (cf. HTML's `<script>` neutering
# in user-generated content). Once inner sequences are escaped, the
# outer wrap is monotonic — the attacker cannot break out regardless
# of whether the tag name itself is public knowledge. See
# https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle for the
# design rationale.
#
# Case-insensitive, attribute-tolerant. Matches:
#   <UNTRUSTED-WEB ...>, </UNTRUSTED-WEB>, <UNTRUSTED-SUBAGENT name="x">,
#   </UNTRUSTED-FILE>, <untrusted-anything> (any future variant).

_UNTRUSTED_TAG_RE = re.compile(
    r"</?\s*UNTRUSTED-[A-Z0-9_-]+(?:\s[^>]*)?\s*/?>",
    re.IGNORECASE,
)

_BREAKOUT_REDACTION = "[REDACTED-FAKE-DELIMITER]"


def _escape_untrusted_tags(text: str) -> tuple[str, dict[str, int]]:
    """Neuter literal UNTRUSTED-* tag sequences inside content.

    Returns the escaped text + a stat dict (count of replaced
    occurrences) so a breakout attempt shows up in the SanitizeResult
    stats and a future test or telemetry hook can flag spikes.
    """
    matches = _UNTRUSTED_TAG_RE.findall(text)
    if not matches:
        return text, {"breakout_attempts": 0}
    escaped = _UNTRUSTED_TAG_RE.sub(_BREAKOUT_REDACTION, text)
    return escaped, {"breakout_attempts": len(matches)}


# ── pipeline ─────────────────────────────────────────────────────────


_HTML_EXTENSIONS = {".html", ".htm", ".xhtml", ".svg"}
_HTML_CONTENT_RE = re.compile(r"^\s*(<(!DOCTYPE|html)\b)", re.IGNORECASE)


def looks_like_html(content: str, file_path: str | None = None) -> bool:
    """Detect HTML content by extension or doctype/root-element prefix."""
    if file_path:
        idx = file_path.rfind(".")
        if idx != -1 and file_path[idx:].lower() in _HTML_EXTENSIONS:
            return True
    return bool(_HTML_CONTENT_RE.match(content))


# The URL is an attacker-influenced value, so it gets output-encoded
# before interpolation into the envelope header (same hygiene as any
# templated attribute). Line-breaking / control chars are dropped so the
# header stays a single clean line: C0 (\x00-\x1f), DEL + C1
# (\x7f-\x9f, includes NEL \x85), and the Unicode line/paragraph
# separators (U+2028/U+2029).
_URL_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _sanitize_envelope_url(url: str) -> str:
    """Output-encode a fetched URL before placing it in the envelope header.

    Attacker-influenced values (the fetched URL included) are
    html-escaped and stripped of control characters before
    interpolation, so the value cannot alter the surrounding envelope
    structure. Standard output-encoding hygiene; keep it in lock-step
    with the wrap format in ``_wrap_untrusted``.
    """
    return html.escape(_URL_CONTROL_RE.sub("", url), quote=True)


def _wrap_untrusted(content: str, url: str) -> str:
    return f'<UNTRUSTED-WEB url="{_sanitize_envelope_url(url)}">\n{content}\n</UNTRUSTED-WEB>'


def _apply_length_cap(content: str) -> str:
    encoded = content.encode("utf-8")
    if len(encoded) <= LENGTH_CAP_BYTES:
        return content
    truncated = encoded[:LENGTH_CAP_BYTES].decode("utf-8", errors="ignore")
    return f"{truncated}\n\n[truncated: input exceeded {LENGTH_CAP_BYTES} bytes]"


def _empty_text_stats() -> dict[str, int]:
    return {
        "base64_payloads": 0,
        "hex_payloads": 0,
        "data_uris": 0,
        "exfiltration_urls": 0,
        "llm_delimiters": 0,
        "custom_patterns": 0,
        "breakout_attempts": 0,
    }


def sanitize_unicode(text: str) -> SanitizeResult:
    """Strip invisible Unicode and apply NFKC normalization. No wrap.

    Returns the cleaned text WITHOUT the untrusted-content envelope and
    WITHOUT the inner-tag escape pass. If you pass this output to a
    context that would treat it as trusted, you have re-opened the
    envelope-breakout vector. Use ``sanitize`` or ``sanitize_text`` for
    any flow that returns content to an agent.
    """
    input_size = len(text.encode("utf-8"))
    content, stats = _strip_unicode(text)
    return SanitizeResult(
        content=content,
        input_size=input_size,
        output_size=len(content.encode("utf-8")),
        stats=stats,
    )


def sanitize_text(text: str, url: str = "unknown://source") -> SanitizeResult:
    """Sanitize plain text (no HTML parse) and wrap in the untrusted envelope."""
    input_size = len(text.encode("utf-8"))

    content, u_stats = _strip_unicode(text)
    content, e_stats = _strip_encoded(content)
    content, x_stats = _strip_exfiltration(content)
    content, d_stats = _strip_delimiters(content)
    content, b_stats = _escape_untrusted_tags(content)

    wrapped = _wrap_untrusted(_apply_length_cap(content), url)
    return SanitizeResult(
        content=wrapped,
        input_size=input_size,
        output_size=len(wrapped.encode("utf-8")),
        stats={**_empty_html_stats(), **_empty_text_stats(), **u_stats, **e_stats, **x_stats, **d_stats, **b_stats},
    )


def sanitize(html: str, url: str = "unknown://source") -> SanitizeResult:
    """Sanitize HTML and wrap output in ``<UNTRUSTED-WEB url="...">``."""
    input_size = len(html.encode("utf-8"))

    if not html:
        wrapped = _wrap_untrusted("", url)
        return SanitizeResult(
            content=wrapped,
            input_size=input_size,
            output_size=len(wrapped.encode("utf-8")),
            stats={**_empty_html_stats(), **_unicode_stats_init(), **_empty_text_stats()},
        )

    soup = BeautifulSoup(html, "html.parser")
    h_stats = _strip_html(soup)

    content = soup.get_text(separator="\n", strip=False)

    content, u_stats = _strip_unicode(content)
    content, e_stats = _strip_encoded(content)
    content, x_stats = _strip_exfiltration(content)
    content, d_stats = _strip_delimiters(content)
    content, b_stats = _escape_untrusted_tags(content)

    wrapped = _wrap_untrusted(_apply_length_cap(content), url)
    return SanitizeResult(
        content=wrapped,
        input_size=input_size,
        output_size=len(wrapped.encode("utf-8")),
        stats={**h_stats, **u_stats, **e_stats, **x_stats, **d_stats, **b_stats},
    )
