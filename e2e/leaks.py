"""One canary detector, used by every leakage assertion in the suite.

It looks for each canary in the bytes as captured and in these re-encodings:
case changes, percent-encoding, JSON \\uXXXX escapes, base64 and hex runs, and,
for the numeric canaries, digits regrouped with separators or rewritten without
the decimal point or in scientific notation.

It cannot see a canary that was compressed, encrypted, hashed, split across two
captures, truncated, or rounded.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from decimal import Decimal

_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_DIGIT_SEPARATOR = re.compile(r"(?<=\d)[,_  '](?=\d)")
_NUMBER = re.compile(r"^\d+(\.\d+)?$")


def _needles(canary: str) -> set[str]:
    needles = {canary.casefold()}
    if _NUMBER.match(canary):
        value = Decimal(canary)
        digits = "".join(str(d) for d in value.as_tuple().digits)
        needles.add(digits)
        needles.add(canary.split(".")[0])
        needles.add(f"{digits[0]}.{digits[1:]}e")
    return needles


def _views(text: str) -> list[tuple[str, str]]:
    views = [("plain", text)]
    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        views.append(("percent", unquoted))
    unescaped = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    if unescaped != text:
        views.append(("json-escape", unescaped))
    regrouped = _DIGIT_SEPARATOR.sub("", text)
    if regrouped != text:
        views.append(("regrouped", regrouped))
    decoded = []
    for run in _BASE64_RUN.findall(text):
        body = run.rstrip("=")
        # A run can start part way into a base64 word, so try all four alignments.
        for offset in range(4):
            piece = body[offset:]
            piece = piece[: len(piece) - (len(piece) % 4 == 1)]
            try:
                raw = base64.b64decode(piece.replace("-", "+").replace("_", "/") + "=" * (-len(piece) % 4))
            except (binascii.Error, ValueError):
                continue
            decoded.append(raw.decode("utf-8", "replace"))
    if decoded:
        views.append(("base64", "\n".join(decoded)))
    hexed = [bytes.fromhex(run).decode("utf-8", "replace") for run in _HEX_RUN.findall(text)]
    if hexed:
        views.append(("hex", "\n".join(hexed)))
    return views


def find(data: bytes, canaries: tuple[str, ...]) -> list[tuple[str, str]]:
    """Return sorted (canary, view) pairs for every canary visible in data."""
    text = data.decode("utf-8", "replace")
    hits = set()
    for view, body in _views(text):
        folded = body.casefold()
        for canary in canaries:
            if any(needle in folded for needle in _needles(canary)):
                hits.add((canary, view))
    return sorted(hits)
