from __future__ import annotations

import re
import unicodedata
from functools import lru_cache


class PatternError(ValueError):
    pass


def normalize_relative_path(value: str) -> str:
    value = unicodedata.normalize("NFC", value)
    if not value or value == ".":
        raise PatternError("paths must not be empty")
    if value.startswith("/") or "\x00" in value or "\\" in value:
        raise PatternError(f"invalid POSIX-relative path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PatternError(f"path traversal or empty segment is not allowed: {value!r}")
    return value


def normalize_pattern(value: str) -> str:
    if not isinstance(value, str):
        raise PatternError("patterns must be strings")
    value = unicodedata.normalize("NFC", value.strip())
    if not value or value.startswith("/") or "\x00" in value or "\\" in value:
        raise PatternError(f"invalid POSIX-relative pattern: {value!r}")
    if value.startswith("!"):
        raise PatternError("negated patterns are not supported; use the deny list")
    literal_parts = [part for part in value.split("/") if not _contains_magic(part)]
    if any(part in {"", ".", ".."} for part in literal_parts):
        raise PatternError(f"invalid pattern segment: {value!r}")
    if "//" in value or value.endswith("/"):
        raise PatternError(f"empty pattern segments are not allowed: {value!r}")
    return value


def _contains_magic(segment: str) -> bool:
    return any(char in segment for char in "*?[")


def _translate_character_class(pattern: str, start: int) -> tuple[str, int]:
    end = start + 1
    if end < len(pattern) and pattern[end] in "!^":
        end += 1
    if end < len(pattern) and pattern[end] == "]":
        end += 1
    while end < len(pattern) and pattern[end] != "]":
        end += 1
    if end >= len(pattern):
        return r"\[", start + 1
    content = pattern[start + 1 : end]
    if content.startswith("!"):
        content = "^" + content[1:]
    elif content.startswith("^"):
        content = "\\" + content
    content = content.replace("\\", r"\\")
    return f"[{content}]", end + 1


def _translate_core(pattern: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    output.append(r"(?:.*/)?")
                    index += 1
                else:
                    output.append(".*")
                continue
            output.append(r"[^/]*")
        elif char == "?":
            output.append(r"[^/]")
        elif char == "[":
            translated, index = _translate_character_class(pattern, index)
            output.append(translated)
            continue
        else:
            output.append(re.escape(char))
        index += 1
    return "".join(output)


@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> re.Pattern[str]:
    pattern = normalize_pattern(pattern)
    if pattern.endswith("/**"):
        base = pattern[:-3]
        translated = _translate_core(base)
        return re.compile(rf"^{translated}(?:/.*)?$")
    return re.compile(rf"^{_translate_core(pattern)}$")


def matches(path: str, pattern: str) -> bool:
    path = normalize_relative_path(path)
    return compile_pattern(pattern).fullmatch(path) is not None


def matches_any(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(matches(path, pattern) for pattern in patterns)

