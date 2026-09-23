"""Small expression language for attribute values, evaluated per session.

Templates must be rendered once per session rather than once per job: a value
referencing $MAC$ would otherwise freeze to whichever endpoint happened to be
generated first.

Variables   $MAC$ $IP$ $SESSION$ $INDEX$ $SSID$
Functions   uc(x) lc(x) hex(x) rand(a..b) pad(x,n)

    uc(hex(rand(4096..65535)))/uc($MAC$)/uc(hex(rand(4096..65535)))
    -> 1A2B/00-11-22-33-44-55/C3D4
"""

from __future__ import annotations

import random
import re

_CALL = re.compile(r"(uc|lc|hex|rand|pad)\(")
_RANGE = re.compile(r"^\s*(\d+)\s*\.\.\s*(\d+)\s*$")


class TemplateError(ValueError):
    pass


def _split_args(text: str) -> list[str]:
    """Split on commas that are not inside nested parentheses."""
    out, depth, current = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(current)
            current = ""
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        current += ch
    out.append(current)
    return out


def _apply(name: str, args: list[str]) -> str:
    if name == "rand":
        match = _RANGE.match(args[0])
        if not match:
            raise TemplateError(f"rand() expects a..b, got {args[0]!r}")
        low, high = int(match.group(1)), int(match.group(2))
        if low > high:
            raise TemplateError(f"rand({low}..{high}) has an empty range")
        return str(random.randint(low, high))
    if len(args) < 1:
        raise TemplateError(f"{name}() needs an argument")
    value = args[0]
    if name == "uc":
        return value.upper()
    if name == "lc":
        return value.lower()
    if name == "hex":
        try:
            return format(int(value), "x")
        except ValueError:
            return value.encode().hex()
    if name == "pad":
        if len(args) < 2:
            raise TemplateError("pad() needs a width")
        return value.rjust(int(args[1]), "0")
    raise TemplateError(f"unknown function {name}()")


def _eval(text: str) -> str:
    """Resolve function calls innermost-first."""
    for _ in range(50):                       # templates do not nest deeply
        match = None
        for candidate in _CALL.finditer(text):
            inner = text[candidate.end():]
            if not _CALL.search(inner.split(")")[0] + ")"):
                match = candidate
                break
        if match is None:
            match = _CALL.search(text)
        if match is None:
            return text
        depth, end = 1, match.end()
        while end < len(text) and depth:
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
            end += 1
        if depth:
            raise TemplateError("unbalanced parentheses")
        body = text[match.end():end - 1]
        if _CALL.search(body):
            body = _eval(body)
        replaced = _apply(match.group(1), _split_args(body))
        text = text[:match.start()] + replaced + text[end:]
    raise TemplateError("template too deeply nested")


def render(text: str, **context) -> str:
    """Render one template against a single session's values."""
    if not text:
        return text
    for key, value in context.items():
        # str(value or "") would turn index 0 into an empty string.
        text = text.replace(f"${key.upper()}$",
                            "" if value is None else str(value))
    if not _CALL.search(text):
        return text
    return _eval(text)


def is_template(text: str) -> bool:
    return bool(text) and ("$" in text or bool(_CALL.search(text)))
