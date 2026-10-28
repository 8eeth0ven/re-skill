"""Shared hostile-input boundaries. Never execute or deserialize sample code."""
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .errors import BudgetExceeded, Cancelled, IntegrityError, InvalidInput


SENSITIVE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[-_]?key|authorization|cookie|credential|private[-_]?key)"
)
_assign = re.compile(
    r"(?im)(\b(?:password|passwd|secret|token|api[-_]?key|authorization|cookie|http_passwd|admin_password)"
    r"\b(?>\s*[\"']?\s*)[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\r\n]+)"
)
# F3 complexity audit (all handlers below must stay linear in hostile output
# size). The (?>...) atomic group above is match-for-match with the old
# \s*["']?\s*: the [: =] literal can only ever be tried at the end of the
# whitespace run (or once after its single optional quote), no matter how many
# characters \s* gives back, so committing the greedy path changes no match
# while removing the O(gap^2) nested backtracking that let "password" plus
# ~500 KB of spaces stall the main process (16 KB gap already cost 0.9 s).
# The PEM block is matched by two anchored sub-patterns (see
# _redact_private_keys): the old single BEGIN.*?END regex swept the lazy .*?
# all the way to the end of the text for every complete BEGIN header that had
# no END, i.e. O(headers x text) — quadratic (0.36 s at 54 KB, 4x per doubling).
_pem_head = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
_pem_tail = re.compile(r"-----END [^-\r\n]*PRIVATE KEY-----")
_reserved = re.compile(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)")

# Character classes for the linear-time email scan (see _redact_emails).
_ASCII_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_LOCAL_EXTRAS = frozenset(".+-")  # old local-part class was [\w.+-]
_DOMAIN_EXTRAS = frozenset(".-")  # old domain run class was [\w.-]
_ASCII_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_WORD_CHAR = re.compile(r"\w")  # exact per-char fallback for non-ASCII \w
_CONTROL_STRIP: dict[int, None] | None = None


def _strip_control_chars(text: str) -> str:
    """C-speed equivalent of the per-character filter
    ``c in "\\n\\t" or (ord(c) >= 32 and unicodedata.category(c) != "Cf")``.

    str.translate drops the forbidden codepoints in one C pass (2 ms at 4 MiB
    versus 0.9 s for the generator join). The table is built once per process
    from unicodedata so it can never drift from the category check.
    """
    global _CONTROL_STRIP
    table = _CONTROL_STRIP
    if table is None:
        table = {code: None for code in range(32) if code not in (9, 10)}
        for code in range(32, 0x110000):
            if unicodedata.category(chr(code)) == "Cf":
                table[code] = None
        _CONTROL_STRIP = table
    return text.translate(table)


def _is_local_char(char: str) -> bool:
    """Exact ``[\\w.+-]`` test (Unicode-aware \\w) with an ASCII fast path."""
    return char in _ASCII_WORD or char in _LOCAL_EXTRAS or (
        ord(char) > 127 and _WORD_CHAR.fullmatch(char) is not None
    )


def _is_domain_char(char: str) -> bool:
    """Exact ``[\\w.-]`` test (Unicode-aware \\w) with an ASCII fast path."""
    return char in _ASCII_WORD or char in _DOMAIN_EXTRAS or (
        ord(char) > 127 and _WORD_CHAR.fullmatch(char) is not None
    )


def _redact_emails(text: str) -> str:
    """Replace email-like spans with "[REDACTED EMAIL]", match-for-match with
    the previous ``re.sub(r"[\\w.+-]+@[\\w.-]+\\.[A-Za-z]{2,}", ...)`` but in
    linear time. The old pattern was quadratic on long word runs without "@":
    its unbounded ``[\\w.+-]+`` re-scanned the whole remaining run from every
    start position (1 MiB of "A" meant hours; 64 KB already cost 26 s). This
    scan anchors on "@" (C-level str.find, one pass even when no "@" exists)
    and only walks the character runs adjacent to each "@"; runs between
    "@"/non-word boundaries are disjoint, so total work stays linear.

    Semantics kept identical: the local part is the longest run of ``[\\w.+-]``
    ending right before "@" within the scan window (the regex engine cannot
    start before the previous match end, so `scan` is the floor); the domain is
    the ``[\\w.-]`` run after "@" with its rightmost dot that has at least two
    ASCII letters after it (the greedy ``[\\w.-]+\\.[A-Za-z]{2,}`` backtracking
    order), then the letter tail extends greedily.
    """
    length = len(text)
    pieces: list[str] = []
    pos = scan = 0
    while (at := text.find("@", scan)) >= 0:
        # The local part needs >= 1 char before "@", and the engine can never
        # match before the previous match end / failure point (scan).
        if at == scan or not _is_local_char(text[at - 1]):
            scan = at + 1
            continue
        start = at
        while start > scan and _is_local_char(text[start - 1]):
            start -= 1
        stop = at + 1
        while stop < length and _is_domain_char(text[stop]):
            stop += 1
        # Rightmost dot in the domain run with two ASCII letters after it, then
        # a greedy letter tail (letters sit inside the run, so it ends <= stop).
        end = -1
        dot = stop - 1
        while dot >= at + 2:
            if (
                text[dot] == "." and dot + 2 < length
                and text[dot + 1] in _ASCII_LETTERS and text[dot + 2] in _ASCII_LETTERS
            ):
                end = dot + 3
                while end < length and text[end] in _ASCII_LETTERS:
                    end += 1
                break
            dot -= 1
        if end < 0:
            scan = at + 1  # the right side fails identically from every start
            continue
        pieces.append(text[pos:start])
        pieces.append("[REDACTED EMAIL]")
        pos = scan = end
    if not pieces:
        return text
    pieces.append(text[pos:])
    return "".join(pieces)


def _redact_private_keys(text: str) -> str:
    """Replace PEM private-key blocks with "[REDACTED PRIVATE KEY]",
    match-for-match with the previous single ``BEGIN.*?END`` regex (re.S) for
    every *complete* pair, but in linear time (see the _pem_* comment for the
    quadratic behavior it replaces). The lazy ``.*?`` means: take the leftmost
    complete BEGIN header and the first "-----END " occurrence after it whose
    tail completes; the find() anchors enumerate exactly those candidate
    positions at C speed.

    R3 conservative boundary rule: when a private-key BEGIN header has no
    completing END anywhere after it — which is exactly what a truncated
    buffer looks like when the END marker fell beyond the truncation point —
    the header and everything up to the end of the text is redacted instead of
    being kept verbatim. Dropping a tail cannot prove the retained prefix is
    free of key material, so an unclosed private-key block is treated as key
    material by definition. This intentionally breaks character-equality with
    the old unsafe oracle for the unclosed case only; complete pairs still
    match the old behavior exactly.
    """
    pieces: list[str] = []
    pos = search_from = 0
    while (begin := text.find("-----BEGIN ", search_from)) >= 0:
        head = _pem_head.match(text, begin)
        if head is None:
            search_from = begin + 1  # malformed header; find() still covers overlapping dashes
            continue
        body = head.end()
        while True:
            end = text.find("-----END ", body)
            if end < 0:
                # Unclosed private-key header (possibly truncated mid-block):
                # conservatively redact from the header to the end of the text.
                pieces.append(text[pos:begin])
                pieces.append("[REDACTED PRIVATE KEY]")
                return "".join(pieces)
            tail = _pem_tail.match(text, end)
            if tail is not None:
                break
            body = end + 1  # END literal without a completing tail; keep scanning
        pieces.append(text[pos:begin])
        pieces.append("[REDACTED PRIVATE KEY]")
        pos = search_from = tail.end()
    return text if not pieces else "".join(pieces) + text[pos:]


def redact_text(text: str) -> str:
    # F3: every rewrite below is linear-time and keeps the old match semantics.
    text = _redact_private_keys(text)
    text = _assign.sub(r"\1[REDACTED]", text)
    # Linear: "Bearer" is a literal gated prefix; \s+ backtracking covers one
    # whitespace gap and the trailing class has no tail to backtrack into.
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    # Linear: literal "AKIA" gates each start; {16} is fixed-width, so a failed
    # \b cannot force backtracking through it.
    text = re.sub(r"\bAKIA[A-Z0-9]{16}\b", "[REDACTED ACCESS KEY]", text)
    # Linear: branch first chars {g, s} gate every start; a failed \b only
    # backtracks its own {20,}/{16,} run and such runs are mutually disjoint.
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,})\b", "[REDACTED TOKEN]", text)
    text = _redact_emails(text)
    # Remove controls/bidi that could disguise a report's displayed meaning.
    return _strip_control_chars(text)


# Bounded tail scrub for stream-cut buffers (R3). When a reader stops at a byte
# cap, a sensitive token can straddle the cut: its head sits at the end of the
# retained buffer and its tail was dropped, so the full-shape patterns above
# (fixed {16}/{20,} widths) legitimately fail to match a partial token. The cut
# point is a single position, so a constant-size anchored tail check is both
# complete for this case and O(1).
_TAIL_PARTIAL = re.compile(
    r"(?s)(\bAKIA[A-Z0-9]{1,15}|\b(?:gh[pousr]_[A-Za-z0-9_]{1,19}|sk-[A-Za-z0-9_-]{1,15})|"
    r"-----BEGIN [^-\r\n]{0,64}$)\Z"
)


def redact_text_truncated(text: str) -> str:
    """Redact a buffer whose tail was cut mid-stream at a byte boundary.

    Applies the normal linear redaction, then conservatively redacts a partial
    sensitive token that ends exactly at the cut (AKIA/TOKEN heads shorter than
    the full-shape minimum, or a cut PEM header fragment). Complete tokens and
    complete/private-key pairs are handled identically by redact_text; only the
    straddling head needs the extra rule.
    """
    result = redact_text(text)
    window = min(len(result), 96)
    tail = result[len(result) - window:]
    scrubbed = _TAIL_PARTIAL.sub("[REDACTED PARTIAL TOKEN AT OUTPUT BOUNDARY]", tail)
    if scrubbed != tail:
        return result[:len(result) - window] + scrubbed
    return result


def public_url(url: str) -> str:
    try:
        p = urlsplit(url)
        if p.scheme not in ("http", "https", "ws", "wss", "grpc", "grpcs"):
            return redact_text(url)
        host = p.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if p.port:
            host += f":{p.port}"
        # Query values frequently carry PII even when their names do not mention a secret.
        query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(p.query, keep_blank_values=True)])
        return urlunsplit((p.scheme, host, p.path, query, ""))
    except ValueError:
        return "[INVALID URL]"


def redact(value: Any, key: str = "") -> Any:
    if SENSITIVE.search(key) and key not in ("secret_count", "credentials_present"):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {redact_text(str(k)): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://", "ws://", "wss://", "grpc://", "grpcs://")):
            return public_url(value)
        return redact_text(value)
    return value


def markdown_text(value: Any) -> str:
    text = redact_text(str(value))
    # Asset text cannot introduce active Markdown, images, links, or new headings.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*{}\[\]()#+.!_|~-])", r"\\\1", text).replace("\n", " ")


def regular_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise InvalidInput(f"Not a regular file (links/devices rejected): {path.name}")
    return info


def open_regular(path: Path) -> BinaryIO:
    before = regular_file(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    after = os.fstat(fd)
    if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd)
        raise IntegrityError(f"File changed while opening: {path.name}")
    return os.fdopen(fd, "rb")


def read_bytes(path: Path, limit: int) -> bytes:
    with open_regular(path) as stream:
        if os.fstat(stream.fileno()).st_size > limit:
            raise BudgetExceeded(f"File exceeds {limit} byte input limit: {path.name}")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise BudgetExceeded(f"File grew beyond input limit: {path.name}")
    return value


def sha256_file(path: Path, budget=None) -> str:
    digest = hashlib.sha256()
    with open_regular(path) as stream:
        expected = os.fstat(stream.fileno()).st_size
        count = 0
        for block in iter(lambda: stream.read(65536), b""):
            if budget:
                budget.check()
            count += len(block)
            if count > expected:
                raise IntegrityError("File grew while computing its hash")
            digest.update(block)
        if count != expected:
            raise IntegrityError("File shrank while computing its hash")
    return digest.hexdigest()


def reject_json_constants(value: str) -> None:
    raise InvalidInput(f"Non-finite JSON value: {value}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput(f"Duplicate JSON key: {key[:80]}")
        result[key] = value
    return result


def parse_json(data: bytes | str) -> Any:
    try:
        result = json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=reject_json_constants)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidInput(f"Malformed JSON: {type(exc).__name__}") from exc
    # An iterative shape budget also bounds later redaction/reporting recursion.
    stack, count = [(result, 0)], 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 48:
            raise BudgetExceeded("JSON object/depth budget exceeded")
        if isinstance(value, float) and not math.isfinite(value):
            raise InvalidInput("Non-finite JSON number")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return result


def load_json(path: Path, max_bytes: int = 16_777_216) -> Any:
    return parse_json(read_bytes(path, max_bytes))


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise IntegrityError(f"Refusing to replace linked state: {path.name}")
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def atomic_json(path: Path, value: Any) -> None:
    atomic_write(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))


def contained(root: Path, path: Path) -> Path:
    resolved_root, resolved_path = root.resolve(), path.resolve()
    if not resolved_path.is_relative_to(resolved_root):
        raise IntegrityError("Artifact path escapes run directory")
    current = path.absolute()
    while current != root.absolute() and current.is_relative_to(root.absolute()):
        if current.is_symlink() or (
            current.exists() and getattr(current.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise IntegrityError("Artifact path contains a link/reparse point")
        current = current.parent
    return resolved_path


def safe_relative(name: str, max_depth: int = 16) -> str:
    name = unicodedata.normalize("NFC", name)
    while name.startswith("./"):
        name = name[2:]
    if not name or len(name) > 1024 or "\\" in name or "\x00" in name:
        raise InvalidInput("Unsafe archive path")
    path = PurePosixPath(name)
    parts = name.rstrip("/").split("/")
    if path.is_absolute() or len(parts) > max_depth:
        raise InvalidInput("Absolute/deep archive path rejected")
    if any(
        p in ("", ".", "..") or ":" in p or p.endswith((" ", ".")) or _reserved.match(p)
        or any(ord(c) < 32 or c in '<>"|?*' or unicodedata.category(c) == "Cf" for c in p)
        for p in parts
    ):
        raise InvalidInput("Traversal, ambiguous or platform-unsafe archive path rejected")
    return "/".join(parts)


class Budget:
    def __init__(
        self, limits: dict[str, int], cancel_path: Path | None = None, usage_path: Path | None = None,
        wall_deadline_epoch: float | None = None,
    ):
        self.limits = limits
        self.started = time.monotonic()
        # An absolute epoch deadline lets the wall budget survive cancel/resume cycles;
        # without one the clock restarts at construction (historical behavior).
        self.wall_deadline_epoch = wall_deadline_epoch
        # Settlement mode: after a stop condition fired, the Runner's bookkeeping
        # segment must still record artifacts and real usage completely. Only the
        # Runner/adapter post-process settlement segments may set this, never new dispatches.
        self.settling = False
        self.cancel_path = cancel_path
        self.usage_path = usage_path
        self.used: dict[str, int] = {"input_bytes": 0, "download_bytes": 0, "unpack_bytes": 0, "files": 0, "requests": 0}
        if usage_path:
            atomic_json(usage_path, self.used)

    def wall_remaining(self) -> float:
        if self.wall_deadline_epoch is not None:
            return self.wall_deadline_epoch - time.time()
        return self.limits["max_wall_seconds"] - (time.monotonic() - self.started)

    def check(self) -> None:
        if self.settling:
            return
        if self.cancel_path and self.cancel_path.exists():
            raise Cancelled("Cancellation requested")
        if self.wall_remaining() < 0:
            raise BudgetExceeded("Run wall-time budget exceeded")

    def consume(self, key: str, amount: int) -> None:
        if not self.settling:
            self.check()
        self.used[key] = self.used.get(key, 0) + amount
        if self.usage_path:
            atomic_json(self.usage_path, self.used)
        if not self.settling and self.used[key] > self.limits[f"max_{key}"]:
            raise BudgetExceeded(f"{key} budget exceeded")
