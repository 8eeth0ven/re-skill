"""F3 regressions: redaction must be complexity-bounded and semantically identical.

The original implementations contained three quadratic patterns reachable from
tool output: the email regex (unbounded local-part backtracking), the PEM
regex (lazy sweep per BEGIN header without END) and the _assign whitespace gap
(nested \\s* backtracking). Each scale test below re-creates the hostile input
at a size the old code could not finish and asserts the new code stays under
one second; every equivalence test compares against the ORIGINAL regexes kept
here as oracles, so a semantic drift in the rewrite fails loudly.
"""
import random
import re
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
from pathlib import Path

from re_runner.contracts import BUDGET_DEFAULTS
from re_runner.execution import REDACT_HARD_CAP_CHARS, _settle_output, run_command
from re_runner.safety import Budget, redact_text, redact_text_truncated


# Oracles: the pre-F3 production regexes, copied verbatim. Only ever applied to
# small strings (the first and third are quadratic by design).
OLD_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
OLD_PEM = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----", re.S)
# R3 safety amendment: an unclosed private-key BEGIN (exactly what a truncated
# buffer with the END beyond the cut looks like) is now conservatively redacted
# from the header to the end of the text. Character-equality with the old
# unsafe behavior is intentionally NOT preserved for this case.
UNCLOSED_PEM = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*", re.S)
OLD_ASSIGN = re.compile(
    r"(?im)(\b(?:password|passwd|secret|token|api[-_]?key|authorization|cookie|http_passwd|admin_password)"
    r"\b\s*[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\r\n]+)"
)


def oracle_redact(text: str) -> str:
    text = OLD_PEM.sub("[REDACTED PRIVATE KEY]", text)
    text = UNCLOSED_PEM.sub("[REDACTED PRIVATE KEY]", text)
    text = OLD_ASSIGN.sub(r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"\bAKIA[A-Z0-9]{16}\b", "[REDACTED ACCESS KEY]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,})\b", "[REDACTED TOKEN]", text)
    text = OLD_EMAIL.sub("[REDACTED EMAIL]", text)
    return "".join(c for c in text if c in "\n\t" or (ord(c) >= 32 and unicodedata.category(c) != "Cf"))


EMAIL_SAMPLES = [
    "", "plain text no email", "@", "@@", "@a", "a@", "a@b", "a@b.c", "a@b.co",
    "user@example.com", "USER@EXAMPLE.COM", "a@b.com and c@d.org", "a@b.com,c@d.org",
    "alice.smith+tag@sub.example.co.uk", "a@b.c.d", "a@.com", "a@b..com", "a@b.com.",
    ".a@b.com", "-a@b.com", "+a@b.com", "a_b-c@d.io", "1@2.tv", "中文字@例え.jp",
    "用户@example.com", "mailto:user@ex.com/x", "https://ex.test/?mail=bob@ex.com",
    "[click](mailto:carol@ex.com)", ">quoted dave@ex.com", "`code erin@ex.com`",
    "**frank@g.h**", "a@b.com@c.com", "a@b.co.uk", "x a@b.com y", "contact zoe@ex.io.",
    "at@no.end", "double@@at.com", "space @ space.com", "a@ex.com\nb@ex.com\r\n",
    "password: gina@ex.com", "Bearer abc hunter@ex.com",
]

PEM_SAMPLES = [
    "",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowABCdef\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\r\nMIIEow\r\n-----END PRIVATE KEY-----",
    "a@b.com\n-----BEGIN PRIVATE KEY-----\n" + "z" * 60,
    "-----BEGIN PRIVATE KEY-----\n" + "z" * 60 + "\n-----END PRIVATE KEY-----\ntail a@b.com",
    "-----END PRIVATE KEY----- before any begin",
    "-----BEGIN PRIVATE KEY----- with no end at all",
    "-----BEGIN FOO-----\n-----END BAR PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY--------END PRIVATE KEY-----",
    "------BEGIN PRIVATE KEY------ overlong dashes",
    "-----BEGIN -----BEGIN PRIVATE KEY----------END PRIVATE KEY-----",
    "PRIVATE KEY----------BEGIN -----BEGIN PRIVATE KEY-----PRIVATE KEY-----MIIE-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nmid\n-----END BAD-----\n-----END GOOD PRIVATE KEY-----",
    "one -----BEGIN PRIVATE KEY----- x -----END EC PRIVATE KEY----- two "
    "-----BEGIN EC PRIVATE KEY----- y -----END PRIVATE KEY----- tail",
]

ASSIGN_SAMPLES = [
    "password: v", "password : v", "password\t=\tv", "password = 'v'", 'password = "v"',
    "password: v with spaces", "password:v", "password=:x", "password=", "password: ",
    "PASSWORD: UPPER", "Password : Mixed", "passwd = p", "secret: s", "token: t",
    "api_key: v", "api-key: v", "apikey: v", "api_key=v", "authorization: Bearer t",
    "cookie: session=abc", "credential: c", "private_key: k", "private-key: k",
    "http_passwd = p", "admin_password: p", "my_password: p", "PASSWORDS: plural",
    "password\n:\nx", "password\n  \t:  x", "password \" : x", "password ' : x",
    "password\"x: y", "password'x: y", "password: a,b;c", "password: \"unterminated",
    "password: " + "x" * 40, "password" + " " * 200 + ": v", "password" + " " * 200,
    "password\n\n  \n: after newlines", "token=abc123def", "user@ex.com password: p",
]

PEM_FUZZ_PARTS = ["-----BEGIN ", "-----END ", "PRIVATE KEY-----", "RSA", "EC", "x", "\n", "-", " ", "MIIE"]
ASSIGN_FUZZ_PARTS = ["password", "token", "key", " ", "\n", "\t", ":", "=", "'", '"', "v", ",", ";", "api-", "cookie"]


class EquivalenceTests(unittest.TestCase):
    def assert_oracle(self, samples):
        for text in samples:
            with self.subTest(text=text[:60]):
                self.assertEqual(redact_text(text), oracle_redact(text))

    def test_email_samples_match_old_regex(self):
        self.assert_oracle(EMAIL_SAMPLES)

    def test_pem_samples_match_old_regex(self):
        self.assert_oracle(PEM_SAMPLES)

    def test_assign_samples_match_old_regex(self):
        self.assert_oracle(ASSIGN_SAMPLES)

    def test_email_sample_expectations(self):
        self.assertEqual(redact_text("user@example.com"), "[REDACTED EMAIL]")
        self.assertEqual(redact_text("mail a@b.co.uk and c@d.org"), "mail [REDACTED EMAIL] and [REDACTED EMAIL]")
        self.assertEqual(redact_text("[x](mailto:carol@ex.com)"), "[x](mailto:[REDACTED EMAIL])")
        self.assertEqual(redact_text("a@b.com."), "[REDACTED EMAIL].")
        self.assertEqual(redact_text("中文字@例え.jp"), "[REDACTED EMAIL]")

    def test_seeded_fuzz_matches_old_regex(self):
        rng = random.Random(20261019)
        for _ in range(2000):
            text = "".join(rng.choice(list("aAbBcC09_.+-@ :\"'\n\t中é\\|*")) for _ in range(rng.randint(0, 48)))
            self.assertEqual(redact_text(text), oracle_redact(text), repr(text))

    def test_seeded_pem_fuzz_matches_old_regex(self):
        rng = random.Random(31415926)
        for _ in range(2000):
            text = "".join(rng.choice(PEM_FUZZ_PARTS) for _ in range(rng.randint(0, 14)))
            self.assertEqual(redact_text(text), oracle_redact(text), repr(text))

    def test_seeded_assign_fuzz_matches_old_regex(self):
        rng = random.Random(27182818)
        for _ in range(2000):
            text = "".join(rng.choice(ASSIGN_FUZZ_PARTS) for _ in range(rng.randint(0, 14)))
            self.assertEqual(redact_text(text), oracle_redact(text), repr(text))


class RedactionScaleTests(unittest.TestCase):
    TIME_BUDGET_SECONDS = 1.0

    @classmethod
    def setUpClass(cls):
        # Build the one-time Unicode control-strip table outside timed sections.
        redact_text("warmup@example.com")

    def timed(self, label, text):
        started = time.monotonic()
        result = redact_text(text)
        elapsed = time.monotonic() - started
        print(f"[timing] redact_text {label}: {elapsed * 1000:.1f} ms (limit {self.TIME_BUDGET_SECONDS:.1f} s)")
        self.assertLess(elapsed, self.TIME_BUDGET_SECONDS, label)
        return result

    def test_word_run_without_at_1mib_unchanged(self):
        text = "A" * 1_000_000
        self.assertEqual(self.timed("1 MiB 'A' run (no @)", text), text)

    def test_word_run_without_at_4mib_unchanged(self):
        rng = random.Random(1618033)
        block = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789") for _ in range(65_536))
        text = block * 64  # 4 MiB of word characters, no "@"
        self.assertNotIn("@", text)
        result = self.timed("4 MiB random word run (no @)", text)
        self.assertEqual(len(result), len(text))
        self.assertEqual(result, text)

    def test_email_dense_1mib_fully_redacted(self):
        unit = "a" * 50 + "@ex.com \n"
        count = 1_048_576 // len(unit)
        text = unit * count
        result = self.timed(f"1 MiB email-dense ({count} addresses)", text)
        self.assertEqual(result, "[REDACTED EMAIL] \n" * count)
        self.assertNotIn("@", result)

    def test_pem_header_flood_1mib(self):
        # Old code: every header swept the rest of the text (quadratic, minutes).
        text = "-----BEGIN PRIVATE KEY-----" * 40_000 + "-----END RSA PRIVATE KEY-----"
        result = self.timed("1 MiB PEM header flood", text)
        self.assertEqual(result, "[REDACTED PRIVATE KEY]")

    def test_assign_whitespace_gap_4mib(self):
        # Old code: O(gap^2) backtracking; a 16 KB gap already cost 0.9 s.
        self.assertEqual(self.timed("'password' + 4 MiB spaces", "password" + " " * 4_000_000), "password" + " " * 4_000_000)
        text = "password" + " " * 4_000_000 + ": hunter2"
        result = self.timed("'password' + 4 MiB spaces + value", text)
        self.assertEqual(result, "password" + " " * 4_000_000 + ": [REDACTED]")

    def test_email_flood_pem_mix_1mib(self):
        # Email sits BEFORE its unit's PEM block: a PEM match spans BEGIN..END,
        # so an email between them would be consumed by it (old regex did the
        # same). This layout makes both rewrites happen in every unit.
        unit = "a" * 40 + "@ex.com\n" + "-----BEGIN PRIVATE KEY-----\n" + "x\n" + "-----END RSA PRIVATE KEY-----\n"
        text = unit * 9_000
        result = self.timed("1 MiB PEM + email mix", text)
        self.assertEqual(result, "[REDACTED EMAIL]\n[REDACTED PRIVATE KEY]\n" * 9_000)


class SettlementCapTests(unittest.TestCase):
    def test_under_cap_passthrough(self):
        self.assertEqual(_settle_output(bytearray(b"contact a@ex.com")), "contact [REDACTED EMAIL]")

    def test_over_cap_truncates_with_marker_and_never_leaks(self):
        cap = REDACT_HARD_CAP_CHARS
        secret_tail = b"tail-secret-hunter2"
        raw = b"a@ex.com " + b"A" * cap + secret_tail
        result = _settle_output(bytearray(raw))
        # R3 ordering: redaction runs on the FULL buffer first; only the
        # redacted text is truncated, so the dropped tail was never part of the
        # emitted text and the marker counts redacted length, not raw length.
        redacted_length = len("[REDACTED EMAIL]") + 1 + cap + len(secret_tail)
        dropped = redacted_length - cap
        marker = f"\n[TRUNCATED {dropped} CHARS OVER SETTLEMENT REDACTION CAP {cap}]"
        self.assertEqual(result, "[REDACTED EMAIL]" + " " + "A" * (cap - 17) + marker)
        self.assertNotIn("hunter2", result)

    def test_straddling_pem_body_never_reaches_the_log_even_when_end_is_dropped(self):
        # R3 regression A: BEGIN + key body inside the retained region, END
        # beyond the settlement cap. Truncating before redaction kept the body
        # verbatim as an "unclosed PEM"; redact-then-truncate removes it, with
        # the pair's marker entirely inside the retained region.
        cap = REDACT_HARD_CAP_CHARS
        body = b"MIIEowCanaryPrivateKeyBody"
        prefix = b"a@ex.com\n"
        filler = cap - len(prefix) - len(b"[REDACTED PRIVATE KEY]") - len(body)
        raw = prefix + b"A" * filler + b"-----BEGIN RSA PRIVATE KEY-----\n" + body + b"\n-----END RSA PRIVATE KEY-----\n"
        result = _settle_output(bytearray(raw))
        self.assertNotIn(body.decode(), result)
        self.assertIn("[REDACTED PRIVATE KEY]", result)

    def test_unclosed_pem_after_stream_cut_is_redacted_to_the_boundary(self):
        # R3 regression B: the reader dropped the stream tail, so the buffer
        # genuinely has no END marker. The conservative unclosed rule redacts
        # from BEGIN to the end of the buffer on every settlement surface.
        body = "MIIEowCanaryStreamCutBody"
        raw = ("header line\n-----BEGIN PRIVATE KEY-----\n" + body + "\n").encode()
        for truncated in (False, True):
            with self.subTest(stream_truncated=truncated):
                result = _settle_output(bytearray(raw), stream_truncated=truncated)
                self.assertNotIn(body, result)
                self.assertNotIn("-----BEGIN PRIVATE KEY-----", result)
                self.assertIn("[REDACTED PRIVATE KEY]", result)

    def test_reader_cut_leaving_partial_token_tail_is_scrubbed(self):
        # R3: a stream cut can leave a partial token head (AKIA + <16 chars) at
        # the buffer end; the full-shape pattern legitimately fails, so the
        # truncated-aware redactor scrubs the tail explicitly.
        partial = "prefix AKIAABCDEFGHIJKL"
        scrubbed = redact_text_truncated(partial)
        self.assertNotIn("AKIAABCDEFGHIJKL", scrubbed)
        self.assertIn("[REDACTED PARTIAL TOKEN AT OUTPUT BOUNDARY]", scrubbed)
        # The untruncated redactor keeps its exact old semantics for the same
        # string in the middle of a buffer (the full token shape never formed).
        self.assertEqual(redact_text("head " + partial + " tail"), "head " + partial + " tail")


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="re-redaction-bounds-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def budget(self, **values):
        return Budget({**BUDGET_DEFAULTS, **values})


class RunCommandBoundsTests(TempDirCase):
    WATCHDOG_SECONDS = 60

    def run_with_watchdog(self, argv, budget, **kwargs):
        """run_command on a worker thread; the main thread enforces the watchdog."""
        outcome = {}

        def body():
            try:
                outcome["result"] = run_command(argv, self.root, budget, **kwargs)
            except BaseException as exc:  # surfaced below, watchdog must fire first
                outcome["error"] = exc

        worker = threading.Thread(target=body, daemon=True)
        started = time.monotonic()
        worker.start()
        worker.join(self.WATCHDOG_SECONDS)
        elapsed = time.monotonic() - started
        self.assertFalse(worker.is_alive(), f"run_command still running after {self.WATCHDOG_SECONDS}s watchdog")
        self.assertNotIn("error", outcome, f"run_command raised: {outcome.get('error')!r}")
        print(f"[timing] run_command chain: {elapsed:.2f} s (limits: 10 s assert / {self.WATCHDOG_SECONDS}s watchdog)")
        return outcome["result"], elapsed

    def test_default_budget_1mib_word_output_returns_bounded(self):
        script = "import sys; sys.stdout.write('A' * 1000000)"
        stdout_path, stderr_path = self.root / "stdout.log", self.root / "stderr.log"
        result, elapsed = self.run_with_watchdog(
            [sys.executable, "-c", script], self.budget(), timeout=30,
            stdout_path=stdout_path, stderr_path=stderr_path,
        )
        self.assertLess(elapsed, 10.0)
        self.assertEqual(result.status, "succeeded")
        self.assertFalse(result.timed_out)
        self.assertEqual(len(result.stdout), 1_000_000)  # length conserved through redaction
        self.assertEqual(result.stdout, "A" * 1_000_000)  # no @, so content must be untouched
        self.assertTrue(stdout_path.exists())
        self.assertEqual(stdout_path.read_text(encoding="utf-8"), result.stdout)
        self.assertTrue(stderr_path.exists())

    def test_word_flood_under_small_cap_reports_output_exceeded(self):
        # 5 MiB single word, no "@": floods the pipe AND would have tripped the
        # quadratic email regex on the retained buffer under the old code.
        script = "import sys; sys.stdout.write('A' * 5000000)"
        result, elapsed = self.run_with_watchdog(
            [sys.executable, "-c", script], self.budget(max_tool_output_bytes=4096), timeout=30,
        )
        self.assertLess(elapsed, 10.0)
        self.assertEqual(result.status, "output-exceeded")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 2 * 4096)

    def test_email_flood_within_default_cap_succeeds(self):
        script = "import sys; sys.stdout.write(('a' * 50 + '@ex.com \\n') * 17000)"
        result, elapsed = self.run_with_watchdog([sys.executable, "-c", script], self.budget(), timeout=30)
        self.assertLess(elapsed, 10.0)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.stdout, "[REDACTED EMAIL] \n" * 17_000)


if __name__ == "__main__":
    unittest.main()
