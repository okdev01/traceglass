import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from traceglass import Analyzer, bounded_lines, fingerprint, render_html


class AnalyzerTests(unittest.TestCase):
    def test_counts_and_aliases(self):
        report = Analyzer().analyze([json.dumps({"level": level}) for level in ("info", "warn", "fatal", "error")])
        self.assertEqual(report["errors"], 2)
        self.assertEqual(report["error_rate"], .5)
        self.assertEqual(report["levels"]["WARNING"], 1)

    def test_exact_percentiles(self):
        report = Analyzer().analyze(json.dumps({"duration_ms": n}) for n in range(1, 101))
        latency = report["latency_ms"]
        self.assertEqual((latency["p50"], latency["p95"], latency["p99"]), (50, 95, 99))
        self.assertEqual(latency["mean"], 50.5)
        self.assertFalse(latency["estimated_percentiles"])

    def test_sampling_bounded_and_reproducible(self):
        lines = [json.dumps({"duration_ms": n}) for n in range(1000)]
        a, b = Analyzer(sample_size=16), Analyzer(sample_size=16)
        self.assertEqual(a.analyze(lines), b.analyze(lines))
        self.assertEqual(len(a.latencies), 16)
        self.assertTrue(a.report()["latency_ms"]["estimated_percentiles"])
        self.assertEqual(a.report()["latency_ms"]["count"], 1000)

    def test_invalid_events_are_atomic(self):
        lines = ['{', '[]', '{"duration_ms":NaN}', '{"duration_ms":true}',
                 '{"level":9}', '{"service":""}', '{"duration_ms":-1}', '{"duration_ms":1e300}',
                 '{"message":null}', '{"level":"unknown"}']
        r = Analyzer().analyze(lines)
        self.assertEqual(r["invalid_lines"], len(lines))
        self.assertEqual(r["valid_events"], 0)
        self.assertEqual(r["services"], {})

    def test_overflow_is_reported(self):
        r = Analyzer(max_groups=2).analyze(json.dumps({"service": s, "level": "ERROR", "message": s})
                                           for s in ("one", "two", "three", "one", "four"))
        self.assertEqual(r["services"], {"one": 2, "two": 1})
        self.assertEqual(r["service_overflow_events"], 2)
        self.assertEqual(r["error_group_overflow_events"], 2)

    def test_grouping_and_redaction(self):
        a = fingerprint("user 42 a@example.com token=abc failed")
        b = fingerprint("user 90 b@example.com token=xyz failed")
        self.assertEqual(a, b)
        self.assertNotIn("abc", a)
        self.assertNotIn("example.com", a)

    def test_html_escapes_untrusted_fields(self):
        r = Analyzer().analyze([json.dumps({"service": "<script>alert(1)</script>",
                                          "level": "ERROR", "message": '<img src=x onerror="bad()">'})])
        document = render_html(r)
        self.assertNotIn("<script>", document)
        self.assertNotIn("<img src=x", document)
        self.assertIn("&lt;script&gt;", document)

    def test_oversize_line_drains_once(self):
        stream = io.StringIO("x" * 100 + '\n{}\n')
        r = Analyzer().analyze(bounded_lines(stream, 10))
        self.assertEqual(r["lines"], 2)
        self.assertEqual(r["invalid_lines"], 1)
        self.assertEqual(r["valid_events"], 1)

    def test_empty_and_blank(self):
        r = Analyzer().analyze(["", " \n"])
        self.assertEqual(r["blank_lines"], 2)
        self.assertIsNone(r["latency_ms"]["p99"])
        self.assertIn("No valid events", render_html(r))

    def test_invalid_samples_bounded(self):
        r = Analyzer().analyze("bad" for _ in range(100))
        self.assertEqual(len(r["invalid_examples"]), 10)
        self.assertEqual(r["invalid_lines"], 100)

    def test_huge_integer_rejected(self):
        r = Analyzer().analyze(['{"duration_ms":' + '9' * 400 + '}'])
        self.assertEqual(r["invalid_lines"], 1)

    def test_cli_strict_html_and_input_protection(self):
        with tempfile.TemporaryDirectory() as temp:
            source, output = Path(temp) / "events.jsonl", Path(temp) / "report.html"
            source.write_text('{}\nbad\n', encoding="utf-8")
            result = subprocess.run([sys.executable, "traceglass.py", str(source), "--html", str(output), "--strict"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(result.stdout)["valid_events"], 1)
            result = subprocess.run([sys.executable, "traceglass.py", str(source), "--html", str(source)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(source.read_text(encoding="utf-8"), '{}\nbad\n')


if __name__ == "__main__":
    unittest.main()
