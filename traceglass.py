"""Streaming JSONL diagnostics with bounded aggregation and explicit estimates."""

import argparse
from collections import Counter
import html
import json
import math
from pathlib import Path
import random
import re
import sys
from typing import Iterable

UUID = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.I)
NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
SECRET = re.compile(r"(?i)(token|password|api_key|secret)(\s*[:=]\s*)([^\s,;]+)")
LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def fingerprint(message: str) -> str:
    """Heuristic grouping, not a complete PII/secret scrubber."""
    text = SECRET.sub(r"\1\2<redacted>", message[:2048])
    text = EMAIL.sub("<email>", text)
    text = UUID.sub("<uuid>", text)
    return NUMBER.sub("<n>", text)


class Analyzer:
    def __init__(self, *, sample_size: int = 4096, max_groups: int = 1000, seed: int = 0):
        if type(sample_size) is not int or type(max_groups) is not int or min(sample_size, max_groups) < 1:
            raise ValueError("sample_size and max_groups must be positive integers")
        self.sample_size, self.max_groups = sample_size, max_groups
        self.rng = random.Random(seed)
        self.latencies: list[float] = []
        self.duration_count = 0
        self.duration_mean = 0.0
        self.duration_max = 0.0
        self.total = self.valid = self.invalid = self.blank = 0
        self.levels: Counter = Counter()
        self.services: Counter = Counter()
        self.groups: Counter = Counter()
        self.service_overflow = self.group_overflow = 0
        self.invalid_examples: list[dict] = []

    def reject(self, reason: str) -> None:
        self.invalid += 1
        if len(self.invalid_examples) < 10:
            self.invalid_examples.append({"line": self.total, "reason": reason})

    def _bounded(self, counts: Counter, key: str) -> bool:
        if key in counts or len(counts) < self.max_groups:
            counts[key] += 1
            return True
        return False

    def consume(self, line: str) -> None:
        self.total += 1
        if not line.strip():
            self.blank += 1
            return
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            self.reject("invalid JSON")
            return
        if not isinstance(event, dict):
            self.reject("event must be an object")
            return
        level = event.get("level", "INFO")
        service = event.get("service", "unknown")
        message = event.get("message", "")
        if not all(isinstance(v, str) for v in (level, service, message)):
            self.reject("level, service and message must be strings")
            return
        level = {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(level.upper(), level.upper())
        if level not in LEVELS or not service.strip() or len(service) > 200:
            self.reject("invalid level or service")
            return
        duration = event.get("duration_ms")
        if duration is not None:
            if (type(duration) not in (int, float) or duration < 0 or duration > 1e15
                    or not math.isfinite(duration)):
                self.reject("duration_ms must be finite and between 0 and 1e15")
                return
        self.valid += 1
        self.levels[level] += 1
        if not self._bounded(self.services, service):
            self.service_overflow += 1
        if level in {"ERROR", "CRITICAL"}:
            if not self._bounded(self.groups, (service, fingerprint(message))):
                self.group_overflow += 1
        if duration is not None:
            self.duration_count += 1
            self.duration_mean += (duration - self.duration_mean) / self.duration_count
            self.duration_max = max(self.duration_max, duration)
            if len(self.latencies) < self.sample_size:
                self.latencies.append(float(duration))
            else:
                index = self.rng.randrange(self.duration_count)
                if index < self.sample_size:
                    self.latencies[index] = float(duration)

    def analyze(self, lines: Iterable[str]) -> dict:
        """Consume an iterable; repeated calls continue the same analysis."""
        for line in lines:
            self.consume(line)
        return self.report()

    def report(self) -> dict:
        ordered = sorted(self.latencies)

        def percentile(p):
            return ordered[max(0, math.ceil(p * len(ordered)) - 1)] if ordered else None

        errors = self.levels["ERROR"] + self.levels["CRITICAL"]
        return {
            "schema_version": 1,
            "lines": self.total, "valid_events": self.valid,
            "invalid_lines": self.invalid, "blank_lines": self.blank,
            "errors": errors, "error_rate": errors / self.valid if self.valid else 0,
            "levels": dict(sorted(self.levels.items())),
            "services": dict(self.services.most_common()),
            "service_overflow_events": self.service_overflow,
            "error_groups": [{"service": key[0], "pattern": key[1], "count": count}
                             for key, count in self.groups.most_common()],
            "error_group_overflow_events": self.group_overflow,
            "latency_ms": {"count": self.duration_count,
                           "mean": self.duration_mean if self.duration_count else None,
                           "max": self.duration_max if self.duration_count else None,
                           "p50": percentile(.5), "p95": percentile(.95), "p99": percentile(.99),
                           "sample_count": len(ordered),
                           "estimated_percentiles": self.duration_count > self.sample_size},
            "invalid_examples": list(self.invalid_examples),
        }


def bounded_lines(stream, limit: int):
    """Drain oversized physical lines without allocating the whole line."""
    if limit < 1:
        raise ValueError("line limit must be positive")
    while True:
        line = stream.readline(limit + 1)
        if not line:
            break
        if len(line) > limit:
            while not line.endswith("\n"):
                line = stream.readline(limit + 1)
                if not line:
                    break
            yield "!oversized-line!"  # one rejected event, not many fragments
        else:
            yield line


def render_html(report: dict) -> str:
    def esc(value):
        return html.escape(str(value), quote=True)

    latency = report["latency_ms"]
    rows = "".join(f'<tr><td>{esc(g["service"])}</td><td><code>{esc(g["pattern"])}</code></td>'
                   f'<td>{g["count"]}</td></tr>' for g in report["error_groups"])
    bars = "".join(f'<div class="bar"><span>{esc(name)}</span><strong>{count}</strong></div>'
                   for name, count in report["levels"].items())
    estimate = "Reservoir estimates" if latency["estimated_percentiles"] else "Exact nearest-rank percentiles"
    cards = [("VALID EVENTS", report["valid_events"]), ("ERROR RATE", f'{report["error_rate"]:.1%}'),
             ("P95 LATENCY", f'{latency["p95"]} ms' if latency["p95"] is not None else "N/A"),
             ("REJECTED LINES", report["invalid_lines"])]
    metrics = "".join(f'<div class="metric"><small>{label}</small><b>{value}</b></div>' for label, value in cards)
    return f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TraceGlass · Diagnostic report</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0b1020;color:#e7edf5;font:16px system-ui,sans-serif}}
main{{max-width:1120px;margin:auto;padding:64px 28px}}header{{border-bottom:1px solid #2b344a;padding-bottom:30px}}
.tag,small{{color:#91a2bd;letter-spacing:.13em;font-size:11px}}h1{{font-size:clamp(38px,7vw,68px);letter-spacing:-.06em;margin:12px 0}}h1 span{{color:#baff5b}}
p{{color:#aebdd1;line-height:1.7}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:32px 0}}
.metric{{border:1px solid #2b344a;border-radius:14px;padding:24px;background:#121a2d}}b{{display:block;font-size:30px;margin-top:14px}}
section{{margin:40px 0}}h2{{font-size:21px}}.bar{{display:flex;justify-content:space-between;background:#172238;padding:12px 18px;margin:7px 0;border-left:3px solid #baff5b}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:16px;text-align:left;border-bottom:1px solid #283348}}th{{font-size:12px;color:#91a2bd}}
code{{white-space:pre-wrap;overflow-wrap:anywhere;color:#bfc5ff}}footer{{font-size:12px;color:#91a2bd;border-top:1px solid #2b344a;padding-top:22px}}
@media(max-width:700px){{.metrics{{grid-template-columns:repeat(2,1fr)}}main{{padding:30px 18px}}.metric{{padding:16px}}b{{font-size:24px}}}}
</style><main><header><div class="tag">LOCAL ANALYSIS / NO EXTERNAL ASSETS</div>
<h1>Trace<span>Glass.</span></h1><p>From noisy logs to a readable diagnostic snapshot.</p></header>
<div class="metrics">{metrics}</div><section><h2>Event levels</h2>{bars or '<p>No valid events.</p>'}</section>
<section><h2>Error fingerprints</h2><p>Heuristically grouped by service and normalized message.</p>
<div class="table-wrap"><table><thead><tr><th>SERVICE</th><th>PATTERN</th><th>EVENTS</th></tr></thead>
<tbody>{rows or '<tr><td colspan="3">No error groups.</td></tr>'}</tbody></table></div></section>
<footer>{estimate} · {latency['sample_count']} sampled / {latency['count']} latency values.<br>
Overflow: {report['service_overflow_events']} service events, {report['error_group_overflow_events']} error events.
Blank lines: {report['blank_lines']}. Fingerprints may still contain sensitive data; review before sharing.</footer></main></html>'''


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="UTF-8 JSONL file, or - for stdin")
    parser.add_argument("--html", type=Path, help="write a standalone HTML report")
    parser.add_argument("--sample-size", type=int, default=4096)
    parser.add_argument("--max-groups", type=int, default=1000)
    parser.add_argument("--max-line-chars", type=int, default=1_048_576)
    parser.add_argument("--strict", action="store_true", help="exit 2 if any input lines are rejected")
    args = parser.parse_args(argv)
    try:
        if args.html and args.input != "-" and Path(args.input).resolve() == args.html.resolve():
            raise ValueError("HTML output must not overwrite input")
        analyzer = Analyzer(sample_size=args.sample_size, max_groups=args.max_groups)
        if args.input == "-":
            report = analyzer.analyze(bounded_lines(sys.stdin, args.max_line_chars))
        else:
            with open(args.input, encoding="utf-8-sig") as stream:
                report = analyzer.analyze(bounded_lines(stream, args.max_line_chars))
        if args.html:
            args.html.write_text(render_html(report), encoding="utf-8")
        print(json.dumps(report, indent=2, allow_nan=False))
        return 2 if args.strict and report["invalid_lines"] else 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
