"""Flatten runtime trace segments into one 0-based JSONL trace.

`bw-runtime` numbers events from 1 within a trace and writes them as segments
described by `trace-index.json`. The oracle requires a single stream whose `seq`
starts at 0, and it validates `TraceEnd.event_count` against the stream it was
given. The D0 runner does this internally; harnesses driven outside that runner
need the same step, or the oracle rejects the trace with `BW-TRACE-SEQ-START`.

Renumbering is safe only because segment order is fixed by the index and each
segment's range is recorded there; the segments are verified to be contiguous
before anything is rewritten.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


class FlattenError(Exception):
    """The trace could not be flattened into a single ordered stream."""


def read_index(trace_dir: pathlib.Path) -> list[dict]:
    index_path = trace_dir / "trace-index.json"
    if not index_path.is_file():
        raise FlattenError(f"{index_path}: trace index is missing")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    segments = index.get("segments")
    if not segments:
        raise FlattenError(f"{index_path}: trace index lists no segments")
    return segments


def load_events(trace_dir: pathlib.Path, segments: list[dict]) -> list[dict]:
    events: list[dict] = []
    expected_start = None
    for segment in segments:
        if segment.get("compressed"):
            raise FlattenError(
                f"{segment['path']}: compressed segments are unsupported; "
                "run the harness with BW_TRACE_COMPRESS=0"
            )
        if expected_start is not None and segment["event_start"] != expected_start:
            raise FlattenError(
                f"{segment['path']}: segment starts at {segment['event_start']}, "
                f"expected {expected_start}; the trace is not contiguous"
            )
        expected_start = segment["event_end"] + 1

        # The index records the path as written by the sink; resolve by name so the
        # trace stays readable after the run directory is moved.
        segment_path = trace_dir / pathlib.PurePosixPath(segment["path"]).name
        if not segment_path.is_file():
            raise FlattenError(f"{segment_path}: segment file is missing")
        for number, line in enumerate(
            segment_path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise FlattenError(f"{segment_path}:{number}: {error}") from error
    if not events:
        raise FlattenError(f"{trace_dir}: the trace contains no events")
    return events


def renumber(events: list[dict]) -> list[dict]:
    for position, event in enumerate(events):
        event["seq"] = position
        if event.get("payload", {}).get("kind") == "trace_end":
            event["payload"]["event_count"] = len(events)
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)

    try:
        segments = read_index(args.trace_dir)
        events = renumber(load_events(args.trace_dir, segments))
    except (FlattenError, KeyError, OSError) as error:
        print(f"flatten-trace: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    print(
        json.dumps(
            {
                "kind": "bw-trace-flatten",
                "event_count": len(events),
                "segment_count": len(segments),
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
