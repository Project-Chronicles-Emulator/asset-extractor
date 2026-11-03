"""Bounded, read-only snapshots of the client's already-enabled binary logger."""
import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--seconds", type=float, default=30)
parser.add_argument("--max-mb", type=int, default=64)
args = parser.parse_args()
if not 0 < args.seconds <= 300 or not 1 <= args.max_mb <= 512:
    raise ValueError("Capture duration must be 0..300 seconds; max-mb 1..512")
if args.output.exists():
    raise ValueError("Use a new capture directory to preserve previous evidence")
args.output.mkdir(parents=True)


def snapshot():
    with args.source.open("rb") as stream:
        data = stream.read(args.max_mb * 1024 * 1024 + 1)
    if len(data) > args.max_mb * 1024 * 1024:
        raise ValueError("Source exceeds the bounded snapshot size")
    return data


started = datetime.now(timezone.utc).isoformat()
first = snapshot()
(args.output / "native-log-start.bin").write_bytes(first)
print(f"Native logger capture started: {len(first)} bytes; duration {args.seconds}s", flush=True)
deadline = time.monotonic() + args.seconds
while time.monotonic() < deadline:
    time.sleep(min(0.25, max(0, deadline-time.monotonic())))
last = snapshot()
prefix = last[:len(first)] == first
(args.output / "native-log-final.bin").write_bytes(last)
meta = {"source": str(args.source), "method": "read-only client-native binary packet logger; no hooks/injection",
        "started_at_utc": started, "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "start_size": len(first), "final_size": len(last), "bytes_appended_during_capture": len(last)-len(first),
        "initial_snapshot_is_exact_prefix": prefix, "start_sha256": hashlib.sha256(first).hexdigest(),
        "final_sha256": hashlib.sha256(last).hexdigest()}
(args.output / "capture-metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
print(json.dumps(meta, indent=2), flush=True)
if not prefix:
    raise SystemExit("Log rotated or changed; both snapshots retained, offsets cannot be joined")
