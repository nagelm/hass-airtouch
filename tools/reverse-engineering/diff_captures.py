"""Analyse and diff AirTouch 4 capture files produced by mitm_proxy.py.

Two jobs, both aimed at pinning down the undocumented Program message format:

1. summarise -- what message types appeared, and dump the candidate
   (undocumented) frames in full. Run this first on any capture to see whether
   editing a Program produced a frame outside the known set.

       python3 diff_captures.py summarise programs.jsonl

2. diff -- byte-align the candidate frames from two captures taken around a
   single controlled change (e.g. before vs after moving Program1 from 06:00 to
   07:00) and highlight exactly which body bytes changed. Changed offsets are the
   fields that encode your edit.

       python3 diff_captures.py diff before.jsonl after.jsonl

A capture is JSONL, one frame per line, as written by mitm_proxy.py (fields:
direction, message_id, ext_sub_id, label, candidate, crc_ok, body_hex, ...).
"""

from __future__ import annotations

import argparse
import collections
import json
from typing import Iterable


def _load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _key(rec: dict) -> tuple:
    """Identity of a frame *type* (ignores per-instance payload)."""
    return (rec["direction"], rec["message_id"], rec.get("ext_sub_id"))


def _ext_payload(rec: dict) -> bytes:
    """Body with the 2-byte extended sub-ID stripped, matching Frame.ext_payload."""
    body = bytes.fromhex(rec["body_hex"])
    return body[2:] if rec["message_id"] == 0x1F else body


def _fmt_key(rec: dict) -> str:
    if rec["message_id"] == 0x1F and rec.get("ext_sub_id") is not None:
        return f"{rec['direction']} 0x1F/0x{rec['ext_sub_id']:04X}"
    return f"{rec['direction']} 0x{rec['message_id']:02X}"


def summarise(records: Iterable[dict]) -> None:
    records = list(records)
    by_label: collections.Counter = collections.Counter()
    for rec in records:
        by_label[(_fmt_key(rec), rec["label"])] += 1

    print(f"# {len(records)} frame(s)\n")
    print("Message types seen (count | key | label):")
    for (key, label), count in sorted(by_label.items()):
        mark = "  !!" if "UNKNOWN" in label else "    "
        print(f"{mark} {count:5d}  {key:<22} {label}")

    candidates = [r for r in records if r["candidate"]]
    print(f"\nCandidate (undocumented) frames: {len(candidates)}")
    if not candidates:
        print("  (none -- editing a Program produced no frame outside the known "
              "set in this capture)")
        return
    print("  These are the Program-message suspects. Full payloads:\n")
    for rec in candidates:
        payload = _ext_payload(rec)
        print(f"  {_fmt_key(rec):<22} len={len(payload):<3} {payload.hex(' ')}")


def _byte_diff(a: bytes, b: bytes) -> str:
    """Render two equal-or-unequal byte strings with changed offsets marked."""
    width = max(len(a), len(b))
    a_cells, b_cells, mark_cells = [], [], []
    for i in range(width):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        a_cells.append(f"{av:02x}" if av is not None else "--")
        b_cells.append(f"{bv:02x}" if bv is not None else "--")
        mark_cells.append("^^" if av != bv else "  ")
    idx = " ".join(f"{i:2d}" for i in range(width))
    return (
        f"    offset: {idx}\n"
        f"    before: {' '.join(a_cells)}\n"
        f"    after : {' '.join(b_cells)}\n"
        f"    diff  : {' '.join(mark_cells)}"
    )


def diff(before: list[dict], after: list[dict]) -> None:
    """Compare candidate frames of matching type between two captures."""
    def index(records: list[dict]) -> dict[tuple, list[dict]]:
        out: dict[tuple, list[dict]] = collections.defaultdict(list)
        for rec in records:
            if rec["candidate"]:
                out[_key(rec)].append(rec)
        return out

    before_idx = index(before)
    after_idx = index(after)
    keys = sorted(set(before_idx) | set(after_idx))
    if not keys:
        print("No candidate frames in either capture -- nothing to diff.\n"
              "If you expected a Program frame, the edit may have produced only "
              "known message types, or the capture missed it. Re-check summarise "
              "output for both files.")
        return

    for key in keys:
        b_list = before_idx.get(key, [])
        a_list = after_idx.get(key, [])
        sample = (a_list or b_list)[0]
        print(f"=== {_fmt_key(sample)} : before={len(b_list)} after={len(a_list)} ===")
        if not b_list or not a_list:
            print("  (present in only one capture -- appearance/disappearance is "
                  "itself a signal)\n")
            continue
        # Compare the last frame of each -- the settled state after the action.
        pa = _ext_payload(b_list[-1])
        pb = _ext_payload(a_list[-1])
        if pa == pb:
            print("  payload identical (this frame type did not encode the change)\n")
            continue
        print(_byte_diff(pa, pb))
        changed = [i for i in range(max(len(pa), len(pb)))
                   if (pa[i] if i < len(pa) else None) != (pb[i] if i < len(pb) else None)]
        print(f"  --> changed byte offset(s): {changed}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sum = sub.add_parser("summarise", help="Summarise one capture file.")
    p_sum.add_argument("capture")

    p_diff = sub.add_parser("diff", help="Byte-diff candidate frames of two captures.")
    p_diff.add_argument("before")
    p_diff.add_argument("after")

    args = parser.parse_args()
    if args.cmd == "summarise":
        summarise(_load(args.capture))
    elif args.cmd == "diff":
        diff(_load(args.before), _load(args.after))


if __name__ == "__main__":
    main()
