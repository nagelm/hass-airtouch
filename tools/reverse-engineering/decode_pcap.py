"""Decode AirTouch 4 frames from a Wireshark/tcpdump capture (RE fallback tool).

Use this if you captured with Wireshark/tcpdump instead of running mitm_proxy.py.
It extracts the TCP payload of the AirTouch port (9004 by default) from a
pcap/pcapng, reassembles each direction of each connection in order, decodes the
frames, and writes the same JSONL format that diff_captures.py consumes.

    python3 decode_pcap.py capture.pcapng --out programs.jsonl

Requires scapy (``pip install scapy``). If you cannot install scapy, export the
payload with tshark and pipe raw hex into the core decoder instead:

    tshark -r capture.pcapng -Y 'tcp.port==9004 && tcp.len>0' \\
        -T fields -e tcp.payload | tr -d '\\n' | \\
        python3 airtouch4_frames.py -

Note: hex-piping loses direction/ordering guarantees; the scapy path here keeps
per-direction reassembly, which matters for clean diffs.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import airtouch4_frames as af


def _iter_payloads(pcap_path: str, port: int):
    """Yield (direction_key, payload_bytes) tuples in capture order."""
    try:
        from scapy.all import TCP, rdpcap  # type: ignore
    except ImportError:
        sys.exit(
            "scapy is required for pcap decoding (pip install scapy).\n"
            "Alternatively, pipe tshark hex into airtouch4_frames.py -- see the "
            "module docstring."
        )
    for pkt in rdpcap(pcap_path):
        if TCP not in pkt:
            continue
        tcp = pkt[TCP]
        if tcp.sport != port and tcp.dport != port:
            continue
        payload = bytes(tcp.payload)
        if not payload:
            continue
        # Direction label: which side is the console (port 9004).
        if tcp.sport == port:
            direction = "CON->APP"
            conn = (tcp.dport,)  # per-client connection key
        else:
            direction = "APP->CON"
            conn = (tcp.sport,)
        yield direction, conn, payload


def decode(pcap_path: str, port: int, out_path: str | None) -> None:
    # One FrameBuffer per (connection, direction) so reassembly stays correct
    # even with several app connections in the capture.
    framers: dict[tuple, af.FrameBuffer] = {}
    out_fh = open(out_path, "w", encoding="utf-8") if out_path else None
    total = candidates = 0
    for direction, conn, payload in _iter_payloads(pcap_path, port):
        framer = framers.setdefault((conn, direction), af.FrameBuffer())
        for frame in framer.feed(payload):
            total += 1
            candidates += frame.is_candidate
            print(frame.format_line(direction))
            if out_fh:
                out_fh.write(json.dumps({
                    "ts": round(time.time(), 3),
                    "direction": direction,
                    "message_id": frame.message_id,
                    "ext_sub_id": frame.ext_sub_id,
                    "label": frame.label,
                    "candidate": frame.is_candidate,
                    "crc_ok": frame.crc_ok,
                    "packet_id": frame.packet_id,
                    "to": frame.to_address,
                    "from": frame.from_address,
                    "body_hex": frame.body.hex(),
                }) + "\n")
    if out_fh:
        out_fh.close()
    print(f"\n# {total} frame(s), {candidates} candidate(s)", file=sys.stderr)
    if out_path:
        print(f"# wrote {out_path}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("pcap", help="Path to the .pcap/.pcapng file.")
    parser.add_argument("--port", type=int, default=9004,
                        help="AirTouch console TCP port (default: 9004).")
    parser.add_argument("--out", metavar="FILE",
                        help="Write decoded frames as JSONL for diff_captures.py.")
    args = parser.parse_args()
    decode(args.pcap, args.port, args.out)


if __name__ == "__main__":
    main()
