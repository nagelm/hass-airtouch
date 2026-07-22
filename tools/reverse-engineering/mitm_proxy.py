"""Man-in-the-middle proxy for AirTouch 4 traffic (RE capture tool).

This is the *primary* capture tool for reverse-engineering the AirTouch 4
"Program" (recurring schedule) messages. It sits between the AirTouch phone app
and the console, forwards every byte verbatim in both directions, and decodes a
copy of the stream for logging -- highlighting any frame that is not a documented
message type (the candidates for Program messages).

Why a proxy rather than a pcap? The stream is already TCP-reassembled per
direction, so you get clean, ordered frames with no packet-boundary noise, and
you see candidates live as you poke the app.

How to route the app through it
-------------------------------
The app talks to the console on TCP 9004. You need the app's connection to land
on this proxy instead of the console. Pick whichever is easiest on your network:

  * ARP spoof (no app config): on a Linux box, enable IP forwarding and use
    ``arpspoof``/``ettercap`` to sit between the phone and the console, then
    DNAT port 9004 to this proxy. See README.md for the exact commands.
  * Static route / firewall DNAT: on your router, redirect
    phone -> console:9004 to proxy_host:9004.
  * Discovery hijack: the app auto-discovers via UDP broadcast; if you run this
    host as the responder it can point the app at itself. (Advanced; ARP spoof
    is usually simpler.)

Then run, e.g.:
    python3 mitm_proxy.py --console-host 192.168.1.50 --listen 0.0.0.0:9004 \
        --capture programs.jsonl

Every frame is appended to the capture file as one JSON object per line
(direction, timestamp, hex, decoded label). Feed that file to diff_captures.py
after running a controlled experiment.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time

import airtouch4_frames as af

# ANSI colours (candidates in bright red so they jump out live).
_RED = "\033[91m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class Capture:
    """Appends decoded frames to a JSONL file and prints them live."""

    def __init__(self, path: str | None, colour: bool) -> None:
        self._fh = open(path, "a", encoding="utf-8") if path else None
        self._colour = colour

    def record(self, direction: str, frame: af.Frame) -> None:
        rec = {
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
            # Full frame bytes so nothing is lost for later analysis.
            "body_hex": frame.body.hex(),
        }
        if self._fh:
            self._fh.write(json.dumps(rec) + "\n")
            self._fh.flush()
        line = frame.format_line(direction)
        if self._colour and frame.is_candidate:
            line = f"{_RED}{line}{_RESET}"
        elif self._colour and not frame.crc_ok:
            line = f"{_DIM}{line}{_RESET}"
        print(line, flush=True)

    def close(self) -> None:
        if self._fh:
            self._fh.close()


async def _pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction: str,
    capture: Capture,
) -> None:
    """Forward bytes reader->writer verbatim, decoding a copy for logging."""
    framer = af.FrameBuffer()
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            # Forward first, always -- never let decoding affect the wire.
            writer.write(data)
            await writer.drain()
            for frame in framer.feed(data):
                capture.record(direction, frame)
    except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    console_host: str,
    console_port: int,
    capture: Capture,
) -> None:
    peer = client_writer.get_extra_info("peername")
    print(f"{_DIM}# app connected from {peer}; dialling console "
          f"{console_host}:{console_port}{_RESET}", flush=True)
    try:
        console_reader, console_writer = await asyncio.open_connection(
            console_host, console_port
        )
    except OSError as exc:
        print(f"# failed to reach console: {exc}", file=sys.stderr, flush=True)
        client_writer.close()
        return

    await asyncio.gather(
        _pump(client_reader, console_writer, "APP->CON", capture),
        _pump(console_reader, client_writer, "CON->APP", capture),
    )
    print(f"{_DIM}# session closed{_RESET}", flush=True)


async def _main_async(args: argparse.Namespace) -> None:
    host, _, port = args.listen.partition(":")
    capture = Capture(args.capture, colour=not args.no_color)

    async def on_client(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await _handle_client(r, w, args.console_host, args.console_port, capture)

    server = await asyncio.start_server(on_client, host or "0.0.0.0", int(port or 9004))
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"# AirTouch 4 MITM proxy listening on {addrs}", flush=True)
    print(f"# forwarding to console {args.console_host}:{args.console_port}", flush=True)
    print(f"# {_RED}candidate (undocumented) frames are highlighted{_RESET}", flush=True)
    if args.capture:
        print(f"# appending decoded frames to {args.capture}", flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        capture.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--console-host", required=True,
        help="IP/hostname of the real AirTouch 4 console.",
    )
    parser.add_argument(
        "--console-port", type=int, default=9004,
        help="Console TCP port (default: 9004).",
    )
    parser.add_argument(
        "--listen", default="0.0.0.0:9004",
        help="Address:port to listen on for the app (default: 0.0.0.0:9004).",
    )
    parser.add_argument(
        "--capture", metavar="FILE",
        help="Append decoded frames to this JSONL file for later diffing.",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour in the live output.",
    )
    args = parser.parse_args()
    try:
        asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        print("\n# stopped", flush=True)


if __name__ == "__main__":
    main()
