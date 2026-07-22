"""AirTouch 4 wire-frame parser and classifier.

Standalone, dependency-free decoder for the AirTouch 4 TCP protocol (port 9004).
Its purpose is reverse-engineering: it parses the framing, validates the CRC, and
labels each frame as a *known* message type or an *unknown candidate* -- the
candidates are where the undocumented "Program" (recurring schedule) messages
must live.

Frame layout (confirmed against pyairtouch 3.3.0):

    55 55 | to | from | pkt_id | msg_id | len(2, big-endian) | body[len] | crc(2)
    \___/   \_______________ header (8 bytes) ______________/  \_______/  \____/
    prefix                                                        body      CRC16/MODBUS

The CRC is CRC16/MODBUS computed over every byte *after* the 55 55 prefix
(i.e. header[2:] + body) and is appended big-endian (matching pyairtouch, which
emits ``crc.to_bytes(2, "big")``).

Known top-level message IDs and extended sub-IDs come straight from the
pyairtouch AT4 registry. Anything outside those sets is flagged as a candidate.
"""

from __future__ import annotations

import dataclasses
from typing import Iterator, Optional

# --------------------------------------------------------------------------- #
# CRC16/MODBUS (identical algorithm to pyairtouch.comms.crc16.Crc16Modbus)
# --------------------------------------------------------------------------- #

_CRC_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
]


def crc16_modbus(buffer: bytes) -> int:
    """Return the CRC16/MODBUS of *buffer* as an int."""
    crc = 0xFFFF
    for val in buffer:
        crc = (crc >> 8) ^ _CRC_TABLE[(val ^ crc) & 0x00FF]
    return crc


# --------------------------------------------------------------------------- #
# Protocol constants (from pyairtouch AT4 registry + header)
# --------------------------------------------------------------------------- #

PREFIX = b"\x55\x55"
HEADER_LEN = 8  # prefix(2) + to(1) + from(1) + pkt(1) + msg_id(1) + len(2)
CRC_LEN = 2

ADDRESS_NAMES = {
    0x80: "AIRTOUCH",
    0x90: "AIRTOUCH_EXT",
    0xB0: "CLIENT",
}

# Top-level message IDs implemented by pyairtouch 3.3.0.
KNOWN_TOP = {
    0x1F: "extended",
    0x2A: "group_ctrl",
    0x2B: "group_status",
    0x2C: "ac_ctrl",
    0x2D: "ac_status",
    0x36: "ac_timer_ctrl",
    0x37: "ac_timer_status",
}

# Extended (0x1F) sub-message IDs implemented by pyairtouch 3.3.0.
# The 2-byte sub-ID is the first two body bytes of an extended message.
KNOWN_EXT_SUB = {
    0xFF10: "err_info",
    0xFF11: "ac_ability",
    0xFF12: "group_names",
    0xFF20: "quick_timer",
    0xFF30: "console_ver",
}


@dataclasses.dataclass
class Frame:
    """A single decoded AirTouch 4 frame."""

    offset: int  # byte offset within the scanned stream
    to_address: int
    from_address: int
    packet_id: int
    message_id: int
    length: int
    body: bytes
    crc_ok: bool
    ext_sub_id: Optional[int]  # populated for 0x1F extended messages

    @property
    def label(self) -> str:
        if self.message_id == 0x1F:
            if self.ext_sub_id is None:
                return "extended(truncated)"
            name = KNOWN_EXT_SUB.get(self.ext_sub_id)
            return f"extended/{name}" if name else f"extended/UNKNOWN(0x{self.ext_sub_id:04X})"
        name = KNOWN_TOP.get(self.message_id)
        return name if name else f"UNKNOWN(0x{self.message_id:02X})"

    @property
    def is_candidate(self) -> bool:
        """True if this frame is NOT a documented/implemented message type.

        These are the frames worth investigating for the Program feature.
        """
        if self.message_id == 0x1F:
            return self.ext_sub_id is not None and self.ext_sub_id not in KNOWN_EXT_SUB
        return self.message_id not in KNOWN_TOP

    @property
    def ext_payload(self) -> bytes:
        """Body with the 2-byte extended sub-ID stripped (extended frames only)."""
        return self.body[2:] if self.message_id == 0x1F else self.body

    def format_line(self, direction: str = "") -> str:
        flag = "!!" if self.is_candidate else ("  " if self.crc_ok else "??")
        to_name = ADDRESS_NAMES.get(self.to_address, f"0x{self.to_address:02X}")
        from_name = ADDRESS_NAMES.get(self.from_address, f"0x{self.from_address:02X}")
        crc = "crc-ok" if self.crc_ok else "CRC-BAD"
        body = self.ext_payload if self.message_id == 0x1F else self.body
        return (
            f"{flag} {direction:<10} pkt={self.packet_id:<3} "
            f"{from_name}->{to_name} {self.label:<26} "
            f"len={self.length:<4} {crc}  {body.hex(' ')}"
        )


def scan(data: bytes, *, require_crc: bool = True) -> Iterator[Frame]:
    """Yield frames found in *data*.

    The scanner resynchronises on the ``55 55`` prefix. Because raw payload bytes
    can coincidentally contain ``55 55``, CRC validation is the disambiguator: a
    real frame boundary is one whose CRC checks out. With ``require_crc=True``
    (default) only CRC-valid frames advance the cursor by their full length;
    otherwise the cursor steps forward one byte to keep resyncing. Set
    ``require_crc=False`` to also surface CRC-bad frames (useful if you suspect
    the framing differs from the assumption above).
    """
    i = 0
    n = len(data)
    while i < n - HEADER_LEN:
        if data[i : i + 2] != PREFIX:
            i += 1
            continue
        to_address = data[i + 2]
        from_address = data[i + 3]
        packet_id = data[i + 4]
        message_id = data[i + 5]
        length = int.from_bytes(data[i + 6 : i + 8], "big")
        frame_end = i + HEADER_LEN + length + CRC_LEN
        if frame_end > n:
            # Incomplete frame at end of buffer; stop (caller may re-feed).
            break
        body = data[i + HEADER_LEN : i + HEADER_LEN + length]
        crc_on_wire = int.from_bytes(
            data[i + HEADER_LEN + length : frame_end], "big"
        )
        crc_calc = crc16_modbus(data[i + 2 : i + HEADER_LEN + length])
        crc_ok = crc_on_wire == crc_calc

        ext_sub_id = None
        if message_id == 0x1F and length >= 2:
            ext_sub_id = int.from_bytes(body[0:2], "big")

        if crc_ok or not require_crc:
            yield Frame(
                offset=i,
                to_address=to_address,
                from_address=from_address,
                packet_id=packet_id,
                message_id=message_id,
                length=length,
                body=body,
                crc_ok=crc_ok,
                ext_sub_id=ext_sub_id,
            )
            i = frame_end if crc_ok else i + 1
        else:
            i += 1


class FrameBuffer:
    """Incremental framer for a single direction of a TCP stream.

    Feed it bytes as they arrive off the wire; it returns complete frames and
    retains any partial trailing frame until more bytes arrive. It resynchronises
    on ``55 55`` and uses CRC validation to confirm frame boundaries, so
    coincidental ``55 55`` sequences inside a payload do not derail it.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        """Append *data* and return any newly-complete frames."""
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            frame = self._try_pop()
            if frame is None:
                break
            frames.append(frame)
        return frames

    def _try_pop(self) -> Optional[Frame]:
        buf = self._buf
        # Drop bytes before the next prefix.
        start = buf.find(PREFIX)
        if start == -1:
            # Keep only a trailing byte that might be the first half of a prefix.
            if buf and buf[-1] == PREFIX[0]:
                del buf[:-1]
            else:
                buf.clear()
            return None
        if start > 0:
            del buf[:start]
        if len(buf) < HEADER_LEN:
            return None
        length = int.from_bytes(buf[6:8], "big")
        frame_end = HEADER_LEN + length + CRC_LEN
        if len(buf) < frame_end:
            return None  # wait for the rest of the frame
        candidate = bytes(buf[:frame_end])
        parsed = next(iter(scan(candidate, require_crc=True)), None)
        if parsed is not None and parsed.offset == 0:
            del buf[:frame_end]
            return parsed
        # Not a valid frame at this position (bad CRC / false prefix); skip one
        # byte and resync on the next 55 55.
        del buf[:1]
        return self._try_pop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: airtouch4_frames.py <hex-string | ->  (- reads hex from stdin)")
        print("Decodes a blob of hex bytes into AirTouch 4 frames.")
        sys.exit(1)
    raw = sys.stdin.read() if sys.argv[1] == "-" else sys.argv[1]
    blob = bytes.fromhex("".join(raw.split()))
    found = 0
    for frame in scan(blob, require_crc=False):
        print(frame.format_line())
        found += 1
    print(f"\n{found} frame(s) decoded.", file=sys.stderr)
