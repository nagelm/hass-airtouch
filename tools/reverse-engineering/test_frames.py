"""Self-contained tests for airtouch4_frames (no pyairtouch dependency).

The golden vector is a real quick-timer frame emitted by pyairtouch 3.3.0's own
encoder, captured during development, so these assertions verify the parser and
CRC against the reference implementation.

    python3 -m unittest test_frames -v
"""

import unittest

import airtouch4_frames as af

# 55 55 | to=90 from=b0 pkt=00 msg=1f len=0006 | ff20 0001 011e | crc=e15e
GOLDEN = bytes.fromhex("5555 90b0 001f 0006 ff20 0001 011e e15e".replace(" ", ""))


class TestCrc(unittest.TestCase):
    def test_modbus_known_vector(self):
        # "123456789" -> 0x4B37 is the canonical CRC16/MODBUS check value.
        self.assertEqual(af.crc16_modbus(b"123456789"), 0x4B37)

    def test_golden_crc(self):
        # CRC covers everything after the 55 55 prefix, excluding the 2 CRC bytes.
        body = GOLDEN[2:-2]
        self.assertEqual(af.crc16_modbus(body), int.from_bytes(GOLDEN[-2:], "big"))


class TestScan(unittest.TestCase):
    def test_parses_golden(self):
        frames = list(af.scan(GOLDEN))
        self.assertEqual(len(frames), 1)
        f = frames[0]
        self.assertTrue(f.crc_ok)
        self.assertEqual(f.message_id, 0x1F)
        self.assertEqual(f.ext_sub_id, 0xFF20)
        self.assertEqual(f.label, "extended/quick_timer")
        self.assertFalse(f.is_candidate)
        self.assertEqual(f.ext_payload, bytes.fromhex("0001011e"))

    def test_rejects_corrupt_crc(self):
        bad = bytearray(GOLDEN)
        bad[-1] ^= 0xFF
        self.assertEqual(list(af.scan(bytes(bad), require_crc=True)), [])

    def test_back_to_back(self):
        self.assertEqual(len(list(af.scan(GOLDEN + GOLDEN))), 2)

    def test_leading_junk_resync(self):
        self.assertEqual(len(list(af.scan(b"\x00\x55\x99" + GOLDEN))), 1)

    def _mutate_sub_id(self, sub_id: int) -> af.Frame:
        m = bytearray(GOLDEN)
        m[8:10] = sub_id.to_bytes(2, "big")
        end = 8 + int.from_bytes(m[6:8], "big")
        m[end:end + 2] = af.crc16_modbus(bytes(m[2:end])).to_bytes(2, "big")
        return next(iter(af.scan(bytes(m))))

    def test_unknown_ext_sub_is_candidate(self):
        f = self._mutate_sub_id(0xFF50)
        self.assertTrue(f.crc_ok)
        self.assertTrue(f.is_candidate)
        self.assertIn("UNKNOWN", f.label)

    def test_unknown_top_id_is_candidate(self):
        m = bytearray(GOLDEN)
        m[5] = 0x40  # unknown top-level message id
        end = 8 + int.from_bytes(m[6:8], "big")
        m[end:end + 2] = af.crc16_modbus(bytes(m[2:end])).to_bytes(2, "big")
        f = next(iter(af.scan(bytes(m))))
        self.assertTrue(f.is_candidate)
        self.assertEqual(f.label, "UNKNOWN(0x40)")


class TestFrameBuffer(unittest.TestCase):
    def test_reassembles_fragmented(self):
        fb = af.FrameBuffer()
        out = []
        for byte in GOLDEN:
            out += fb.feed(bytes([byte]))
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].crc_ok)

    def test_holds_partial_until_complete(self):
        fb = af.FrameBuffer()
        self.assertEqual(fb.feed(GOLDEN[:5]), [])
        done = fb.feed(GOLDEN[5:])
        self.assertEqual(len(done), 1)


if __name__ == "__main__":
    unittest.main()
