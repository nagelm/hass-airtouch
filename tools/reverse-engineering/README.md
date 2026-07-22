# AirTouch 4 Program (Schedule) Reverse-Engineering Toolkit

The AirTouch 4 **Program** feature — the recurring day/time AC schedules shown in
the AirTouch app's *Program* tab (e.g. `HoP 10pm`, `Week`, `Weekend`, `6am-7am`,
`Program8`) — is **not** part of the published AirTouch 4 communication protocol
(v1.6), and **no** public library decodes it. `pyairtouch` (which
`hass-airtouch` is built on) implements only zone/AC control+status, AC ability,
error info, names, console version, and reverse-engineered *quick timers* — none
of which are the Program schedules.

Programs nevertheless sync to the phone app, so the console must exchange them
over some **undocumented message**. This toolkit is for capturing that traffic on
your own system and decoding the message format, so that Program read/write can
eventually be added to `pyairtouch` and surfaced in Home Assistant.

> **Scope / ethics:** This is for reverse-engineering **your own** AirTouch
> hardware on **your own** network for interoperability. Don't point it at
> equipment you don't own or aren't authorised to test.

---

## The tools

| File | Purpose |
|------|---------|
| `airtouch4_frames.py` | Dependency-free AirTouch 4 frame parser + CRC16/MODBUS. Classifies each frame as a **known** message or an **unknown candidate**. Validated byte-for-byte against `pyairtouch` 3.3.0. |
| `mitm_proxy.py` | **Primary capture tool.** Sits between the app and console, forwards bytes verbatim, decodes a copy live, highlights candidate (undocumented) frames, and logs them to JSONL. |
| `decode_pcap.py` | Fallback: decode a Wireshark/tcpdump `.pcap`/`.pcapng` into the same JSONL (needs `scapy`). |
| `diff_captures.py` | `summarise` a capture, and `diff` two captures to pin down exactly which body bytes encode a Program change. |

Everything is pure-Python 3.9+ stdlib except `decode_pcap.py` (optional `scapy`).

---

## Why programs must be a "candidate" frame

AirTouch 4 frames are:

```
55 55 | to | from | pkt_id | msg_id | len(2, big-endian) | body[len] | crc16(2)
```

`msg_id` is one of the documented/implemented set — `0x1F` (extended), `0x2A`,
`0x2B`, `0x2C`, `0x2D`, `0x36`, `0x37`. Extended (`0x1F`) messages carry a 2-byte
sub-ID as their first body bytes; the known sub-IDs are `0xFF10`, `0xFF11`,
`0xFF12`, `0xFF20`, `0xFF30`.

Programs are none of these, so when the app reads or writes a Program the console
exchange **must** carry either a new top-level `msg_id` or a new `0x1F` sub-ID.
The parser flags exactly those as **candidates** (`!!` / red). Finding the
candidate is step one; decoding its body is step two.

---

## Step 1 — Route the app through the proxy

The app talks to the console on **TCP 9004**. You need the app's connection to
land on the machine running `mitm_proxy.py` instead of on the console. Pick one:

### Option A — ARP spoof + DNAT (no app/router config; Linux box on the LAN)

Say: phone = `192.168.1.20`, console = `192.168.1.50`, proxy host = `192.168.1.9`.

```bash
# 1. Enable forwarding so the phone's other traffic still flows.
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Redirect the console port that transits this box to the local proxy.
sudo iptables -t nat -A PREROUTING -p tcp -s 192.168.1.20 -d 192.168.1.50 \
    --dport 9004 -j REDIRECT --to-ports 9004

# 3. Sit between phone and console (two directions).
sudo apt install dsniff        # provides arpspoof
sudo arpspoof -i eth0 -t 192.168.1.20 192.168.1.50 &   # tell phone we're the console
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.20 &   # tell console we're the phone

# 4. Run the proxy (see Step 2). Stop arpspoof (kill %1 %2) when finished so the
#    phone's ARP table heals.
```

### Option B — Router DNAT / port forward

If your router supports it, forward `phone → console:9004` to `proxyhost:9004`.
Cleanest, no ARP games, but router-dependent.

### Option C — Pin the console IP to the proxy host

Some setups let you give the app a manual host. If you can, point it at the proxy
host and set `--console-host` to the real console. (The AirTouch app usually
auto-discovers via UDP broadcast, so this isn't always available.)

> **Sanity check:** with the proxy running you should immediately see a stream of
> `group_status` / `ac_status` frames — the console pushes these continuously. If
> you see nothing, the routing isn't working yet.

---

## Step 2 — Capture

```bash
python3 mitm_proxy.py \
    --console-host 192.168.1.50 \
    --listen 0.0.0.0:9004 \
    --capture session.jsonl
```

Candidate frames print in red and are logged with full payloads. Keep the proxy
running for the whole experiment.

---

## Step 3 — The controlled experiment (the important part)

Reverse-engineering is **controlled diffing**: change exactly one thing, capture
before and after, and see which bytes moved. Do each action deliberately, with a
few seconds of quiet between them so frames are easy to attribute. Use a
**separate capture file per state** so `diff` is clean.

A good sequence to isolate the format:

1. **Baseline read.** Start capture. Open the app's *Program* tab and scroll
   through all programs (this often triggers the console to send the full program
   set). Save as `00-baseline.jsonl`. Run `summarise` — note every candidate
   message ID/sub-ID. *This alone may reveal the Program read message.*

2. **Single-field time edit.** New capture `01-before.jsonl`: open one program
   (e.g. `Program8`). Stop. New capture `02-after.jsonl`: change **only** its
   start time by one unit (06:00 → 07:00), save in the app. `diff 01 02`. The
   changed byte offset is the **hour** field.

3. **Minute edit.** Repeat changing only minutes (07:00 → 07:30) → **minute**
   field / resolution.

4. **Day-of-week toggle.** Toggle one weekday on/off → the **day bitmask** byte(s).

5. **On/off action & mode.** Change the program's action (turn AC on vs off, or
   its mode/fan/setpoint) one at a time → those field offsets.

6. **Enable/disable & which-program index.** Enable/disable the program, then
   repeat an edit on a *different* program number → the **program index** field
   and the **enabled** flag.

7. **Write path.** Watch the `APP->CON` direction during each save: the frame the
   app *sends* is the **write** command you'll ultimately need to replicate from
   Home Assistant. The `CON->APP` frames are the **read/broadcast** form.

Keep a short log (a text file) mapping each capture to the exact action you took.
That mapping is what turns raw byte diffs into a field map.

---

## Step 4 — Analyse

```bash
# What message types / candidates showed up?
python3 diff_captures.py summarise 00-baseline.jsonl

# Which bytes encode the change between two states?
python3 diff_captures.py diff 01-before.jsonl 02-after.jsonl
```

`diff` byte-aligns the candidate frames and marks changed offsets:

```
=== CON->APP 0x1F/0xFF50 : before=1 after=1 ===
    offset:  0  1  2  3  4
    before: 01 00 06 00 1e
    after : 01 00 07 00 1e
    diff  :       ^^
  --> changed byte offset(s): [2]
```

Build up a field table offset-by-offset. Watch both directions: the **read**
(`CON->APP`) and **write** (`APP->CON`) layouts are often the same body with a
different message ID or address.

### No candidate appeared?

If editing a Program produces **only** known message types (or nothing over TCP),
that's a real finding too: the Program store may sync via the **cloud/app path**
rather than the local TCP link. In that case local read/write isn't possible and
HA-side scheduling remains the route. Record it either way.

---

## Step 5 — Turn a decode into working code

Once you have the message ID(s) and a field map:

1. Write a `pyairtouch` message module mirroring the existing ones
   (e.g. copy the shape of `at4/comms/x1FFF20_quick_timer.py`), with an
   encoder/decoder and a dataclass, and register it in `at4/comms/registry.py`.
2. Expose a `programs` API on the `AirConditioner`/`AirTouch` protocol objects.
3. In `hass-airtouch`, surface programs as entities/services and (optionally) the
   two-way HA ⇄ console sync.

Contribute the decoded format upstream — this would be the first public
documentation of the AirTouch 4 Program protocol.

---

## Quick hex decode (no capture pipeline)

To decode a lone blob (e.g. a `tshark -e tcp.payload` field or bytes pasted from
Wireshark's *Follow TCP Stream → hex*):

```bash
python3 airtouch4_frames.py "5555 90b0 001f 0006 ff20 0001 011e e15e"
# or:  echo '5555...' | python3 airtouch4_frames.py -
```
