#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import re
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from bleak import BleakClient, BleakScanner
from bleak.exc import (
    BleakCharacteristicNotFoundError,
    BleakGATTProtocolError,
    BleakGATTProtocolErrorCode,
)

SERVICE_UUID = "3e135142-654f-9090-134a-a6ff5bb77046"
CMD_UUID = "3fa4585a-ce4a-3bad-db4b-b8df8179ea09"
REPLY_UUID = "d0e8434d-cd29-0996-af41-6c90f4e0eb2a"
ENC_CMD_UUID = "2e3fa1b0-5a55-4c0d-9e11-0b130a1c0001"
ENC_REPLY_UUID = "2e3fa1b0-5a55-4c0d-9e11-0b130a1c0002"
PLAINTEXT_COMMAND_IDS = {0x52, 0x53, 0x54}
BTHOME_UUID = 0xFCD2
KEY_FILE = Path(__file__).with_name("key.txt")

class EQ3Error(Exception):
    pass

class CommandTimeout(EQ3Error):
    pass

@dataclass
class ThermostatStatus:
    mode: str | None = None
    boost: bool | None = None
    dst: bool | None = None
    window_open: bool | None = None
    locked: bool | None = None
    battery_low: bool | None = None
    valve_percent: int | None = None
    target_temperature: float | None = None
    ui_state: int | None = None
    raw: bytes = b""

@dataclass
class Advertisement:
    address: str
    name: str | None
    rssi: int | None
    received_at: float
    room_temperature: float | None = None
    target_temperature: float | None = None
    battery_voltage: float | None = None
    valve_percent: int | None = None
    mode: str | None = None
    boost: bool | None = None
    battery_low: bool | None = None
    connected: bool | None = None
    locked: bool | None = None
    window_open: bool | None = None
    raw_service_data: bytes | None = None
    encrypted: bool = False
    encryption_counter: int | None = None
    event: dict[str, Any] | None = None
    decode_error: str | None = None
    field_received_at: dict[str, float] | None = None

def _bthome_value(data: bytes, pos: int, length: int, signed=False):
    if pos + length > len(data):
        raise ValueError("Truncated BTHome object")
    return int.from_bytes(data[pos:pos + length], "little", signed=signed), pos + length

def _is_bthome_uuid(value: Any) -> bool:
    if isinstance(value, int):
        return value == BTHOME_UUID
    normalized = str(value).lower()
    return normalized in {
        "fcd2",
        "0000fcd2-0000-1000-8000-00805f9b34fb",
    } or normalized.startswith("0x") and normalized[2:] == "fcd2"

def _service_data(adv) -> bytes | None:
    for key, value in (adv.service_data or {}).items():
        if _is_bthome_uuid(key):
            return bytes(value)
    return None

def _is_eq3_name(name: str) -> bool:
    return name == "CC-RT-BLE" or name.startswith("eQ3-") or "CC-RT-BLE" in name

def load_broadcast_key(path: Path = KEY_FILE) -> bytes | None:
    try:
        contents = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    key_text = "".join(
        line.split("#", 1)[0] for line in contents.splitlines()
    ).strip()
    if not key_text:
        return None
    key_text = "".join(key_text.split())
    if key_text.startswith("0x"):
        key_text = key_text[2:]
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key_text):
        raise EQ3Error(f"{path} must contain exactly 32 hexadecimal characters (a 128-bit key)")
    return bytes.fromhex(key_text)

def _decrypt_bthome(data: bytes, key: bytes, address: str) -> tuple[bytes, int]:
    if len(key) != 16:
        raise ValueError("BThome encryption key must be 16 bytes (128 bits)")
    if len(data) < 10:
        raise ValueError("Encrypted BThome payload is too short")
    mac_text = address.replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{12}", mac_text):
        raise ValueError(
            "Cannot decrypt encrypted broadcast without the device's six-byte Bluetooth MAC "
            "(not available as a MAC address on macOS)"
        )
    counter_bytes = data[-8:-4]
    nonce = bytes.fromhex(mac_text) + bytes.fromhex("d2fc") + data[:1] + counter_bytes
    ciphertext_and_tag = data[1:-8] + data[-4:]
    try:
        plaintext = AESCCM(key, tag_length=4).decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag as exc:
        raise ValueError(
            "BThome authentication failed: check that key.txt and the device MAC are correct"
        ) from exc
    return plaintext, int.from_bytes(counter_bytes, "little")

def decode_bthome(data: bytes, *, key: bytes | None = None,
                  address: str | None = None) -> dict[str, Any]:
    if not data:
        raise ValueError("Empty BTHome payload")
    info = data[0]
    if info not in (0x40, 0x41):
        raise ValueError(f"Unsupported BTHome device-info 0x{info:02x}")
    if info == 0x41:
        if key is None:
            return {"encrypted": True, "raw": data}
        if address is None:
            raise ValueError("Device MAC address is required to decrypt BThome broadcasts")
        plaintext, counter = _decrypt_bthome(data, key, address)
        decoded = decode_bthome(b"\x40" + plaintext)
        decoded["encrypted"] = True
        decoded["encryption_counter"] = counter
        return decoded
    out: dict[str, Any] = {"encrypted": False}
    pos = 1
    temps = []
    while pos < len(data):
        oid = data[pos]
        pos += 1
        if oid == 0x00:  # packet id
            val, pos = _bthome_value(data, pos, 1)
            out["packet_id"] = val
        elif oid == 0x02:  # temperature, repeated room then target
            val, pos = _bthome_value(data, pos, 2, True)
            temps.append(val / 100.0)
        elif oid == 0x0C:  # voltage
            val, pos = _bthome_value(data, pos, 2)
            out["battery_voltage"] = val / 1000.0
        elif oid == 0x09:  # enum mode
            val, pos = _bthome_value(data, pos, 1)
            out["mode"] = {0: "auto", 1: "manual", 2: "holiday"}.get(val, f"unknown-{val}")
        elif oid in (0x0F, 0x15, 0x19, 0x1F, 0x2D):  # bool
            val, pos = _bthome_value(data, pos, 1)
            key = {0x0F: "boost", 0x15: "battery_low", 0x19: "connected",
                   0x1F: "unlocked", 0x2D: "window_open"}[oid]
            out[key] = bool(val)
        elif oid == 0x2F:
            val, pos = _bthome_value(data, pos, 1)
            out["valve_percent"] = val
        elif oid == 0x3A:
            val, pos = _bthome_value(data, pos, 1)
            out.setdefault("button_values", []).append(val)
        elif oid == 0x3C:
            if pos + 2 > len(data):
                raise ValueError("Truncated wheel event")
            out["wheel"] = {"direction": data[pos], "steps": data[pos + 1]}
            pos += 2
        else:
            raise ValueError(f"Unknown BTHome object id 0x{oid:02x}; cannot safely continue")
    if temps:
        out["room_temperature"] = temps[0]
        if len(temps) > 1:
            out["target_temperature"] = temps[1]
    if "unlocked" in out:
        out["locked"] = not out.pop("unlocked")
    return out

def decode_status(data: bytes) -> ThermostatStatus:
    if len(data) < 6 or data[0] != 0x02 or data[1] != 0x01:
        raise ValueError(f"Not a thermostat status frame: {data.hex()}")
    flags = data[2]
    return ThermostatStatus(
        mode={0: "auto", 1: "manual", 2: "holiday"}.get(flags & 3, "unknown"),
        boost=bool(flags & 0x04),
        dst=bool(flags & 0x08),
        window_open=bool(flags & 0x10),
        locked=bool(flags & 0x20),
        battery_low=bool(flags & 0x80),
        valve_percent=data[3],
        ui_state=data[4],
        target_temperature=data[5] / 2.0,
        raw=data,
    )

def decode_schedule(data: bytes) -> dict[str, Any]:
    if len(data) < 16 or data[0] != 0x21:
        raise ValueError(f"Not a schedule reply: {data.hex()}")
    day = data[1]
    slots = []
    for i in range(7):
        temp_half, until10 = data[2 + i * 2:4 + i * 2]
        slots.append({"temperature": temp_half / 2.0, "until_minutes": until10 * 10})
    return {"requested_day": day, "day": day if day <= 6 else (0 if day == 7 else 2),
            "slots": slots}

def _connection_nonce(session: bytes, counter: int, direction: int) -> bytes:
    if len(session) != 8:
        raise ValueError("Encrypted-channel session nonce must be 8 bytes")
    if not 0 <= counter <= 0xFFFF:
        raise ValueError("Encrypted-channel counter must fit in 2 bytes")
    if direction not in (0, 1):
        raise ValueError("Encrypted-channel direction must be 0 or 1")
    return session + counter.to_bytes(2, "little") + bytes([direction, 0, 0])

def _seal_command(key: bytes, session: bytes, sequence: int, command: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("Encrypted-channel key must be 16 bytes (128 bits)")
    if not 1 <= len(command) <= 16:
        raise ValueError("Command must be 1–16 bytes")
    if not 0 <= sequence <= 0xFFFF:
        raise ValueError("Encrypted-channel sequence must fit in 2 bytes")
    sealed = AESCCM(key, tag_length=4).encrypt(
        _connection_nonce(session, sequence, 0), command, None
    )
    ciphertext, mic = sealed[:-4], sealed[-4:]
    seq_bytes = sequence.to_bytes(2, "little")
    if len(command) <= 8:
        return [b"\x55" + seq_bytes + mic + bytes([len(ciphertext)]) + ciphertext]

    writes = []
    for offset in range(0, len(ciphertext), 13):
        chunk = ciphertext[offset:offset + 13]
        writes.append(b"\x57" + bytes([offset, len(chunk)]) + chunk)
    writes.append(b"\x58" + seq_bytes + mic + bytes([len(ciphertext)]))
    return writes

def _open_encrypted_reply(key: bytes, session: bytes,
                          frame: bytes) -> tuple[int, bytes, bool]:
    if len(key) != 16:
        raise ValueError("Encrypted-channel key must be 16 bytes (128 bits)")
    if len(frame) < 7 or frame[0] not in (0x55, 0x59):
        raise ValueError(f"Malformed encrypted reply: {frame.hex()}")
    counter = int.from_bytes(frame[1:3], "little")
    ciphertext, mic = frame[3:-4], frame[-4:]
    try:
        plaintext = AESCCM(key, tag_length=4).decrypt(
            _connection_nonce(session, counter, 1), ciphertext + mic, None
        )
    except InvalidTag as exc:
        raise EQ3Error(
            "Encrypted reply authentication failed; check that key.txt matches the "
            "encryption key stored on the thermostat"
        ) from exc
    return counter, plaintext, frame[0] == 0x59

class _EncryptedReplyAssembler:
    def __init__(self):
        self._partial: bytes | None = None
        self._last_counter: int | None = None

    def push(self, counter: int, plaintext: bytes, more: bool) -> bytes | None:
        if self._partial is not None and (
            self._last_counter is None
            or counter != ((self._last_counter + 1) & 0xFFFF)
        ):
            self.reset()
        if more:
            self._partial = (self._partial or b"") + plaintext
            self._last_counter = counter
            return None
        complete = (self._partial or b"") + plaintext
        self.reset()
        return complete

    def reset(self):
        self._partial = None
        self._last_counter = None

class EQ3Thermostat:
    """Async eQ-3 CC-RT-BLE custom-firmware client (2.00+).

    Use a BLE address or a Bleak device object. Every command opens and closes
    its own connection. Broadcast readings are passive and require no connection.
    The shared 128-bit encryption key is read from key.txt beside this module.
    """

    def __init__(self, address: str, *, timeout: float = 8.0, retries: int = 3,
                 connect_timeout: float = 15.0, key: bytes | None = None,
                 channel: str = "encrypted", pair: bool = False):
        self.address = address
        self.timeout = timeout
        self.retries = retries
        self.connect_timeout = connect_timeout
        self.pair = pair
        if channel not in ("encrypted", "plain"):
            raise ValueError("Channel must be encrypted or plain")
        self.channel = channel
        if channel == "plain":
            self.key = None
        else:
            self.key = load_broadcast_key() if key is None else (bytes(key) or None)
        if self.key is not None and len(self.key) != 16:
            raise ValueError("Encryption key must be 16 bytes (128 bits)")

    @classmethod
    async def discover(cls, timeout: float = 8.0, name: str | None = None):
        found: dict[str, dict[str, Any]] = {}

        def handler(device, adv):
            nm = adv.local_name or device.name or ""
            has_bthome_data = _service_data(adv) is not None
            if name:
                if name.lower() not in nm.lower():
                    return
            elif not (_is_eq3_name(nm) or has_bthome_data):
                return
            found[device.address] = {
                "name": nm,
                "address": device.address,
                "rssi": getattr(adv, "rssi", None),
            }

        scanner = BleakScanner(detection_callback=handler)
        await scanner.start()
        try:
            await asyncio.sleep(timeout)
        finally:
            await scanner.stop()
        return list(found.values())

    @classmethod
    async def scan_broadcasts(cls, duration: float = 10.0, *, name: str | None = None,
                              callback=None, key: bytes | None = None) -> list[Advertisement]:
        if key is None:
            key = load_broadcast_key()
            if key is None:
                logging.warning(
                    "%s is empty or missing; encrypted broadcasts will remain undecoded",
                    KEY_FILE,
                )
        latest: dict[str, Advertisement] = {}

        stop_event = asyncio.Event()

        def handler(device, adv):
            nm = adv.local_name or device.name or ""
            if name and name.lower() not in nm.lower():
                return
            sd = _service_data(adv)
            if not name and not (_is_eq3_name(nm) or sd is not None):
                return
            received_at = time.time()
            obj = latest.get(device.address)
            if obj is None:
                obj = Advertisement(
                    address=device.address, name=nm or None,
                    rssi=getattr(adv, "rssi", None), received_at=received_at,
                    field_received_at={},
                )
                latest[device.address] = obj
            else:
                obj.name = nm or obj.name
                obj.rssi = getattr(adv, "rssi", None)
                obj.received_at = received_at

            obj.raw_service_data = sd
            if sd is not None:
                try:
                    payload = decode_bthome(sd, key=key, address=device.address)
                except ValueError as e:
                    obj.decode_error = str(e)
                else:
                    obj.decode_error = None
                    obj.encrypted = bool(payload.get("encrypted", False))
                    for field_name, value in payload.items():
                        if hasattr(obj, field_name):
                            setattr(obj, field_name, value)
                            if value is not None and obj.field_received_at is not None:
                                obj.field_received_at[field_name] = received_at
                    event = {
                        key: payload[key]
                        for key in ("packet_id", "button_values", "wheel")
                        if key in payload
                    }
                    obj.event = event or None
            if callback:
                stop = callback(replace(
                    obj,
                    event=dict(obj.event) if obj.event is not None else None,
                    field_received_at=dict(obj.field_received_at or {}),
                ))
                if stop:
                    stop_event.set()

        scanner = BleakScanner(detection_callback=handler)
        await scanner.start()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            pass
        finally:
            await scanner.stop()
        return list(latest.values())

    async def _run(self, command: bytes, *, expected=None, timeout=None) -> bytes:
        if not 1 <= len(command) <= 16:
            raise ValueError("Command must be 1–16 bytes")
        wait_time = self.timeout if timeout is None else timeout
        last_error = None
        for _ in range(self.retries):
            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[bytes] = asyncio.Queue()
            sequence = 1
            def notification(_, data):
                queue.put_nowait(bytes(data))
            try:
                async with BleakClient(self.address, timeout=self.connect_timeout) as client:
                    if self.pair:
                        await client.pair()
                    session = None
                    encrypted = False
                    encrypted_notify_started = False
                    if self.key is not None and command[0] not in PLAINTEXT_COMMAND_IDS:
                        try:
                            await client.start_notify(ENC_REPLY_UUID, notification)
                            encrypted_notify_started = True
                            await client.write_gatt_char(
                                ENC_CMD_UUID, b"\x56", response=True
                            )
                        except BleakCharacteristicNotFoundError:
                            pass
                        except BleakGATTProtocolError as e:
                            if e.code != BleakGATTProtocolErrorCode.INVALID_HANDLE:
                                raise
                        else:
                            nonce_deadline = loop.time() + min(wait_time, 2.0)
                            while loop.time() < nonce_deadline:
                                try:
                                    frame = await asyncio.wait_for(
                                        queue.get(), nonce_deadline - loop.time()
                                    )
                                except asyncio.TimeoutError:
                                    break
                                if len(frame) == 8:
                                    session = frame
                                    break
                        if session is not None:
                            encrypted = True
                        elif encrypted_notify_started:
                            await client.stop_notify(ENC_REPLY_UUID)

                    if encrypted:
                        assert self.key is not None and session is not None
                        for frame in _seal_command(
                            self.key, session, sequence, command
                        ):
                            try:
                                await client.write_gatt_char(
                                    ENC_CMD_UUID, frame, response=True
                                )
                            except BleakGATTProtocolError as e:
                                if e.code == BleakGATTProtocolErrorCode.INVALID_HANDLE:
                                    raise EQ3Error(
                                        "The thermostat refused the encrypted command; "
                                        "key.txt does not match the key stored on the device"
                                    ) from e
                                raise
                    else:
                        await client.start_notify(REPLY_UUID, notification)
                        await client.write_gatt_char(CMD_UUID, command, response=True)
                    if command[0] == 0x30:
                        return b""  # protocol explicitly has no reply
                    assembler = _EncryptedReplyAssembler()
                    deadline = loop.time() + wait_time
                    while loop.time() < deadline:
                        try:
                            frame = await asyncio.wait_for(queue.get(), deadline - loop.time())
                        except asyncio.TimeoutError:
                            break
                        if not frame:
                            continue
                        if encrypted and frame[0] in (0x55, 0x59):
                            counter, plaintext, more = _open_encrypted_reply(
                                self.key, session, frame
                            )
                            frame = assembler.push(counter, plaintext, more)
                            if frame is None:
                                continue
                        if expected is not None:
                            if expected(frame):
                                return frame
                            continue
                        if frame[0] == 0x02:
                            return frame
                        if frame[0] == 0x01 and len(frame) >= 2 and frame[1] == command[0]:
                            return frame
                        if command[0] == 0x00 and frame[0] == 0x01 and len(frame) == 15:
                            return frame
                    last_error = CommandTimeout(f"No matching reply for {command.hex()}")
            except Exception as e:
                last_error = e
            # Context manager disconnects on every attempt.
        raise EQ3Error(f"Command {command.hex()} failed after {self.retries} attempts: {last_error}") from last_error

    async def status(self) -> ThermostatStatus:
        return await self.set_clock()

    async def version(self) -> dict[str, Any]:
        frame = await self._run(b"\x00", expected=lambda f: f[:1] == b"\x01" and len(f) == 15)
        if len(frame) != 15 or frame[0] != 0x01 or frame[2:4] != b"\x00\x00":
            raise EQ3Error(f"Unexpected version frame: {frame.hex()}")
        version = frame[1]
        serial = bytes((b - 0x30) & 0xFF for b in frame[4:14]).decode("latin1")
        return {"version": version, "version_string": f"{version // 100}.{version % 100:02d}",
                "serial": serial, "raw": frame.hex()}

    async def set_temperature(self, celsius: float):
        if not 4.5 <= celsius <= 30.0 or celsius * 2 != round(celsius * 2):
            raise ValueError("Temperature must be 4.5–30 °C in 0.5 °C steps")
        return decode_status(await self._run(bytes([0x41, round(celsius * 2)])))

    async def set_mode(self, mode: str, temperature: float | None = None):
        modes = {"auto": 0, "manual": 1, "holiday": 2}
        if mode not in modes:
            raise ValueError("Mode must be auto, manual, or holiday")
        sub = 0
        if temperature is not None:
            if temperature in (4.5, 30.0):
                sub = round(temperature * 2)
            elif temperature * 2 == round(temperature * 2) and 4.5 <= temperature <= 30:
                sub = round(temperature * 2)
            else:
                raise ValueError("Temperature must be 4.5–30 °C in 0.5 °C steps")
        return decode_status(await self._run(bytes([0x40, (modes[mode] << 6) | sub])))

    async def set_lock(self, locked: bool):
        return decode_status(await self._run(bytes([0x80, int(locked), 0])))

    async def set_window(self, open_: bool):
        await self._run(bytes([0x30, int(open_)]))
        return {"sent": True, "note": "cmd 0x30 has no reply; confirm via broadcast/status"}

    async def boost(self, enabled: bool):
        return decode_status(await self._run(bytes([0x45, int(enabled)])))

    async def comfort(self):
        return decode_status(await self._run(b"\x43"))

    async def eco(self):
        return decode_status(await self._run(b"\x44"))

    async def set_comfort_eco(self, comfort: float, eco: float):
        for t in (comfort, eco):
            if not 4.5 <= t <= 30 or t * 2 != round(t * 2):
                raise ValueError("Temperatures must be 4.5–30 °C in 0.5 °C steps")
        return decode_status(await self._run(bytes([0x11, round(comfort * 2), round(eco * 2)])))

    async def settings(self):
        frame = await self._run(b"\x16", expected=lambda f: f[:2] == b"\x01\x16")
        if len(frame) < 15:
            raise EQ3Error(f"Short settings reply: {frame.hex()}")
        b = frame[2:15]
        return {
            "comfort_temperature": b[0] / 2, "eco_temperature": b[1] / 2,
            "calibration_offset": (b[2] - 7) / 2,
            "window_temperature": b[3] / 2, "window_duration_minutes": b[4] * 5,
            "boost_duration_minutes": b[5], "boost_valve_percent": b[6],
            "idle_screen_mask": b[7], "idle_rotation_seconds": b[8],
            "screen_contrast": b[9], "window_auto_detect": bool(b[10]),
            "descaling_interval": b[11], "descaling_battery_hold": bool(b[12]),
        }

    async def get_schedule_day(self, day: int) -> dict[str, Any]:
        if not 0 <= day <= 6:
            raise ValueError("Schedule day must be 0–6 (Saturday=0)")
        frame = await self._run(bytes([0x20, day]), expected=lambda f: f[:2] == bytes([0x21, day]))
        return decode_schedule(frame)

    async def get_week(self):
        return [await self.get_schedule_day(d) for d in range(7)]

    async def set_schedule(self, day: int, slots: list[tuple[float, int]]):
        """Write one day (0-6), weekend (7), weekdays (8), or all days (9).

        slots must contain exactly seven (temperature °C, end time in minutes)
        pairs. Times are 10-minute increments; final slot should normally end at 1440.
        """
        if day not in range(10):
            raise ValueError("Schedule day/group must be 0–9")
        if len(slots) != 7:
            raise ValueError("Exactly seven schedule slots are required")
        payload = bytearray([0x10, day])
        previous_time = -1
        for temp, minutes in slots:
            if not 4.5 <= temp <= 30 or temp * 2 != round(temp * 2):
                raise ValueError("Schedule temperatures must be 4.5–30 °C in 0.5 °C steps")
            if minutes < 0 or minutes > 1440 or minutes % 10:
                raise ValueError("Schedule end times must be 0–1440 minutes, in 10-minute increments")
            if minutes < previous_time:
                raise ValueError("Schedule times must be ascending")
            previous_time = minutes
            payload.extend([round(temp * 2), minutes // 10])
        frame = await self._run(bytes(payload), expected=lambda f: f[:2] == b"\x01\x10")
        return {"written": True, "reply": frame.hex(),
                "note": "Stored schedule takes effect at the next switch point."}

    async def set_clock(self, dt: datetime | None = None):
        dt = dt or datetime.now()
        if not (2000 <= dt.year <= 2255):
            raise ValueError("Year must fit one byte (2000–2255)")
        command = bytes([0x03, dt.year - 2000, dt.month, dt.day, dt.hour, dt.minute, dt.second])
        return decode_status(await self._run(command))

async def cli_async(args):
    if args.command == "scan":
        found = await EQ3Thermostat.discover(args.duration, args.name)
        print(json.dumps(found, indent=2))
        return
    if args.command == "broadcast":
        def show(item):
            d = asdict(item)
            if d["raw_service_data"] is not None:
                d["raw_service_data"] = d["raw_service_data"].hex()
            print(json.dumps(d), flush=True)
        await EQ3Thermostat.scan_broadcasts(args.duration, name=args.name, callback=show)
        return
    if not args.address:
        raise SystemExit("--address is required for this command")
    dev = EQ3Thermostat(
        args.address,
        timeout=args.timeout,
        retries=args.retries,
        channel=args.channel,
        pair=args.pair,
    )
    if args.command == "version":
        result = await dev.version()
    elif args.command == "status":
        result = asdict(await dev.status())
        result["raw"] = result["raw"].hex()
    elif args.command == "set-temp":
        result = asdict(await dev.set_temperature(args.temperature))
        result["raw"] = result["raw"].hex()
    elif args.command == "mode":
        result = asdict(await dev.set_mode(args.mode, args.temperature))
        result["raw"] = result["raw"].hex()
    elif args.command == "lock":
        result = asdict(await dev.set_lock(args.locked))
        result["raw"] = result["raw"].hex()
    elif args.command == "window":
        result = await dev.set_window(args.open)
    elif args.command == "boost":
        result = asdict(await dev.boost(args.enabled))
        result["raw"] = result["raw"].hex()
    elif args.command == "comfort":
        result = asdict(await dev.comfort())
        result["raw"] = result["raw"].hex()
    elif args.command == "eco":
        result = asdict(await dev.eco())
        result["raw"] = result["raw"].hex()
    elif args.command == "settings":
        result = await dev.settings()
    elif args.command == "schedule-get":
        result = await dev.get_week() if args.day is None else await dev.get_schedule_day(args.day)
    elif args.command == "schedule-set":
        slots = json.loads(args.slots)
        result = await dev.set_schedule(args.day, [(float(x[0]), int(x[1])) for x in slots])
    elif args.command == "clock":
        result = asdict(await dev.set_clock())
        result["raw"] = result["raw"].hex()
    print(json.dumps(result, indent=2, default=str))

def _parse_bool_arg(value: str) -> bool:
    normalized = value.lower()
    if normalized in ("1", "true", "on", "yes"):
        return True
    if normalized in ("0", "false", "off", "no"):
        return False
    raise argparse.ArgumentTypeError("expected true/false, yes/no, on/off, or 1/0")

def build_parser():
    p = argparse.ArgumentParser(prog="eq3", description="eQ-3 CC-RT-BLE custom firmware 2.00+ client")
    p.add_argument("--address", help="BLE MAC address or Bleak device address")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument(
        "--channel",
        choices=["encrypted", "plain"],
        default="encrypted",
        help="encrypted uses key.txt and the sealed 2.00 characteristics; plain uses paired ordinary characteristics",
    )
    p.add_argument(
        "--pair",
        action="store_true",
        help="pair over Bluetooth before sending a command; mainly for plain-channel access",
    )
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--duration", type=float, default=8)
    s.add_argument("--name")
    s = sub.add_parser("broadcast")
    s.add_argument("--duration", type=float, default=30)
    s.add_argument("--name")
    sub.add_parser("version")
    sub.add_parser("status")
    s = sub.add_parser("set-temp")
    s.add_argument("temperature", type=float)
    s = sub.add_parser("mode")
    s.add_argument("mode", choices=["auto", "manual", "holiday"])
    s.add_argument("--temperature", type=float)
    s = sub.add_parser("lock")
    s.add_argument("locked", type=_parse_bool_arg)
    s = sub.add_parser("window")
    s.add_argument("open", type=_parse_bool_arg)
    s = sub.add_parser("boost")
    s.add_argument("enabled", type=_parse_bool_arg)
    sub.add_parser("comfort")
    sub.add_parser("eco")
    sub.add_parser("settings")
    s = sub.add_parser("schedule-get")
    s.add_argument("--day", type=int, choices=range(7))
    s = sub.add_parser("schedule-set")
    s.add_argument("day", type=int, choices=range(10))
    s.add_argument("slots", help='JSON array of 7 [temperature_c, until_minutes] pairs')
    sub.add_parser("clock")
    return p

def main():
    logging.basicConfig(level=logging.WARNING)
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(cli_async(args))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"eq3: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
