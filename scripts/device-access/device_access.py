#!/usr/bin/env python3
"""Device certificate + user credential access controller.

This is the operational companion to the FreeRADIUS policy in
``raddb/policy.d/device-access``.  It manages the small device/user registry,
session lookup, CRL revocation, and RFC 5176 Disconnect-Request delivery.

It uses only the Python standard library so the acceptance workflow can run on
a minimal FreeRADIUS build host.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


EXIT_OK = 0
EXIT_DENY = 3
EXIT_ERROR = 2
DISCONNECT_CODE = 40
DISCONNECT_ACK_CODE = 41


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_serial(serial: str | None) -> str:
    if not serial:
        return ""
    return "".join(ch for ch in serial.upper() if ch in "0123456789ABCDEF")


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("ascii"),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt$16384$8$1${salt}${digest.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, n_text, r_text, p_text, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt.encode("ascii"),
            n=int(n_text),
            r=int(r_text),
            p=int(p_text),
            dklen=len(expected) // 2,
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


def run_cmd(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


class DeviceAccessStore:
    def __init__(self, home: Path):
        self.home = home
        self.path = home / "registry.json"
        self.lock_path = home / "registry.lock"
        self.home.mkdir(parents=True, exist_ok=True)

    def _empty(self) -> dict[str, Any]:
        return {"users": {}, "devices": {}, "sessions": {}, "revoked": []}

    @contextlib.contextmanager
    def _locked(self):
        self.home.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                if self.path.exists():
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                else:
                    data = self._empty()
                for key, default in self._empty().items():
                    data.setdefault(key, default)
                yield data
                temporary = self.path.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                os.replace(temporary, self.path)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def read(self) -> dict[str, Any]:
        with self._locked() as data:
            return json.loads(json.dumps(data))

    def mutate(self, fn) -> Any:
        with self._locked() as data:
            return fn(data)

    def add_user(self, username: str, password: str) -> None:
        def update(data):
            data["users"][username] = {"password": hash_password(password)}

        self.mutate(update)

    def add_device(self, serial: str, common_name: str, username: str, **extra: str) -> None:
        serial = normalize_serial(serial)

        def update(data):
            device = {"cn": common_name, "user": username}
            device.update({k: v for k, v in extra.items() if v is not None})
            data["devices"][serial] = device

        self.mutate(update)

    def revoke(self, serial: str) -> bool:
        serial = normalize_serial(serial)

        def update(data):
            if serial not in data["revoked"]:
                data["revoked"].append(serial)
            for session in data["sessions"].values():
                if normalize_serial(session.get("serial")) == serial:
                    session["revoke_pending"] = True
            return True

        return bool(self.mutate(update))

    def start_session(self, session_id: str, session_data: dict[str, Any]) -> None:
        def update(data):
            session = dict(session_data)
            session["session_id"] = session_id
            session["active"] = True
            session["started_at"] = now_utc().isoformat()
            data["sessions"][session_id] = session

        self.mutate(update)

    def stop_session(self, session_id: str) -> None:
        def update(data):
            session = data["sessions"].get(session_id)
            if session:
                session["active"] = False
                session["stopped_at"] = now_utc().isoformat()

        self.mutate(update)

    def active_sessions(self, serial: str | None = None, username: str | None = None) -> list[dict[str, Any]]:
        data = self.read()
        serial = normalize_serial(serial) if serial else None
        result = []
        for session in data["sessions"].values():
            if not session.get("active", False):
                continue
            if serial and normalize_serial(session.get("serial")) != serial:
                continue
            if username and session.get("username") != username:
                continue
            result.append(session)
        return result


def cert_info(cert_path: Path) -> dict[str, str]:
    result = run_cmd(
        [
            "openssl", "x509", "-in", str(cert_path), "-noout",
            "-serial", "-subject", "-startdate", "-enddate",
            "-nameopt", "RFC2253",
        ]
    )
    if result.returncode != 0:
        raise ValueError(f"cannot parse certificate {cert_path}: {result.stdout.strip()}")

    info: dict[str, str] = {"path": str(cert_path)}
    for line in result.stdout.splitlines():
        if line.startswith("serial="):
            info["serial"] = normalize_serial(line.split("=", 1)[1])
        elif line.startswith("subject="):
            subject = line.split("=", 1)[1]
            info["subject"] = subject
            for component in subject.split(","):
                if component.startswith("CN="):
                    info["cn"] = component[3:]
                    break
        elif line.startswith("notBefore="):
            info["not_before"] = line.split("=", 1)[1]
        elif line.startswith("notAfter="):
            info["not_after"] = line.split("=", 1)[1]
    if "serial" not in info:
        raise ValueError(f"certificate has no serial: {cert_path}")
    return info


def verify_cert(cert_path: Path, ca_path: Path, crl_path: Path | None = None) -> tuple[bool, str]:
    cmd = ["openssl", "verify", "-purpose", "sslclient", "-CAfile", str(ca_path)]
    if crl_path and crl_path.exists():
        cmd += ["-crl_check", "-CRLfile", str(crl_path)]
    cmd.append(str(cert_path))
    result = run_cmd(cmd)
    output = result.stdout.strip()
    if result.returncode == 0:
        return True, output or "OK"
    lowered = output.lower()
    if "revoked" in lowered:
        reason = "cert_revoked"
    elif "expired" in lowered or "not yet valid" in lowered:
        reason = "cert_expired"
    elif "unable to get local issuer" in lowered or "self-signed certificate" in lowered:
        reason = "cert_untrusted"
    else:
        reason = "cert_invalid"
    return False, f"{reason}: {output}"


def cert_time_valid(cert_path: Path) -> tuple[bool, str]:
    """Check the certificate validity window, independently of CA validation."""
    result = run_cmd(["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "0"])
    if result.returncode == 0:
        return True, "OK"
    return False, "cert_expired: certificate is outside its validity window"


def evaluate_access(
    store: DeviceAccessStore,
    cert_path: Path,
    username: str,
    password: str,
    ca_path: Path | None = None,
    crl_path: Path | None = None,
) -> dict[str, Any]:
    try:
        certificate = cert_info(cert_path)
    except ValueError as exc:
        return {"allowed": False, "reason": "cert_invalid", "detail": str(exc)}

    time_valid, detail = cert_time_valid(cert_path)
    if not time_valid:
        return {"allowed": False, "reason": "cert_expired", "detail": detail, "cert": certificate}

    if ca_path:
        valid, detail = verify_cert(cert_path, ca_path, crl_path)
        if not valid:
            reason = detail.split(":", 1)[0] if ":" in detail else "cert_invalid"
            return {"allowed": False, "reason": reason, "detail": detail, "cert": certificate}

    data = store.read()
    serial = certificate["serial"]
    if serial in {normalize_serial(item) for item in data.get("revoked", [])}:
        return {
            "allowed": False,
            "reason": "cert_revoked",
            "detail": "serial is in operational revocation list",
            "cert": certificate,
        }

    device = data.get("devices", {}).get(serial)
    if not device:
        return {
            "allowed": False,
            "reason": "device_unregistered",
            "detail": f"serial {serial} is not bound to a device",
            "cert": certificate,
        }

    expected_cn = device.get("cn")
    actual_cn = certificate.get("cn")
    if expected_cn and actual_cn and expected_cn != actual_cn:
        return {
            "allowed": False,
            "reason": "device_cn_mismatch",
            "detail": f"expected CN {expected_cn}, got {actual_cn}",
            "cert": certificate,
            "device": device,
        }

    bound_user = device.get("user")
    if bound_user != username:
        return {
            "allowed": False,
            "reason": "device_user_mismatch",
            "detail": f"device is bound to {bound_user!r}, not {username!r}",
            "cert": certificate,
            "device": device,
        }

    user = data.get("users", {}).get(username)
    if not user or not verify_password(password, user.get("password")):
        return {
            "allowed": False,
            "reason": "bad_credentials",
            "detail": "username or password is incorrect",
            "cert": certificate,
            "device": device,
        }

    return {
        "allowed": True,
        "reason": "allow",
        "detail": "certificate, device binding, and credentials are valid",
        "cert": certificate,
        "device": device,
    }


def encode_string_attr(attr_type: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("!BB", attr_type, len(raw) + 2) + raw


def encode_ip_attr(attr_type: int, value: str) -> bytes:
    raw = ipaddress.ip_address(value).packed
    return struct.pack("!BB", attr_type, len(raw) + 2) + raw


def parse_attributes(packet: bytes) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    offset = 20
    while offset + 2 <= len(packet):
        attr_type, length = packet[offset], packet[offset + 1]
        if length < 2 or offset + length > len(packet):
            break
        attrs[attr_type] = packet[offset + 2 : offset + length]
        offset += length
    return attrs


def radius_authenticator(prefix: bytes, attributes: bytes, secret: str) -> bytes:
    return hashlib.md5(prefix + attributes + secret.encode("utf-8")).digest()


def send_disconnect(
    server: str,
    port: int,
    secret: str,
    username: str | None = None,
    session_id: str | None = None,
    calling_station: str | None = None,
    nas_ip: str | None = None,
    timeout: float = 2.0,
) -> dict[str, Any]:
    attributes = b""
    if username:
        attributes += encode_string_attr(1, username)
    if nas_ip:
        attributes += encode_ip_attr(4, nas_ip)
    if calling_station:
        attributes += encode_string_attr(31, calling_station)
    if session_id:
        attributes += encode_string_attr(44, session_id)

    message_auth_attr = struct.pack("!BB", 80, 18) + b"\x00" * 16
    all_attributes = attributes + message_auth_attr
    identifier = secrets.randbelow(256)
    length = 20 + len(all_attributes)
    packet = bytearray(
        struct.pack("!BBH", DISCONNECT_CODE, identifier, length)
        + b"\x00" * 16
        + all_attributes
    )
    message_auth = hmac.new(secret.encode("utf-8"), bytes(packet), hashlib.md5).digest()
    packet[-16:] = message_auth
    request_auth = hashlib.md5(bytes(packet) + secret.encode("utf-8")).digest()
    packet[4:20] = request_auth

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        started = time.monotonic()
        client.sendto(packet, (server, port))
        data, addr = client.recvfrom(4096)
        elapsed = time.monotonic() - started

    response_code, response_id, response_length = struct.unpack("!BBH", data[:4])
    if response_id != identifier or response_length != len(data):
        raise RuntimeError("malformed Disconnect-ACK response")
    response_auth = data[4:20]
    expected_auth = hashlib.md5(
        data[:4] + request_auth + data[20:] + secret.encode("utf-8")
    ).digest()
    if not hmac.compare_digest(response_auth, expected_auth):
        raise RuntimeError("Disconnect-ACK authenticator verification failed")
    return {
        "response_code": response_code,
        "ack": response_code == DISCONNECT_ACK_CODE,
        "elapsed_seconds": elapsed,
        "addr": addr,
    }


class FakeNasDisconnectServer(threading.Thread):
    def __init__(self, secret: str = "testing123"):
        super().__init__(daemon=True)
        self.secret = secret
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.received: dict[str, Any] | None = None
        self.error: Exception | None = None
        self._done = threading.Event()

    def run(self) -> None:
        try:
            self.socket.settimeout(5)
            packet, addr = self.socket.recvfrom(4096)
            request_auth = packet[4:20]
            expected = hashlib.md5(
                packet[:4] + b"\x00" * 16 + packet[20:] + self.secret.encode()
            ).digest()
            if not hmac.compare_digest(request_auth, expected):
                raise RuntimeError("request authenticator mismatch")

            raw_attrs = parse_attributes(packet)
            self.received = {
                "code": packet[0],
                "identifier": packet[1],
                "authenticator_valid": True,
                "username": raw_attrs.get(1, b"").decode(),
                "nas_ip": socket.inet_ntoa(raw_attrs[4]) if 4 in raw_attrs else None,
                "calling_station": raw_attrs.get(31, b"").decode(),
                "session_id": raw_attrs.get(44, b"").decode(),
                "addr": addr,
            }

            response_header_prefix = struct.pack("!BBH", DISCONNECT_ACK_CODE, packet[1], 20)
            response_auth = hashlib.md5(
                response_header_prefix + request_auth + self.secret.encode()
            ).digest()
            self.socket.sendto(response_header_prefix + response_auth, addr)
        except Exception as exc:  # noqa: BLE001 - reported to test thread
            self.error = exc
        finally:
            self._done.set()

    def wait(self, timeout: float = 3.0) -> bool:
        return self._done.wait(timeout)

    def close(self) -> None:
        self.socket.close()


def write_openssl_ca_config(path: Path, pki: Path) -> None:
    path.write_text(
        f"""[ca]
default_ca = device_ca

[device_ca]
dir = {pki}
database = {pki / 'index.txt'}
crlnumber = {pki / 'crlnumber'}
serial = {pki / 'serial'}
new_certs_dir = {pki / 'newcerts'}
certificate = {pki / 'ca.pem'}
private_key = {pki / 'ca.key'}
default_md = sha256
default_days = 30
default_crl_days = 7
policy = device_policy
email_in_dn = no
unique_subject = no
copy_extensions = copy

[device_policy]
commonName = supplied

""",
        encoding="utf-8",
    )


def issue_fixture_cert(pki: Path, name: str, expired: bool = False) -> dict[str, str]:
    key = pki / f"{name}.key"
    csr = pki / f"{name}.csr"
    crt = pki / f"{name}.crt"
    ext = pki / f"{name}.ext"
    ext.write_text(
        "[client_ext]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
        f"subjectAltName=DNS:{name}\n",
        encoding="utf-8",
    )

    result = run_cmd(
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", f"/CN={name}"]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)

    cmd = [
        "openssl", "ca", "-batch", "-config", str(pki / "ca.cnf"),
        "-in", str(csr), "-out", str(crt),
        "-extensions", "client_ext", "-extfile", str(ext),
    ]
    if expired:
        start = (now_utc() - timedelta(days=2)).strftime("%y%m%d%H%M%SZ")
        end = (now_utc() - timedelta(days=1)).strftime("%y%m%d%H%M%SZ")
        cmd += ["-startdate", start, "-enddate", end]
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    return cert_info(crt)


def create_fixture(home: Path) -> tuple[DeviceAccessStore, Path]:
    pki = home / "pki"
    pki.mkdir(parents=True, exist_ok=True)
    (pki / "newcerts").mkdir(exist_ok=True)
    (pki / "index.txt").write_text("", encoding="utf-8")
    (pki / "crlnumber").write_text("1000\n", encoding="utf-8")
    (pki / "serial").write_text("1000\n", encoding="utf-8")
    write_openssl_ca_config(pki / "ca.cnf", pki)

    result = run_cmd(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.pem"),
         "-days", "30", "-subj", "/CN=FreeRADIUS Device Access Test CA"]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)

    good = issue_fixture_cert(pki, "device-good")
    wrong = issue_fixture_cert(pki, "device-wrong")
    expired = issue_fixture_cert(pki, "device-expired", expired=True)

    state = home / "state"
    store = DeviceAccessStore(state)
    store.add_user("alice", "alice-pass")
    store.add_device(good["serial"], good["cn"], "alice")
    store.add_device(expired["serial"], expired["cn"], "alice")
    # Deliberately do not register device-wrong.
    return store, pki


def revoke_fixture_cert(pki: Path, cert_path: Path) -> Path:
    result = run_cmd(
        ["openssl", "ca", "-batch", "-config", str(pki / "ca.cnf"), "-revoke", str(cert_path)]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    crl = pki / "ca.crl"
    result = run_cmd(
        ["openssl", "ca", "-batch", "-config", str(pki / "ca.cnf"), "-gencrl", "-out", str(crl)]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    return crl


def run_selftest() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="freeradius-device-access-"))
    store, pki = create_fixture(workdir)
    ca = pki / "ca.pem"

    cases = [
        (
            "证书对凭据对",
            pki / "device-good.crt",
            "alice",
            "alice-pass",
            True,
            "allow",
        ),
        (
            "证书错凭据对",
            pki / "device-wrong.crt",
            "alice",
            "alice-pass",
            False,
            "device_unregistered",
        ),
        (
            "证书过期",
            pki / "device-expired.crt",
            "alice",
            "alice-pass",
            False,
            "cert_expired",
        ),
    ]

    print("== EAP-TLS device/user combination ==")
    for name, cert, user, password, expected_allowed, expected_reason in cases:
        result = evaluate_access(store, cert, user, password, ca)
        passed = result["allowed"] is expected_allowed and result["reason"] == expected_reason
        status = "PASS" if passed else "FAIL"
        print(f"{status} | {name} | allowed={result['allowed']!s:<5} | {result['reason']}")
        if not passed:
            print(json.dumps(result, indent=2, default=str))
            print(f"workdir={workdir}")
            return 1

    good = cert_info(pki / "device-good.crt")
    dm_server = FakeNasDisconnectServer()
    dm_server.start()
    store.start_session(
        "sess-acceptance-001",
        {
            "username": "alice",
            "serial": good["serial"],
            "nas_ip": "127.0.0.1",
            "calling_station": "02:00:00:00:00:01",
            "dm_port": dm_server.port,
        },
    )

    store.revoke(good["serial"])
    crl = revoke_fixture_cert(pki, pki / "device-good.crt")
    revoked_result = evaluate_access(store, pki / "device-good.crt", "alice", "alice-pass", ca, crl)
    if revoked_result["allowed"] or revoked_result["reason"] != "cert_revoked":
        print("FAIL | revocation rejects new authentication")
        print(json.dumps(revoked_result, indent=2, default=str))
        return 1
    print("PASS | revoked certificate rejected on next authentication | cert_revoked")

    sessions = store.active_sessions(serial=good["serial"])
    if len(sessions) != 1:
        print(f"FAIL | expected one active session, found {len(sessions)}")
        return 1
    session = sessions[0]
    dm_result = send_disconnect(
        session.get("nas_ip", "127.0.0.1"),
        int(session["dm_port"]),
        "testing123",
        username=session.get("username"),
        session_id=session.get("session_id"),
        calling_station=session.get("calling_station"),
        nas_ip=session.get("nas_ip"),
    )
    if not dm_server.wait(3.0):
        print("FAIL | NAS did not receive Disconnect-Request")
        if dm_server.error:
            print(repr(dm_server.error))
        return 1
    if dm_server.error:
        print(f"FAIL | fake NAS rejected DM: {dm_server.error!r}")
        return 1
    if not dm_result["ack"]:
        print(f"FAIL | expected Disconnect-ACK, code {dm_result['response_code']}")
        return 1

    received = dm_server.received or {}
    expected_attrs = {
        "code": DISCONNECT_CODE,
        "username": "alice",
        "session_id": "sess-acceptance-001",
        "calling_station": "02:00:00:00:00:01",
        "nas_ip": "127.0.0.1",
        "authenticator_valid": True,
    }
    for key, expected in expected_attrs.items():
        if received.get(key) != expected:
            print(f"FAIL | DM attribute {key}: expected {expected!r}, got {received.get(key)!r}")
            return 1

    if dm_result["elapsed_seconds"] > 2.0:
        print(f"FAIL | disconnect took {dm_result['elapsed_seconds']:.3f}s")
        return 1

    print(
        "PASS | revocation delivers Disconnect-Request and receives ACK | "
        f"{dm_result['elapsed_seconds'] * 1000:.1f} ms"
    )
    dm_server.close()
    print(f"workdir={workdir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", default=os.environ.get("DEVICE_ACCESS_HOME", ".device-access"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest")

    user_add = sub.add_parser("user-add")
    user_add.add_argument("username")
    user_add.add_argument("password")

    device_add = sub.add_parser("device-add")
    device_add.add_argument("serial")
    device_add.add_argument("cn")
    device_add.add_argument("username")
    device_add.add_argument("--nas-ip")

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--cert", required=True, type=Path)
    evaluate.add_argument("--user", required=True)
    evaluate.add_argument("--password", required=True)
    evaluate.add_argument("--ca", type=Path)
    evaluate.add_argument("--crl", type=Path)

    session_start = sub.add_parser("session-start")
    session_start.add_argument("session_id")
    session_start.add_argument("--user", required=True)
    session_start.add_argument("--serial", required=True)
    session_start.add_argument("--nas-ip", default="127.0.0.1")
    session_start.add_argument("--calling-station")
    session_start.add_argument("--dm-port", type=int, default=3799)

    session_stop = sub.add_parser("session-stop")
    session_stop.add_argument("session_id")

    sub.add_parser("sessions")
    sub.add_parser("accounting", help=argparse.SUPPRESS)

    revoke = sub.add_parser("revoke")
    revoke.add_argument("--serial", required=True)
    revoke.add_argument("--disconnect", action="store_true")
    revoke.add_argument("--secret", default=os.environ.get("RADIUS_COA_SECRET", "testing123"))
    revoke.add_argument("--timeout", type=float, default=2.0)

    disconnect = sub.add_parser("disconnect")
    disconnect.add_argument("--serial")
    disconnect.add_argument("--user")
    disconnect.add_argument("--secret", default=os.environ.get("RADIUS_COA_SECRET", "testing123"))
    disconnect.add_argument("--port", type=int, default=3799)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "selftest":
        return run_selftest()

    store = DeviceAccessStore(Path(args.home))
    if args.command == "user-add":
        store.add_user(args.username, args.password)
        return EXIT_OK
    if args.command == "device-add":
        extra = {"nas_ip": args.nas_ip} if args.nas_ip else {}
        store.add_device(args.serial, args.cn, args.username, **extra)
        return EXIT_OK
    if args.command == "evaluate":
        result = evaluate_access(store, args.cert, args.user, args.password, args.ca, args.crl)
        print(json.dumps(result, indent=2, default=str))
        return EXIT_OK if result["allowed"] else EXIT_DENY
    if args.command == "session-start":
        store.start_session(
            args.session_id,
            {
                "username": args.user,
                "serial": normalize_serial(args.serial),
                "nas_ip": args.nas_ip,
                "calling_station": args.calling_station,
                "dm_port": args.dm_port,
            },
        )
        return EXIT_OK
    if args.command == "session-stop":
        store.stop_session(args.session_id)
        return EXIT_OK
    if args.command == "sessions":
        print(json.dumps(store.active_sessions(), indent=2))
        return EXIT_OK
    if args.command == "accounting":
        status = os.environ.get("ACCT_STATUS_TYPE", "")
        session_id = os.environ.get("ACCT_SESSION_ID", "")
        if not session_id:
            return EXIT_OK
        if status in {"Start", "Interim-Update", "InterimUpdate", "1", "3"}:
            store.start_session(
                session_id,
                {
                    "username": os.environ.get("USER_NAME", ""),
                    "nas_ip": os.environ.get("NAS_IP_ADDRESS") or os.environ.get("NAS_IPV6_ADDRESS", ""),
                    "calling_station": os.environ.get("CALLING_STATION_ID", ""),
                    "nas_identifier": os.environ.get("NAS_IDENTIFIER", ""),
                },
            )
        elif status in {"Stop", "2"}:
            store.stop_session(session_id)
        return EXIT_OK
    if args.command == "revoke":
        store.revoke(args.serial)
        if not args.disconnect:
            return EXIT_OK

        sessions = store.active_sessions(serial=args.serial)
        if not sessions:
            data = store.read()
            device = data.get("devices", {}).get(normalize_serial(args.serial), {})
            if device.get("user"):
                sessions = store.active_sessions(username=device["user"])
        results = []
        for session in sessions:
            result = send_disconnect(
                session.get("nas_ip", "127.0.0.1"),
                int(session.get("dm_port", 3799)),
                args.secret,
                username=session.get("username"),
                session_id=session.get("session_id"),
                calling_station=session.get("calling_station"),
                nas_ip=session.get("nas_ip"),
                timeout=args.timeout,
            )
            results.append({"session_id": session.get("session_id"), **result})
        print(json.dumps({"revoked": normalize_serial(args.serial), "results": results}, indent=2))
        return EXIT_OK if all(item.get("ack") for item in results) else EXIT_DENY
    if args.command == "disconnect":
        sessions = store.active_sessions(serial=args.serial, username=args.user)
        if not sessions:
            print(json.dumps({"sent": 0, "reason": "no active sessions"}, indent=2))
            return EXIT_DENY
        results = []
        for session in sessions:
            target = session.get("nas_ip", "127.0.0.1")
            port = int(session.get("dm_port", args.port))
            result = send_disconnect(
                target,
                port,
                args.secret,
                username=session.get("username"),
                session_id=session.get("session_id"),
                calling_station=session.get("calling_station"),
                nas_ip=session.get("nas_ip"),
            )
            result["session_id"] = session.get("session_id")
            results.append(result)
        print(json.dumps({"sent": len(results), "results": results}, indent=2))
        return EXIT_OK if all(item["ack"] for item in results) else EXIT_DENY
    parser.error(f"unhandled command {args.command}")
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
