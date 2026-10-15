#!/usr/bin/env python
"""Fail-closed lifecycle broker for authorized Android dynamic analysis.

This module contains no Android, su or Frida implementation. A concrete adapter
must implement DynamicBackend. The broker is attach-only: it has no spawn,
spawn-gating, system-process recovery or generic kill API.
"""
from __future__ import annotations

import abc
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import uuid
from collections.abc import Iterator


SCHEMA_VERSION = 1
MAX_TTL_SECONDS = 900
PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{2,255}$")
PURPOSE_PATTERN = re.compile(r"^[\w .:/@+()#-]{3,256}$", re.UNICODE)
SESSION_PATTERN = re.compile(r"^[a-f0-9]{32}$")

# UID >= 10000 is still required. Names add defense in depth against misleading
# process metadata returned by an adapter.
DENIED_EXACT_NAMES = {
    "zygote", "zygote32", "zygote64", "webview_zygote", "system_server",
    "surfaceflinger", "servicemanager", "hwservicemanager",
    "vndservicemanager", "init",
}
DENIED_PACKAGE_PREFIXES = (
    "android", "com.android.systemui", "com.android.launcher",
    "com.google.android.apps.nexuslauncher",
)


class BrokerError(RuntimeError):
    """Stable error carrying a machine-readable denial/failure code."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    package: str
    cmdline: str
    start_ticks: int

    def fingerprint(self) -> str:
        raw = json.dumps(dataclasses.asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class RuntimeTrace:
    name: str
    pid: int
    tracer_pid: int


@dataclasses.dataclass(frozen=True)
class ServerIdentity:
    pid: int
    start_ticks: int
    endpoint: str = "127.0.0.1:27042"


@dataclasses.dataclass(frozen=True)
class Attachment:
    token: str
    target_pid: int


class DynamicBackend(abc.ABC):
    """Narrow adapter contract; implementations must verify owned identities."""

    @abc.abstractmethod
    def read_process(self, pid: int) -> ProcessIdentity | None:
        """Return a stable procfs identity or None if the PID vanished."""

    @abc.abstractmethod
    def runtime_traces(self) -> list[RuntimeTrace]:
        """Return TracerPid observations for zygote*, system_server and peers."""

    @abc.abstractmethod
    def list_frida_servers(self) -> list[ServerIdentity]:
        """Return every visible Frida server without adopting it."""

    @abc.abstractmethod
    def start_owned_server(self, session_id: str) -> ServerIdentity:
        """Start one loopback-only server and return its stable identity."""

    @abc.abstractmethod
    def attach(self, server: ServerIdentity, target: ProcessIdentity) -> Attachment:
        """Attach to an already-running target PID; never spawn or gate."""

    @abc.abstractmethod
    def detach_owned(self, attachment: Attachment) -> bool:
        """Detach only the attachment token created by this broker."""

    @abc.abstractmethod
    def stop_owned_server(self, server: ServerIdentity) -> bool:
        """Stop only the supplied PID/start_ticks server identity."""


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat()


def _parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


def _atomic_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class DynamicSessionBroker:
    """Persistent, fail-closed dynamic-session state machine."""

    def __init__(self, state_root: pathlib.Path, backend: DynamicBackend, *,
                 now=_utc_now, max_ttl_seconds: int = MAX_TTL_SECONDS):
        self.state_root = pathlib.Path(state_root)
        self.sessions_root = self.state_root / "sessions"
        self.dirty_path = self.state_root / "DIRTY.json"
        self.lock_path = self.state_root / "broker.lock"
        self.backend = backend
        self.now = now
        self.max_ttl_seconds = max_ttl_seconds
        self.sessions_root.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        self.state_root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _session_path(self, session_id: str) -> pathlib.Path:
        if not SESSION_PATTERN.fullmatch(session_id):
            raise BrokerError("INVALID_SESSION_ID")
        return self.sessions_root / f"{session_id}.json"

    def _load(self, session_id: str) -> dict:
        try:
            return json.loads(self._session_path(session_id).read_text())
        except FileNotFoundError as error:
            raise BrokerError("SESSION_NOT_FOUND") from error

    def _save(self, state: dict) -> None:
        state["updated_at"] = _iso(self.now())
        _atomic_json(self._session_path(state["session_id"]), state)

    def _event(self, state: dict, status: str, code: str | None = None) -> None:
        state["status"] = status
        event = {"at": _iso(self.now()), "status": status}
        if code:
            event["code"] = code
            state["last_error"] = code
        state.setdefault("events", []).append(event)
        self._save(state)

    def _assert_globally_clean(self) -> None:
        if self.dirty_path.exists():
            raise BrokerError("BROKER_DIRTY")

    def _mark_dirty(self, state: dict, code: str) -> None:
        self._event(state, "DIRTY", code)
        _atomic_json(self.dirty_path, {
            "schema_version": SCHEMA_VERSION,
            "status": "DIRTY",
            "session_id": state["session_id"],
            "code": code,
            "at": _iso(self.now()),
            "requires_manual_reconciliation": True,
        })

    @staticmethod
    def _validate_target(package: str, uid: int, pid: int) -> None:
        lowered = package.lower()
        if lowered in DENIED_EXACT_NAMES or lowered.startswith(DENIED_PACKAGE_PREFIXES):
            raise BrokerError("SYSTEM_TARGET_DENIED")
        if not PACKAGE_PATTERN.fullmatch(package):
            raise BrokerError("INVALID_PACKAGE")
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 10000:
            raise BrokerError("SYSTEM_UID_DENIED")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise BrokerError("INVALID_PID")

    @staticmethod
    def _assert_identity_allowed(identity: ProcessIdentity) -> None:
        DynamicSessionBroker._validate_target(identity.package, identity.uid, identity.pid)
        names = {identity.package.lower()}
        if identity.cmdline:
            command = identity.cmdline.split("\0", 1)[0].lower()
            names.add(command)
            names.add(pathlib.PurePosixPath(command).name)
            command_package = command.split(":", 1)[0]
            if (command_package in DENIED_EXACT_NAMES
                    or command_package.startswith(DENIED_PACKAGE_PREFIXES)):
                raise BrokerError("SYSTEM_TARGET_DENIED")
        if names & DENIED_EXACT_NAMES:
            raise BrokerError("SYSTEM_TARGET_DENIED")

    def _assert_runtime_clean(self, state: dict) -> None:
        traced = [item for item in self.backend.runtime_traces() if item.tracer_pid != 0]
        if traced:
            names = ",".join(sorted({item.name for item in traced}))
            self._mark_dirty(state, f"SYSTEM_RUNTIME_TRACED:{names}")
            raise BrokerError("SYSTEM_RUNTIME_TRACED")

    @staticmethod
    def _identity_matches(expected: dict, actual: ProcessIdentity | None) -> bool:
        return bool(
            actual
            and actual.pid == expected["pid"]
            and actual.uid == expected["uid"]
            and actual.package == expected["package"]
            and actual.fingerprint() == expected["fingerprint"]
        )

    def create(self, *, package: str, uid: int, pid: int, ttl_seconds: int,
               purpose: str, authorization_ref: str,
               target_version: str | None = None,
               target_sha256: str | None = None) -> dict:
        """Create a session after validating the immutable request."""
        with self._lock():
            self._assert_globally_clean()
            self._validate_target(package, uid, pid)
            if (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
                    or ttl_seconds < 1 or ttl_seconds > self.max_ttl_seconds):
                raise BrokerError("TTL_DENIED")
            if not PURPOSE_PATTERN.fullmatch(purpose):
                raise BrokerError("PURPOSE_REQUIRED")
            if not REFERENCE_PATTERN.fullmatch(authorization_ref):
                raise BrokerError("AUTHORIZATION_REF_REQUIRED")
            if target_sha256 is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", target_sha256):
                raise BrokerError("INVALID_TARGET_SHA256")
            session_id = uuid.uuid4().hex
            created = self.now()
            state = {
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id,
                "status": "CREATED",
                "package": package,
                "uid": uid,
                "pid": pid,
                "purpose": purpose,
                "authorization_ref": authorization_ref,
                "target_version": target_version,
                "target_sha256": target_sha256.lower() if target_sha256 else None,
                "ttl_seconds": ttl_seconds,
                "created_at": _iso(created),
                "deadline": _iso(created + dt.timedelta(seconds=ttl_seconds)),
                "updated_at": _iso(created),
                "expected_process": None,
                "owned_server": None,
                "owned_attachment": None,
                "last_error": None,
                "events": [{"at": _iso(created), "status": "CREATED"}],
            }
            _atomic_json(self._session_path(session_id), state)
            return state

    def open(self, session_id: str) -> dict:
        """Precheck, start owned server, recheck PID identity, then attach."""
        with self._lock():
            self._assert_globally_clean()
            state = self._load(session_id)
            if state["status"] != "CREATED":
                raise BrokerError("INVALID_STATE")
            if self.now() >= _parse_time(state["deadline"]):
                self._event(state, "DENIED", "TTL_EXPIRED")
                raise BrokerError("TTL_EXPIRED")

            self._assert_runtime_clean(state)
            identity = self.backend.read_process(state["pid"])
            if identity is None:
                self._event(state, "DENIED", "TARGET_NOT_RUNNING")
                raise BrokerError("TARGET_NOT_RUNNING")
            try:
                self._assert_identity_allowed(identity)
            except BrokerError as error:
                self._event(state, "DENIED", error.code)
                raise
            if (identity.pid, identity.uid, identity.package) != (
                    state["pid"], state["uid"], state["package"]):
                self._event(state, "DENIED", "TARGET_IDENTITY_MISMATCH")
                raise BrokerError("TARGET_IDENTITY_MISMATCH")
            state["expected_process"] = {
                **dataclasses.asdict(identity), "fingerprint": identity.fingerprint()
            }
            self._event(state, "PRECHECKED")

            if self.backend.list_frida_servers():
                self._event(state, "DENIED", "UNMANAGED_FRIDA_SERVER")
                raise BrokerError("UNMANAGED_FRIDA_SERVER")

            try:
                server = self.backend.start_owned_server(session_id)
                state["owned_server"] = dataclasses.asdict(server)
                self._save(state)
                if server.endpoint != "127.0.0.1:27042":
                    raise BrokerError("NON_LOOPBACK_SERVER_DENIED")

                # Mandatory second identity read immediately before attach.
                # start_ticks closes the PID-reuse race.
                current = self.backend.read_process(state["pid"])
                if not self._identity_matches(state["expected_process"], current):
                    raise BrokerError("TARGET_IDENTITY_CHANGED")
                self._assert_runtime_clean(state)
                attachment = self.backend.attach(server, current)
                if attachment.target_pid != state["pid"] or not attachment.token:
                    raise BrokerError("INVALID_ATTACHMENT_IDENTITY")
                state["owned_attachment"] = dataclasses.asdict(attachment)
                self._event(state, "ATTACHED")
                return state
            except Exception as error:
                code = error.code if isinstance(error, BrokerError) else "ATTACH_FAILED"
                clean = self._cleanup_owned(state)
                if not clean:
                    self._mark_dirty(state, f"CLEANUP_FAILED_AFTER:{code}")
                elif state["status"] != "DIRTY":
                    self._event(state, "FAILED", code)
                if isinstance(error, BrokerError):
                    raise
                raise BrokerError(code) from error

    def begin_collecting(self, session_id: str) -> dict:
        with self._lock():
            self._assert_globally_clean()
            state = self._load(session_id)
            if state["status"] != "ATTACHED":
                raise BrokerError("INVALID_STATE")
            if self.now() >= _parse_time(state["deadline"]):
                self._close_locked(state, "TTL_EXPIRED")
                raise BrokerError("TTL_EXPIRED")
            current = self.backend.read_process(state["pid"])
            if not self._identity_matches(state["expected_process"], current):
                self._close_locked(state, "TARGET_IDENTITY_CHANGED")
                raise BrokerError("TARGET_IDENTITY_CHANGED")
            try:
                self._assert_runtime_clean(state)
            except BrokerError as error:
                if not self._cleanup_owned(state):
                    self._mark_dirty(state, f"CLEANUP_FAILED_AFTER:{error.code}")
                    raise BrokerError("OWNED_CLEANUP_FAILED") from error
                raise
            self._event(state, "COLLECTING")
            return state

    def close(self, session_id: str) -> dict:
        with self._lock():
            state = self._load(session_id)
            if state["status"] in {"CLOSED", "DENIED", "FAILED"}:
                return state
            if state["status"] == "DIRTY":
                if not self._cleanup_owned(state):
                    self._mark_dirty(state, "OWNED_CLEANUP_FAILED")
                    raise BrokerError("OWNED_CLEANUP_FAILED")
                # Cleanup can reduce impact but cannot clear DIRTY. Only an
                # explicit external reconciliation may remove the global gate.
                self._event(state, "DIRTY", state.get("last_error") or "BROKER_DIRTY")
                return state
            return self._close_locked(state, None)

    def _cleanup_owned(self, state: dict) -> bool:
        clean = True
        attachment_data = state.get("owned_attachment")
        if attachment_data:
            attachment = Attachment(**attachment_data)
            try:
                detached = self.backend.detach_owned(attachment)
            except Exception:
                detached = False
            clean = bool(detached) and clean
            if detached:
                state["owned_attachment"] = None
                self._save(state)
        server_data = state.get("owned_server")
        if server_data:
            server = ServerIdentity(**server_data)
            try:
                stopped = self.backend.stop_owned_server(server)
            except Exception:
                stopped = False
            clean = bool(stopped) and clean
            if stopped:
                state["owned_server"] = None
                self._save(state)
        return clean

    def _close_locked(self, state: dict, reason: str | None) -> dict:
        self._event(state, "CLEANING", reason)
        if not self._cleanup_owned(state):
            self._mark_dirty(state, "OWNED_CLEANUP_FAILED")
            raise BrokerError("OWNED_CLEANUP_FAILED")
        self._assert_runtime_clean(state)
        self._event(state, "CLOSED", reason)
        return state

    def sweep_expired(self) -> list[str]:
        """Close expired sessions. Call from the adapter watchdog at <= TTL."""
        closed: list[str] = []
        with self._lock():
            self._assert_globally_clean()
            for path in sorted(self.sessions_root.glob("*.json")):
                state = json.loads(path.read_text())
                if state["status"] not in {"PRECHECKED", "ATTACHED", "COLLECTING"}:
                    continue
                if self.now() < _parse_time(state["deadline"]):
                    continue
                self._close_locked(state, "TTL_EXPIRED")
                closed.append(state["session_id"])
        return closed

    def get(self, session_id: str) -> dict:
        with self._lock():
            return self._load(session_id)

    def dirty_status(self) -> dict | None:
        with self._lock():
            if not self.dirty_path.exists():
                return None
            return json.loads(self.dirty_path.read_text())


@contextlib.contextmanager
def managed_session(broker: DynamicSessionBroker, **request) -> Iterator[dict]:
    """Open and always close a session owned by this context."""
    created = broker.create(**request)
    opened = broker.open(created["session_id"])
    try:
        yield opened
    finally:
        broker.close(created["session_id"])
