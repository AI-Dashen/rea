#!/usr/bin/env python
import datetime as dt
import pathlib
import shutil
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/rea"))

from dynamic_session_broker import (
    Attachment,
    BrokerError,
    DynamicBackend,
    DynamicSessionBroker,
    ProcessIdentity,
    RuntimeTrace,
    ServerIdentity,
    managed_session,
)


class Clock:
    def __init__(self):
        self.value = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += dt.timedelta(seconds=seconds)


class FakeBackend(DynamicBackend):
    def __init__(self):
        self.process_reads = []
        self.traces = [
            RuntimeTrace("zygote64", 100, 0),
            RuntimeTrace("system_server", 200, 0),
        ]
        self.servers = []
        self.started = []
        self.attached = []
        self.detached = []
        self.stopped = []
        self.detach_ok = True
        self.stop_ok = True
        self.next_server = ServerIdentity(7000, 41)

    def read_process(self, pid):
        if not self.process_reads:
            return None
        return self.process_reads.pop(0)

    def runtime_traces(self):
        return list(self.traces)

    def list_frida_servers(self):
        return list(self.servers)

    def start_owned_server(self, session_id):
        self.started.append(session_id)
        return self.next_server

    def attach(self, server, target):
        result = Attachment(f"attach:{target.pid}", target.pid)
        self.attached.append((server, target, result))
        return result

    def detach_owned(self, attachment):
        self.detached.append(attachment)
        return self.detach_ok

    def stop_owned_server(self, server):
        self.stopped.append(server)
        return self.stop_ok


class DynamicSessionBrokerTest(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="rea-dynamic-broker-"))
        self.clock = Clock()
        self.backend = FakeBackend()
        self.broker = DynamicSessionBroker(self.root, self.backend, now=self.clock)
        self.identity = ProcessIdentity(
            32100, 10234, "owned.acceptance", "owned.acceptance", 991
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def create(self, **overrides):
        values = dict(
            package="owned.acceptance",
            uid=10234,
            pid=32100,
            ttl_seconds=60,
            purpose="Observe owned acceptance method",
            authorization_ref="task:test-123",
            target_version="1.0",
            target_sha256="a" * 64,
        )
        values.update(overrides)
        return self.broker.create(**values)

    def open_ready(self):
        created = self.create()
        self.backend.process_reads = [self.identity, self.identity]
        return self.broker.open(created["session_id"])

    def assert_code(self, code, callback):
        with self.assertRaises(BrokerError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)

    def test_request_requires_target_ttl_purpose_and_authorization(self):
        self.assert_code("SYSTEM_UID_DENIED", lambda: self.create(uid=9999))
        self.assert_code(
            "SYSTEM_TARGET_DENIED",
            lambda: self.create(package="com.android.systemui"),
        )
        self.assert_code("TTL_DENIED", lambda: self.create(ttl_seconds=901))
        self.assert_code("PURPOSE_REQUIRED", lambda: self.create(purpose="x"))
        self.assert_code(
            "AUTHORIZATION_REF_REQUIRED",
            lambda: self.create(authorization_ref=""),
        )

    def test_denies_unmanaged_server_without_start_or_attach(self):
        created = self.create()
        self.backend.process_reads = [self.identity]
        self.backend.servers = [ServerIdentity(8888, 12)]
        self.assert_code(
            "UNMANAGED_FRIDA_SERVER",
            lambda: self.broker.open(created["session_id"]),
        )
        self.assertEqual(self.broker.get(created["session_id"])["status"], "DENIED")
        self.assertEqual(self.backend.started, [])
        self.assertEqual(self.backend.attached, [])

    def test_pid_identity_is_read_twice_and_change_cleans_owned_server(self):
        created = self.create()
        reused = ProcessIdentity(
            32100, 10234, "owned.acceptance", "owned.acceptance", 992
        )
        self.backend.process_reads = [self.identity, reused]
        self.assert_code(
            "TARGET_IDENTITY_CHANGED",
            lambda: self.broker.open(created["session_id"]),
        )
        state = self.broker.get(created["session_id"])
        self.assertEqual(state["status"], "FAILED")
        self.assertIsNone(state["owned_server"])
        self.assertEqual(self.backend.stopped, [self.backend.next_server])
        self.assertEqual(self.backend.attached, [])

    def test_successful_session_cleans_only_owned_handles(self):
        opened = self.open_ready()
        self.assertEqual(opened["status"], "ATTACHED")
        self.backend.process_reads = [self.identity]
        collecting = self.broker.begin_collecting(opened["session_id"])
        self.assertEqual(collecting["status"], "COLLECTING")
        closed = self.broker.close(opened["session_id"])
        self.assertEqual(closed["status"], "CLOSED")
        self.assertEqual(
            [item.token for item in self.backend.detached], ["attach:32100"]
        )
        self.assertEqual(self.backend.stopped, [self.backend.next_server])
        self.assertIsNone(closed["owned_attachment"])
        self.assertIsNone(closed["owned_server"])

    def test_cleanup_failure_marks_global_dirty_and_blocks_next_session(self):
        opened = self.open_ready()
        self.backend.detach_ok = False
        self.assert_code(
            "OWNED_CLEANUP_FAILED",
            lambda: self.broker.close(opened["session_id"]),
        )
        self.assertEqual(self.broker.get(opened["session_id"])["status"], "DIRTY")
        self.assertTrue(self.broker.dirty_status()["requires_manual_reconciliation"])
        self.assert_code("BROKER_DIRTY", lambda: self.create())

    def test_traced_system_runtime_marks_dirty_without_cleanup_or_kill(self):
        created = self.create()
        self.backend.traces = [RuntimeTrace("zygote64", 100, 7000)]
        self.assert_code(
            "SYSTEM_RUNTIME_TRACED",
            lambda: self.broker.open(created["session_id"]),
        )
        self.assertEqual(self.broker.get(created["session_id"])["status"], "DIRTY")
        self.assertEqual(self.backend.started, [])
        self.assertEqual(self.backend.stopped, [])

    def test_runtime_trace_after_attach_marks_dirty_and_cleans_own_handles(self):
        opened = self.open_ready()
        self.backend.process_reads = [self.identity]
        self.backend.traces = [RuntimeTrace("system_server", 200, 7000)]
        self.assert_code(
            "SYSTEM_RUNTIME_TRACED",
            lambda: self.broker.begin_collecting(opened["session_id"]),
        )
        self.assertEqual(self.broker.get(opened["session_id"])["status"], "DIRTY")
        self.assertEqual(len(self.backend.detached), 1)
        self.assertEqual(len(self.backend.stopped), 1)

    def test_backend_system_identity_is_denied_and_recorded(self):
        created = self.create()
        self.backend.process_reads = [
            ProcessIdentity(32100, 1000, "android", "zygote64", 991)
        ]
        self.assert_code(
            "SYSTEM_TARGET_DENIED",
            lambda: self.broker.open(created["session_id"]),
        )
        state = self.broker.get(created["session_id"])
        self.assertEqual(state["status"], "DENIED")
        self.assertEqual(self.backend.started, [])

    def test_ttl_sweep_closes_and_cleans_owned_session(self):
        opened = self.open_ready()
        self.clock.advance(61)
        self.assertEqual(self.broker.sweep_expired(), [opened["session_id"]])
        state = self.broker.get(opened["session_id"])
        self.assertEqual(state["status"], "CLOSED")
        self.assertEqual(state["last_error"], "TTL_EXPIRED")
        self.assertEqual(len(self.backend.detached), 1)
        self.assertEqual(len(self.backend.stopped), 1)

    def test_managed_context_closes_after_client_exception(self):
        self.backend.process_reads = [self.identity, self.identity]
        with self.assertRaisesRegex(RuntimeError, "client crashed"):
            with managed_session(
                self.broker,
                package="owned.acceptance",
                uid=10234,
                pid=32100,
                ttl_seconds=60,
                purpose="Observe method",
                authorization_ref="task:test-123",
            ) as opened:
                session_id = opened["session_id"]
                raise RuntimeError("client crashed")
        self.assertEqual(self.broker.get(session_id)["status"], "CLOSED")

    def test_non_loopback_server_is_rejected_and_cleaned(self):
        created = self.create()
        self.backend.next_server = ServerIdentity(7000, 41, "0.0.0.0:27042")
        self.backend.process_reads = [self.identity]
        self.assert_code(
            "NON_LOOPBACK_SERVER_DENIED",
            lambda: self.broker.open(created["session_id"]),
        )
        self.assertEqual(self.backend.stopped, [self.backend.next_server])


if __name__ == "__main__":
    unittest.main()
