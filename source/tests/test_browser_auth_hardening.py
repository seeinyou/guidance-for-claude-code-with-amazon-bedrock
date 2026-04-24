# ABOUTME: Tests for browser-auth hardening: callback handler filtering,
# ABOUTME: stale-callback non-termination, and the pidfile global lock.
"""Tests covering the browser-auth UX fixes in credential_provider.__main__.

These protect against regressions of:
  1. Non-/callback requests terminating the auth loop.
  2. Stale (mismatched state) callbacks recursively reopening browsers.
  3. A second credential-process opening a second browser window while the
     first is still waiting for the user.
"""

import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def auth_instance(tmp_path):
    """Create a MultiProviderAuth instance with patched config/storage."""
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")

    with patch("credential_provider.__main__.MultiProviderAuth._load_config") as mock_load, \
         patch("credential_provider.__main__.MultiProviderAuth._init_credential_storage"):
        mock_load.return_value = {
            "provider_domain": "test.okta.com",
            "client_id": "test-client-id",
            "aws_region": "us-east-1",
            "credential_storage": "session",
            "provider_type": "okta",
            "federation_type": "cognito",
            "tvm_endpoint": "https://test.example.com",
        }
        from credential_provider.__main__ import MultiProviderAuth
        instance = MultiProviderAuth(profile="TestProfile")
        instance.credential_storage = "session"
        return instance


class TestCallbackHandler:
    """The /callback handler must only terminate auth on /callback; other paths = 404."""

    def _make_handler_cls(self, auth_instance, expected_state, result_container, auth_url=None):
        return auth_instance._create_callback_handler(expected_state, result_container, auth_url)

    def _make_fake_request(self, HandlerCls, path):
        """Instantiate the real handler class without running __init__, inject recording methods."""
        handler = HandlerCls.__new__(HandlerCls)  # Skip BaseHTTPRequestHandler.__init__ (needs a socket).
        handler.path = path
        handler.wfile = MagicMock()
        handler._status = None
        handler._headers = {}

        def send_response(code):
            handler._status = code
        def send_header(k, v):
            handler._headers[k] = v
        def end_headers():
            pass

        handler.send_response = send_response
        handler.send_header = send_header
        handler.end_headers = end_headers
        return handler

    def test_favicon_request_returns_404_and_does_not_terminate(self, auth_instance):
        """A browser rendering the success page fires /favicon.ico — must not end auth."""
        result_container = {"code": None, "error": None}
        HandlerCls = self._make_handler_cls(auth_instance, "state-xyz", result_container)

        fake = self._make_fake_request(HandlerCls, "/favicon.ico")
        HandlerCls.do_GET(fake)

        assert fake._status == 404
        assert result_container["error"] is None
        assert result_container["code"] is None

    def test_random_probe_path_returns_404(self, auth_instance):
        """IDE port probes (e.g. GET /, GET /status) must not hijack the loop."""
        result_container = {"code": None, "error": None}
        # auth_url is None so the root redirect branch doesn't fire
        HandlerCls = self._make_handler_cls(auth_instance, "state-xyz", result_container)

        for path in ["/status", "/api/health", "/.well-known/oauth"]:
            fake = self._make_fake_request(HandlerCls, path)
            HandlerCls.do_GET(fake)
            assert fake._status == 404, f"path={path}"
            assert result_container["error"] is None

    def test_stale_callback_state_does_not_set_error(self, auth_instance):
        """Mismatched state on /callback must 400 but NOT terminate."""
        result_container = {"code": None, "error": None}
        HandlerCls = self._make_handler_cls(auth_instance, "expected-state", result_container)

        fake = self._make_fake_request(HandlerCls, "/callback?code=abc&state=old-state")
        HandlerCls.do_GET(fake)

        assert fake._status == 400
        # Critical: error must NOT be set, so the server keeps listening.
        assert result_container["error"] is None
        assert result_container["code"] is None

    def test_valid_callback_succeeds(self, auth_instance):
        """Matching state on /callback sets result_container['code']."""
        result_container = {"code": None, "error": None}
        HandlerCls = self._make_handler_cls(auth_instance, "expected-state", result_container)

        fake = self._make_fake_request(HandlerCls, "/callback?code=abc&state=expected-state")
        HandlerCls.do_GET(fake)

        assert fake._status == 200
        assert result_container["code"] == "abc"
        assert result_container["error"] is None

    def test_provider_error_callback_terminates(self, auth_instance):
        """?error= from the IdP is a real failure — must terminate with error set."""
        result_container = {"code": None, "error": None}
        HandlerCls = self._make_handler_cls(auth_instance, "expected-state", result_container)

        fake = self._make_fake_request(HandlerCls, "/callback?error=access_denied&error_description=User+cancelled")
        HandlerCls.do_GET(fake)

        assert fake._status == 400
        assert result_container["error"] == "User cancelled"


class TestBrowserLock:
    """The pidfile lock must block concurrent browser windows but recover from stale holders."""

    def _fresh_lock_dir(self, auth_instance, tmp_path, monkeypatch):
        """Point Path.home() at tmp_path so the lock lands under tmp."""
        monkeypatch.setattr("credential_provider.__main__.Path.home", lambda: tmp_path)
        return tmp_path / ".claude-code-session"

    def test_acquire_when_no_lock_exists(self, auth_instance, tmp_path, monkeypatch):
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)

        assert auth_instance._acquire_browser_lock() is True
        lock_path = auth_instance._browser_lock_path()
        assert lock_path.exists()
        data = json.loads(lock_path.read_text())
        assert data["pid"] == os.getpid()
        assert data["profile"] == "TestProfile"

    def test_acquire_blocked_when_lock_held_by_live_pid(self, auth_instance, tmp_path, monkeypatch):
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)
        # Simulate another live credential-process holding the lock.
        lock_path = auth_instance._browser_lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 99999, "profile": "TestProfile", "ts": int(time.time())}))

        with patch.object(auth_instance, "_is_pid_alive", return_value=True):
            assert auth_instance._acquire_browser_lock() is False

        # Lock file must be preserved — we didn't steal it.
        data = json.loads(lock_path.read_text())
        assert data["pid"] == 99999

    def test_acquire_takes_over_dead_pid(self, auth_instance, tmp_path, monkeypatch):
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)
        lock_path = auth_instance._browser_lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 99999, "profile": "TestProfile", "ts": int(time.time())}))

        with patch.object(auth_instance, "_is_pid_alive", return_value=False):
            assert auth_instance._acquire_browser_lock() is True

        data = json.loads(lock_path.read_text())
        assert data["pid"] == os.getpid()

    def test_acquire_takes_over_expired_ttl_even_if_alive(self, auth_instance, tmp_path, monkeypatch):
        """Pid recycling safety: age > TTL triggers takeover even if _is_pid_alive says True."""
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)
        lock_path = auth_instance._browser_lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 99999, "profile": "TestProfile", "ts": 0}))
        # Force the mtime to be ancient (TTL default 600s).
        ancient = time.time() - 9999
        os.utime(lock_path, (ancient, ancient))

        with patch.object(auth_instance, "_is_pid_alive", return_value=True):
            assert auth_instance._acquire_browser_lock() is True

        data = json.loads(lock_path.read_text())
        assert data["pid"] == os.getpid()

    def test_release_removes_own_lock(self, auth_instance, tmp_path, monkeypatch):
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)
        auth_instance._acquire_browser_lock()
        lock_path = auth_instance._browser_lock_path()
        assert lock_path.exists()

        auth_instance._release_browser_lock()
        assert not lock_path.exists()

    def test_release_does_not_remove_others_lock(self, auth_instance, tmp_path, monkeypatch):
        """If another process has taken over, we must not delete their lock."""
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)
        lock_path = auth_instance._browser_lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 99999, "profile": "TestProfile", "ts": int(time.time())}))

        auth_instance._release_browser_lock()
        assert lock_path.exists()
        assert json.loads(lock_path.read_text())["pid"] == 99999

    def test_is_pid_alive_handles_negative_pid(self, auth_instance):
        assert auth_instance._is_pid_alive(0) is False
        assert auth_instance._is_pid_alive(-1) is False

    def test_is_pid_alive_reports_self(self, auth_instance):
        # Our own PID must always read as alive.
        assert auth_instance._is_pid_alive(os.getpid()) is True

    def test_acquire_failopen_on_unwritable_dir(self, auth_instance, tmp_path, monkeypatch):
        """If the lock file is unwritable, we fail-open rather than block the user forever."""
        self._fresh_lock_dir(auth_instance, tmp_path, monkeypatch)

        def boom(self, *a, **kw):
            raise OSError("simulated")

        with patch("pathlib.Path.write_text", boom):
            # write_text is used for the lock file; fail-open should return True
            assert auth_instance._acquire_browser_lock() is True


class TestWaitForAuthCompletion:
    """_wait_for_auth_completion must distinguish third_party / timeout / cached."""

    def test_third_party_holds_port_prints_user_message(self, auth_instance, capsys):
        """A non-ccwb process holding the port: user sees Chinese port-busy message, no wait."""
        with patch.object(auth_instance, "_is_port_held_by_ccwb", return_value=False):
            result = auth_instance._wait_for_auth_completion()

        assert result is None
        assert auth_instance._last_wait_result == "third_party"
        err = capsys.readouterr().err
        # Chinese port-busy text
        assert "端口" in err
        assert "已被占用" in err
        assert str(auth_instance.redirect_port) in err

    def test_timeout_sets_timeout_sentinel(self, auth_instance):
        """If the ccwb holder never releases, _last_wait_result == 'timeout'."""
        # Short timeout to keep the test fast; bind a real socket to simulate the holder.
        import socket

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))  # kernel-assigned free port
        holder.listen(1)
        port = holder.getsockname()[1]

        auth_instance.redirect_port = port
        try:
            with patch.object(auth_instance, "_is_port_held_by_ccwb", return_value=True), \
                 patch.object(auth_instance, "get_cached_credentials", return_value=None):
                result = auth_instance._wait_for_auth_completion(timeout=1)
        finally:
            holder.close()

        assert result is None
        assert auth_instance._last_wait_result == "timeout"

    def test_cached_result_sets_cached_sentinel(self, auth_instance):
        """When the port frees up and cached creds appear, sentinel == 'cached'."""
        fake_creds = {"Version": 1, "AccessKeyId": "X", "SecretAccessKey": "Y",
                      "SessionToken": "Z", "Expiration": "2099-01-01T00:00:00Z"}

        # Port is held by us (ccwb check True), but immediately bindable — simulates
        # the holder having just released. No real holder socket needed.
        with patch.object(auth_instance, "_is_port_held_by_ccwb", return_value=True), \
             patch.object(auth_instance, "get_cached_credentials", return_value=fake_creds):
            result = auth_instance._wait_for_auth_completion(timeout=2)

        assert result == fake_creds
        assert auth_instance._last_wait_result == "cached"


class TestIsPortHeldByCcwb:
    """Port-ownership detection is the source of truth for whether to wait or bail."""

    def test_returns_false_when_nothing_listening(self, auth_instance):
        """Unused port: nothing is listening, so no ccwb holder exists."""
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
        s.close()

        auth_instance.redirect_port = free_port
        # On a truly free port neither /proc nor lsof should find a holder.
        assert auth_instance._is_port_held_by_ccwb() is False

    def test_third_party_listener_not_detected_as_ccwb(self, auth_instance):
        """A non-ccwb process holding the port must NOT be mistaken for a ccwb sibling.

        Starts a plain Python HTTP server as the external app; the detection
        should recognize it's not credential_provider / ccwb.
        """
        import socket
        import subprocess
        import sys as _sys
        import textwrap
        import time as _time

        # Find a free port before spawning the helper.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        # Spawn a subprocess that listens on that port with a cmdline that
        # contains neither "credential_provider" nor "ccwb".
        script = textwrap.dedent(f"""
            import socket, time
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", {port}))
            s.listen(1)
            time.sleep(30)
        """)
        proc = subprocess.Popen(
            [_sys.executable, "-c", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            # Wait until the child actually listens.
            deadline = _time.time() + 5
            while _time.time() < deadline:
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    probe.bind(("127.0.0.1", port))
                    probe.close()
                    _time.sleep(0.1)  # child hasn't bound yet
                except OSError:
                    probe.close()
                    break
            else:
                pytest.skip("helper process failed to bind the port in time")

            auth_instance.redirect_port = port
            assert auth_instance._is_port_held_by_ccwb() is False
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_failsafe_true_when_lsof_missing(self, auth_instance, monkeypatch):
        """Windows / minimal containers have no lsof AND no /proc.

        When both detection backends are unavailable, the function must
        fail safe (return True) so legitimate sibling ccwb processes aren't
        mistaken for strangers.
        """
        # Block /proc access to force the lsof fallback path on Linux.
        import builtins
        real_open = builtins.open

        def no_proc_open(path, *a, **kw):
            if isinstance(path, str) and path.startswith("/proc/net/"):
                raise FileNotFoundError(path)
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", no_proc_open)

        # lsof not installed → subprocess.run raises FileNotFoundError; the
        # outer except catches it and returns True (fail-safe).
        import subprocess
        def lsof_missing(*a, **kw):
            raise FileNotFoundError("lsof not found")
        monkeypatch.setattr(subprocess, "run", lsof_missing)

        # Even if the current test host has a free port, detection should
        # return True because both backends blew up.
        assert auth_instance._is_port_held_by_ccwb() is True

    def test_failsafe_true_on_lsof_decode_error(self, auth_instance, monkeypatch):
        """Some Windows PowerShell paths emit non-UTF-8 output; decoding may raise.

        The outer `except Exception: return True` guarantees no crash.
        """
        import builtins
        real_open = builtins.open

        def no_proc_open(path, *a, **kw):
            if isinstance(path, str) and path.startswith("/proc/net/"):
                raise FileNotFoundError(path)
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", no_proc_open)

        import subprocess
        def lsof_decode_boom(*a, **kw):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        monkeypatch.setattr(subprocess, "run", lsof_decode_boom)

        assert auth_instance._is_port_held_by_ccwb() is True


class TestIsPortHeldByCcwbWindows:
    """The Windows code path uses netstat + tasklist. Exercise it on any host
    by patching platform detection and subprocess.run.

    Windows users without lsof used to always hit the fail-safe `return True`,
    which means a third-party app holding 8400 was mistaken for a sibling
    ccwb process — user saw the wrong error message. The new Windows branch
    runs netstat + tasklist so the third-party detection works.
    """

    def _force_windows(self, monkeypatch):
        # Make the function take the Windows branch.
        monkeypatch.setattr("credential_provider.__main__.platform.system", lambda: "Windows")
        # Also make /proc unavailable so the Linux branch doesn't short-circuit.
        import builtins
        real_open = builtins.open

        def no_proc_open(path, *a, **kw):
            if isinstance(path, str) and path.startswith("/proc/net/"):
                raise FileNotFoundError(path)
            return real_open(path, *a, **kw)
        monkeypatch.setattr("builtins.open", no_proc_open)

    def test_windows_detects_ccwb_holder(self, auth_instance, monkeypatch):
        """netstat shows PID on 8400, tasklist image contains credential-process.exe → True."""
        self._force_windows(monkeypatch)
        auth_instance.redirect_port = 8400

        netstat_out = (
            "\r\nActive Connections\r\n\r\n"
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    0.0.0.0:8400           0.0.0.0:0              LISTENING       12345\r\n"
            "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r\n"
        ).encode("utf-8")
        tasklist_out = b'"credential-process.exe","12345","Console","1","12,345 K"\r\n'

        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            if cmd[0] == "netstat":
                r.stdout = netstat_out
            elif cmd[0] == "tasklist":
                r.stdout = tasklist_out
            calls["n"] += 1
            return r

        monkeypatch.setattr("subprocess.run", fake_run)
        assert auth_instance._is_port_held_by_ccwb() is True
        assert calls["n"] >= 2  # netstat + tasklist both called

    def test_windows_detects_third_party_holder(self, auth_instance, monkeypatch):
        """netstat shows a PID, tasklist image is some other app → False."""
        self._force_windows(monkeypatch)
        auth_instance.redirect_port = 8400

        netstat_out = (
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    127.0.0.1:8400         0.0.0.0:0              LISTENING       98765\r\n"
        ).encode("utf-8")
        tasklist_out = b'"node.exe","98765","Console","1","45,678 K"\r\n'

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = netstat_out if cmd[0] == "netstat" else tasklist_out
            return r

        monkeypatch.setattr("subprocess.run", fake_run)
        assert auth_instance._is_port_held_by_ccwb() is False

    def test_windows_nothing_listening(self, auth_instance, monkeypatch):
        """netstat has no row for our port → False without calling tasklist."""
        self._force_windows(monkeypatch)
        auth_instance.redirect_port = 8400

        netstat_out = (
            "  Proto  Local Address          Foreign Address        State           PID\r\n"
            "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r\n"
        ).encode("utf-8")

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            assert cmd[0] == "netstat", "tasklist must not be invoked when netstat has no match"
            r.stdout = netstat_out
            return r

        monkeypatch.setattr("subprocess.run", fake_run)
        assert auth_instance._is_port_held_by_ccwb() is False

    def test_windows_non_utf8_output_tolerated(self, auth_instance, monkeypatch):
        """PowerShell 5.x / cp1252 emits non-UTF-8 bytes — decode with errors=replace,
        don't crash."""
        self._force_windows(monkeypatch)
        auth_instance.redirect_port = 8400

        # Inject a 0xFF byte that UTF-8 can't decode strictly.
        netstat_out = (
            b"  Proto  Local Address          Foreign Address        State           PID\r\n"
            b"  TCP    0.0.0.0:8400           0.0.0.0:0              LISTENING       12345\r\n"
            b"\xff\xfe noise \xff\r\n"
        )
        tasklist_out = b'"credential-process.exe","12345","Console","1","12,345 K"\r\n'

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 0
            r.stdout = netstat_out if cmd[0] == "netstat" else tasklist_out
            return r

        monkeypatch.setattr("subprocess.run", fake_run)
        # Must not raise; should still find PID 12345 → ccwb.
        assert auth_instance._is_port_held_by_ccwb() is True

    def test_windows_netstat_missing_failsafe(self, auth_instance, monkeypatch):
        """Extremely locked-down Windows where netstat is missing or blocked:
        fail-safe True so sibling ccwb isn't mistaken for a stranger."""
        self._force_windows(monkeypatch)
        auth_instance.redirect_port = 8400

        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("netstat not found")

        monkeypatch.setattr("subprocess.run", fake_run)
        assert auth_instance._is_port_held_by_ccwb() is True


class TestRefreshTokenRoundTrip:
    """Saving refresh_token must verify the backend actually persisted it.

    If the keychain / filesystem silently drops the write, the next
    invocation hits 'No cached refresh_token' and is forced back to the
    browser — indistinguishable from genuine expiry without this check.
    """

    def test_warns_when_readback_differs(self, auth_instance, tmp_path, monkeypatch, caplog):
        """Simulate a backend that swallows the write: _get_cached_refresh_token
        returns something other than what we just saved."""
        # Route save through the session-file path inside tmp_path.
        monkeypatch.setattr("credential_provider.__main__.Path.home", lambda: tmp_path)
        auth_instance.credential_storage = "session"

        # Force readback to return None regardless of what was saved.
        with patch.object(auth_instance, "_get_cached_refresh_token", return_value=None):
            with caplog.at_level("INFO", logger="credential-process"):
                auth_instance._save_refresh_token("new-refresh-token-xyz")

        messages = [r.getMessage() for r in caplog.records]
        assert any("refresh_token save did not round-trip" in m for m in messages)
        assert any("readback=missing" in m for m in messages)

    def test_silent_when_readback_matches(self, auth_instance, tmp_path, monkeypatch, caplog):
        """Happy path: readback equals what we wrote → no warning logged."""
        monkeypatch.setattr("credential_provider.__main__.Path.home", lambda: tmp_path)
        auth_instance.credential_storage = "session"

        with caplog.at_level("INFO", logger="credential-process"):
            auth_instance._save_refresh_token("new-refresh-token-xyz")

        messages = [r.getMessage() for r in caplog.records]
        assert not any("did not round-trip" in m for m in messages)
