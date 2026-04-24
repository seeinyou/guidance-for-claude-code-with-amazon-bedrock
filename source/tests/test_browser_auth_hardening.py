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
