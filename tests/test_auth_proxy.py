import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import auth_proxy


REPO_ROOT = Path(__file__).resolve().parents[1]


class GitHubWhitelistTest(unittest.TestCase):
    def setUp(self):
        entries = [
            line.strip().lower()
            for line in (REPO_ROOT / "config/whitelist.txt").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.whitelist_patch = mock.patch.object(auth_proxy, "_whitelist", entries)
        self.whitelist_patch.start()

    def tearDown(self):
        self.whitelist_patch.stop()

    def test_core_github_web_and_git_hosts_are_allowed(self):
        hosts = {
            "github.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "github.githubassets.com",
            "codeload.github.com",
        }
        for host in hosts:
            with self.subTest(host=host):
                self.assertTrue(auth_proxy.host_allowed(host))

    def test_unrequested_github_products_are_not_accidentally_allowed(self):
        for host in ("ghcr.io", "example.github.io", "github.dev"):
            with self.subTest(host=host):
                self.assertFalse(auth_proxy.host_allowed(host))

    def test_non_whitelisted_domain_is_denied(self):
        self.assertFalse(auth_proxy.host_allowed("example.com"))


class ConfigurationTest(unittest.TestCase):
    def test_port_validation(self):
        with mock.patch.dict("os.environ", {"TEST_PROXY_PORT": "21808"}):
            self.assertEqual(auth_proxy._env_port("TEST_PROXY_PORT", 1), 21808)

    def test_invalid_port_is_rejected(self):
        with mock.patch.dict("os.environ", {"TEST_PROXY_PORT": "70000"}):
            with self.assertRaises(SystemExit):
                auth_proxy._env_port("TEST_PROXY_PORT", 1)

    def test_timeout_validation(self):
        with mock.patch.dict("os.environ", {"TEST_PROXY_TIMEOUT": "2.5"}):
            self.assertEqual(
                auth_proxy._env_seconds("TEST_PROXY_TIMEOUT", 1), 2.5)
        with mock.patch.dict("os.environ", {"TEST_PROXY_TIMEOUT": "0"}):
            with self.assertRaises(SystemExit):
                auth_proxy._env_seconds("TEST_PROXY_TIMEOUT", 1)

    def test_wrong_runtime_user_is_rejected(self):
        current = mock.Mock(pw_name="someone-else")
        with mock.patch.object(auth_proxy, "PROXY_OWNER", "pypto"), \
             mock.patch.object(auth_proxy.os, "getuid", return_value=1234), \
             mock.patch.object(auth_proxy.pwd, "getpwuid", return_value=current), \
             mock.patch.object(auth_proxy, "log") as log:
            with self.assertRaisesRegex(SystemExit, "1"):
                auth_proxy.require_proxy_owner()

        messages = "\n".join(call.args[0] for call in log.call_args_list)
        self.assertIn("must run as user 'pypto'", messages)
        self.assertIn("sudo -u pypto pto-auth-proxy run", messages)

    def test_required_runtime_user_is_accepted(self):
        current = mock.Mock(pw_name="pypto")
        with mock.patch.object(auth_proxy, "PROXY_OWNER", "pypto"), \
             mock.patch.object(auth_proxy.os, "getuid", return_value=1070), \
             mock.patch.object(auth_proxy.pwd, "getpwuid", return_value=current):
            auth_proxy.require_proxy_owner()


class RecentDownloadRankingTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.stats_file = Path(self.tempdir.name) / "stats.jsonl"
        self.stats_patch = mock.patch.object(auth_proxy, "STATS_FILE", self.stats_file)
        self.stats_patch.start()

    def tearDown(self):
        self.stats_patch.stop()
        self.tempdir.cleanup()

    def write_stats(self, entries):
        self.stats_file.write_text(
            "".join(json.dumps(entry) + "\n" for entry in entries))

    def test_ranks_downloads_within_window(self):
        self.write_stats([
            {"ts": 7000, "user": "old", "bytes_down": 999999},
            {"ts": 9000, "user": "alice", "bytes_down": 100},
            {"ts": 9500, "user": "bob", "bytes_down": 400},
            {"ts": 9800, "user": "alice", "bytes_down": 500},
            {"ts": 10001, "user": "future", "bytes_down": 999999},
        ])

        result = auth_proxy.recent_download_ranking(1800, now=10000)

        self.assertEqual([item["user"] for item in result], ["alice", "bob"])
        self.assertEqual(result[0], {
            "rank": 1, "user": "alice", "bytes_down": 600,
            "connections": 2,
        })

    def test_single_record_is_not_dropped_by_tail_reader(self):
        self.write_stats([
            {"ts": 9999, "user": "alice", "bytes_down": 123},
        ])
        result = auth_proxy.recent_download_ranking(1800, now=10000)
        self.assertEqual(result[0]["bytes_down"], 123)

    def test_empty_human_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            auth_proxy.print_download_ranking(30)
        self.assertIn("最近 30 分钟", output.getvalue())
        self.assertIn("暂无", output.getvalue())


class RelayLifecycleTest(unittest.IsolatedAsyncioTestCase):
    class Writer:
        def __init__(self):
            self.data = bytearray()
            self.eof_count = 0

        def write(self, data):
            self.data.extend(data)

        async def drain(self):
            return None

        def can_write_eof(self):
            return True

        def write_eof(self):
            self.eof_count += 1

    async def test_relay_bounds_blocked_sibling_after_half_close(self):
        left = asyncio.StreamReader()
        left.feed_data(b"hello")
        left.feed_eof()
        right = asyncio.StreamReader()  # Intentionally never receives EOF.
        left_writer = self.Writer()
        right_writer = self.Writer()
        uploaded, downloaded = [0], [0]

        with mock.patch.object(auth_proxy, "RELAY_HALF_CLOSE_TIMEOUT", 0.01):
            await asyncio.wait_for(
                auth_proxy._relay(left, left_writer, right, right_writer,
                                  uploaded, downloaded),
                timeout=0.2)

        self.assertEqual(right_writer.data, b"hello")
        self.assertEqual(right_writer.eof_count, 1)
        self.assertEqual(uploaded[0], 5)
        self.assertEqual(downloaded[0], 0)

    async def test_relay_keeps_response_after_client_half_close(self):
        left = asyncio.StreamReader()
        left.feed_data(b"request")
        left.feed_eof()
        right = asyncio.StreamReader()
        left_writer = self.Writer()
        right_writer = self.Writer()
        uploaded, downloaded = [0], [0]

        async def finish_response():
            await asyncio.sleep(0.01)
            right.feed_data(b"response")
            right.feed_eof()

        feeder = asyncio.create_task(finish_response())
        await auth_proxy._relay(left, left_writer, right, right_writer,
                                uploaded, downloaded)
        await feeder

        self.assertEqual(right_writer.data, b"request")
        self.assertEqual(left_writer.data, b"response")
        self.assertEqual(uploaded[0], 7)
        self.assertEqual(downloaded[0], 8)
        self.assertEqual(right_writer.eof_count, 1)
        self.assertEqual(left_writer.eof_count, 1)

    async def test_upstream_read_has_a_hard_timeout(self):
        reader = asyncio.StreamReader()
        with mock.patch.object(auth_proxy, "UPSTREAM_HANDSHAKE_TIMEOUT", 0.01):
            with self.assertRaises(asyncio.TimeoutError):
                await auth_proxy._upstream_readexactly(reader, 1)

    async def test_http_header_reader_preserves_coalesced_payload(self):
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com\r\n\r\n"
            b"first-tls-bytes")
        line, headers, tail = await auth_proxy._read_http_headers(reader)
        self.assertEqual(line, b"CONNECT github.com:443 HTTP/1.1")
        self.assertEqual(headers, [b"Host: github.com"])
        self.assertEqual(tail, b"first-tls-bytes")


if __name__ == "__main__":
    unittest.main()
