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


if __name__ == "__main__":
    unittest.main()
