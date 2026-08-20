import contextlib
import io
import os
import unittest
from unittest import mock

import status_proxy


class StatusTest(unittest.TestCase):
    def test_guard_ports_follow_configuration(self):
        with mock.patch.dict(
                os.environ, {"PTO_AUTH_PROXY_GUARD_PORTS": "5000,5001"},
                clear=True):
            self.assertEqual(status_proxy.guard_ports(4780), (5000, 5001))

    def test_invalid_guard_ports_fail_closed(self):
        with mock.patch.dict(
                os.environ, {"PTO_AUTH_PROXY_GUARD_PORTS": "4780,bad"},
                clear=True):
            self.assertEqual(status_proxy.guard_ports(4780), ())

    def test_proxy_url_ignores_direct_upstream_configuration(self):
        environment = {
            "HTTPS_PROXY": "http://user:secret@127.0.0.1:4780",
            "HTTP_PROXY": "http://user:secret@127.0.0.1:20809",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertEqual(url, environment["HTTP_PROXY"])
        self.assertEqual(source, "env")

    def test_ready_output_contains_no_credential(self):
        output = io.StringIO()
        with mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "authd_capability",
                               return_value=(True, "token")), \
             mock.patch.object(status_proxy, "proxy_url",
                               return_value=("http://user:top-secret@127.0.0.1:20809",
                                             "file")), \
             mock.patch.object(status_proxy, "authenticated_connect",
                               return_value="200"), \
             mock.patch.object(status_proxy, "direct_access_is_correct",
                               return_value=True), \
             mock.patch.object(status_proxy, "guard_service_active",
                               return_value=True), \
             contextlib.redirect_stdout(output):
            result = status_proxy.main()
        self.assertEqual(result, 0)
        self.assertIn("READY", output.getvalue())
        self.assertNotIn("top-secret", output.getvalue())

    def test_proxy_url_rejects_non_http_scheme(self):
        environment = {
            "HTTPS_PROXY": "socks5h://user:secret@127.0.0.1:20809",
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(status_proxy.Path, "home",
                               return_value=status_proxy.Path("/missing-home")):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertIsNone(url)
        self.assertEqual(source, "missing")

    def test_empty_xdg_config_home_uses_home_default(self):
        environment = {"XDG_CONFIG_HOME": ""}
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(status_proxy.Path, "home",
                               return_value=status_proxy.Path("/home/test")), \
             mock.patch.object(status_proxy.Path, "read_text",
                               side_effect=OSError):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertIsNone(url)
        self.assertEqual(source, "missing")


if __name__ == "__main__":
    unittest.main()
