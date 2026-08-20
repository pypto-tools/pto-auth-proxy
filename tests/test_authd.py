import asyncio
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import authd


class ProxyTokenTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.token_dir = Path(self.tempdir.name) / "pto-auth-proxy"
        self.token_file = self.token_dir / "token.sha256"
        self.dir_patch = mock.patch.object(authd, "_TOKEN_DIR", str(self.token_dir))
        self.file_patch = mock.patch.object(
            authd, "_TOKEN_HASH_FILE", str(self.token_file))
        self.dir_patch.start()
        self.file_patch.start()

    def tearDown(self):
        self.file_patch.stop()
        self.dir_patch.stop()
        self.tempdir.cleanup()

    def test_issue_stores_only_digest_and_matches(self):
        with mock.patch.object(authd.secrets, "token_urlsafe",
                               return_value="known-random-token"):
            token = authd._issue_proxy_token()

        self.assertEqual(token, "pto_known-random-token")
        stored = self.token_file.read_text().strip()
        self.assertIn(authd._token_digest(token), stored)
        self.assertNotIn(token, self.token_file.read_text())
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)
        self.assertTrue(authd._token_matches(token))
        self.assertFalse(authd._token_matches("pto_wrong-token"))
        self.assertFalse(authd._token_matches("ordinary-linux-password"))

    def test_previous_token_has_rotation_grace(self):
        with mock.patch.object(authd.secrets, "token_urlsafe",
                               side_effect=["first", "second"]), \
             mock.patch.object(authd.time, "time", return_value=1000):
            first = authd._issue_proxy_token()
            second = authd._issue_proxy_token()
            self.assertTrue(authd._token_matches(first))
            self.assertTrue(authd._token_matches(second))

        with mock.patch.object(authd.time, "time", return_value=2000):
            self.assertFalse(authd._token_matches(first))
            self.assertTrue(authd._token_matches(second))


class CredentialFallbackTest(unittest.IsolatedAsyncioTestCase):
    async def test_matching_token_does_not_call_pam(self):
        token = "pto_" + "A" * authd._TOKEN_BODY_LENGTH
        with mock.patch.object(authd, "_token_matches", return_value=True), \
             mock.patch.object(authd, "_pam_call_async") as pam_call:
            reply, via = await authd._authenticate("alice", token)

        self.assertTrue(reply["ok"])
        self.assertEqual(via, "token")
        pam_call.assert_not_called()

    async def test_password_with_token_prefix_falls_back_to_pam(self):
        with mock.patch.object(authd, "_token_matches", return_value=False), \
             mock.patch.object(authd, "_cache_get", return_value=False), \
             mock.patch.object(authd, "_cache_put") as cache_put, \
             mock.patch.object(
                 authd, "_pam_call_async",
                 new=mock.AsyncMock(return_value=(True, 0, "success"))) as pam_call:
            reply, via = await authd._authenticate("alice", "pto_password")

        self.assertTrue(reply["ok"])
        self.assertEqual(via, "pam")
        pam_call.assert_awaited_once_with("alice", "pto_password")
        cache_put.assert_called_once_with("alice", "pto_password")

    async def test_stale_token_shape_does_not_fall_through_to_pam(self):
        token = "pto_" + "A" * authd._TOKEN_BODY_LENGTH
        with mock.patch.object(authd, "_token_matches", return_value=False), \
             mock.patch.object(authd, "_pam_call_async") as pam_call:
            reply, via = await authd._authenticate("alice", token)

        self.assertFalse(reply["ok"])
        self.assertEqual(reply["code"], -6)
        self.assertEqual(via, "token")
        pam_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
