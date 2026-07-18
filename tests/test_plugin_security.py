import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


def stub_module(name):
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


def load_plugin(token="test-token"):
    ida_idaapi = stub_module("ida_idaapi")
    ida_idaapi.BADADDR = (1 << 64) - 1
    ida_idaapi.plugin_t = object
    ida_idaapi.PLUGIN_KEEP = 1

    ida_kernwin = stub_module("ida_kernwin")
    ida_kernwin.MFF_READ = 0
    ida_kernwin.MFF_WRITE = 1
    ida_kernwin.UI_Hooks = type("UI_Hooks", (), {})
    ida_kernwin.execute_sync = lambda callback, _flags: callback()

    ida_lines = stub_module("ida_lines")
    ida_lines.SCOLOR_ON = "\x01"
    ida_lines.SCOLOR_OFF = "\x02"
    ida_lines.SCOLOR_ESC = "\x03"
    ida_lines.SCOLOR_INV = "\x04"
    ida_lines.SCOLOR_ADDR = "\x05"
    ida_lines.COLOR_ADDR_SIZE = 16

    for name in (
        "ida_funcs",
        "ida_nalt",
        "ida_ida",
        "ida_bytes",
        "ida_name",
        "ida_segment",
        "ida_typeinf",
        "ida_gdl",
        "ida_xref",
        "idautils",
    ):
        stub_module(name)

    ida_hexrays = stub_module("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: False

    if token is None:
        os.environ.pop("IDAREM_AUTH_TOKEN", None)
    else:
        os.environ["IDAREM_AUTH_TOKEN"] = token
    os.environ.pop("IDAREM_ALLOW_WRITE", None)
    path = Path(__file__).resolve().parents[1] / "plugin" / "idarem.py"
    spec = importlib.util.spec_from_file_location("idarem_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PluginSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = load_plugin()
        cls.client = cls.plugin.app.test_client()

    def test_api_rejects_missing_or_query_string_token(self):
        self.assertEqual(self.client.get("/api/search?q=").status_code, 401)
        self.assertEqual(self.client.get("/api/search?q=&token=test-token").status_code, 401)

    def test_missing_token_generates_a_strong_session_secret(self):
        try:
            generated = load_plugin(token=None)
            self.assertTrue(generated._auth_token_generated)
            self.assertNotEqual(generated.AUTH_TOKEN, "CreateUrOwnToken")
            self.assertGreaterEqual(len(generated.AUTH_TOKEN), 32)
        finally:
            os.environ["IDAREM_AUTH_TOKEN"] = "test-token"

    def test_bearer_token_is_required_and_responses_are_not_cached(self):
        response = self.client.get("/api/search?q=", headers={"Authorization": "Bearer test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_cors_allows_only_configured_development_origins(self):
        headers = {"Authorization": "Bearer test-token"}
        denied = self.client.get("/api/search?q=", headers={**headers, "Origin": "https://example.com"})
        allowed = self.client.get("/api/search?q=", headers={**headers, "Origin": "http://localhost:5173"})
        self.assertNotIn("Access-Control-Allow-Origin", denied.headers)
        self.assertEqual(allowed.headers["Access-Control-Allow-Origin"], "http://localhost:5173")

    def test_write_back_is_disabled_by_default(self):
        response = self.client.post("/api/rename", headers={"Authorization": "Bearer test-token"}, json={})
        self.assertEqual(response.status_code, 403)

    def test_malformed_and_oversized_json_are_rejected(self):
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        malformed = self.client.post("/api/goto", headers=headers, data="[]")
        oversized = self.client.post("/api/goto", headers=headers, data='{"ea":"' + "A" * 70000 + '"}')
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(oversized.status_code, 413)

    def test_address_validation_rejects_invalid_ranges(self):
        self.assertEqual(self.plugin.parse_ea("0x140001000"), 0x140001000)
        for value in (None, True, "not-an-address", "-1", "FFFFFFFFFFFFFFFF"):
            with self.assertRaises(self.plugin.ApiError):
                self.plugin.parse_ea(value)


if __name__ == "__main__":
    unittest.main()
