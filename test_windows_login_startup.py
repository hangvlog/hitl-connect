import importlib.machinery
import importlib.util
from pathlib import Path
import unittest


loader = importlib.machinery.SourceFileLoader(
    "startup", str(Path(__file__).with_name("windows-login-startup.pyw")))
spec = importlib.util.spec_from_loader(loader.name, loader)
startup = importlib.util.module_from_spec(spec)
loader.exec_module(startup)


class StartupTests(unittest.TestCase):
    def test_batch_entry_preserves_windows_path_separators(self):
        entry = Path(__file__).with_name("windows-login-startup.cmd").read_bytes()
        self.assertFalse([byte for byte in entry if byte < 32 and byte not in (10, 13)])
        self.assertIn(rb".workbuddy\binaries\python\versions\3.13.12\pythonw.exe", entry)
        self.assertIn(rb"%HITL_STARTUP_DIR%\bootstrap.log", entry)
        self.assertIn(b"entry_started", entry)

    def run_case(self, states, launch_result=0):
        events, launched = [], []
        states = iter(states)
        code = startup.ensure_provider(
            {}, lambda event, **fields: events.append(event),
            query=lambda _: next(states),
            launch=lambda _: launched.append(True) or launch_result,
            sleep=lambda _: None)
        return code, events, launched

    def test_running_with_network_failure_is_not_restarted(self):
        code, events, launched = self.run_case([
            {"code": "RELAY_FAILED", "state": {"running": True}}])
        self.assertEqual((code, events, launched), (0, ["already_running"], []))

    def test_manually_stopped_panel_is_preserved(self):
        code, _, launched = self.run_case([
            {"code": "STATUS", "state": {"running": False}}])
        self.assertEqual(code, 1)
        self.assertFalse(launched)

    def test_offline_provider_is_launched_once(self):
        offline = {"code": "SYSTEM_SSH_PROVIDER_NOT_RUNNING"}
        code, events, launched = self.run_case([
            offline, offline, {"state": {"running": True}}])
        self.assertEqual(code, 0)
        self.assertEqual(launched, [True])
        self.assertEqual(events[-1], "provider_running")

    def test_declined_elevation_is_not_retried(self):
        code, events, launched = self.run_case([
            {"code": "SYSTEM_SSH_PROVIDER_NOT_RUNNING"}], 5)
        self.assertEqual(code, 1)
        self.assertEqual(launched, [True])
        self.assertEqual(events[-1], "elevation_not_completed")

    def test_missing_or_failed_state_does_not_claim_success(self):
        offline = {"code": "SYSTEM_SSH_PROVIDER_NOT_RUNNING"}
        code, events, _ = self.run_case([offline] * 21)
        self.assertEqual(code, 1)
        self.assertEqual(events[-1], "startup_not_confirmed")


if __name__ == "__main__":
    unittest.main()
