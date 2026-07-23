import importlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend import database as db_mod
from backend.ML import machine_learning as ml_mod
from backend.DL import deep_learning as dl_mod


class SettingsLogicTests(unittest.TestCase):
    def test_get_latest_network_stats_uses_ml_stats_for_rf_model(self):
        ml_stats = {
            "connections": 7,
            "packet_rate": 2,
            "score": 77,
            "message": "ML stable",
            "is_anomaly": False,
            "recent_flows": []
        }
        dl_stats = {
            "connections": 999,
            "packet_rate": 99,
            "score": 99,
            "message": "DL stable",
            "is_anomaly": False,
            "recent_flows": []
        }

        with patch.object(ml_mod, "stats", ml_stats), patch.object(dl_mod, "stats", dl_stats):
            data = db_mod.get_latest_network_stats("rf")

        self.assertEqual(data["active_connections"], 7)
        self.assertEqual(data["packet_rate"], 2)
        self.assertEqual(data["risk_score"], 77)

    def test_run_network_check_ml_uses_database_monitoring_mode(self):
        class DummySession:
            def close(self):
                pass

        def fake_sniff(*args, **kwargs):
            stop_filter = kwargs.get("stop_filter")
            self.assertTrue(callable(stop_filter))
            stop_filter(None)
            return None

        with patch.object(db_mod, "get_settings_db", return_value=SimpleNamespace(monitoring_mode="scapy", active_model="rf")):
            ml_module = importlib.reload(ml_mod)
            with patch.object(ml_module, "SessionLocal", return_value=DummySession()):
                with patch.object(ml_module, "sniff", side_effect=fake_sniff):
                    result = ml_module.run_network_check_ML()

        self.assertEqual(result["message"], "System is stable.")


if __name__ == "__main__":
    unittest.main()
