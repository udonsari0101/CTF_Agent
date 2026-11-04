"""Offline capacity warnings and protected-worker retention checks."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd()))

from ctf_agent.solver_autoscaler import MANAGED_LABEL, SLOT_LABEL, SolverAutoscaler
from ctf_agent.solver_service import SolverService
from ctf_agent.local_capacity import recommended_solver_concurrency


GIB = 1024**3


class FakeCoordinator:
    def __init__(self, *, demand: int = 1):
        self.demand = demand

    def reconcile_capacity(self):
        return {
            "baseline": 1, "hard_max": 0, "open_jobs": self.demand,
            "demand": self.demand, "requested": self.demand, "configured": self.demand,
        }


def capacity_service(sample, *, demand: int = 1):
    service = object.__new__(SolverService)
    monitor = SimpleNamespace(snapshot=lambda: sample)
    service.app = SimpleNamespace(state=SimpleNamespace(resource_monitor=monitor))
    service.coordinator = FakeCoordinator(demand=demand)
    service.baseline_concurrent = 1
    service.recommended_concurrent = 1
    service.admin_max = 0
    service.environment_max = 0
    service.web_pids_limit = 0
    return service


class FakeEngine:
    def __init__(self):
        self.template = {
            "State": {"Running": True}, "Config": {"Labels": {}},
            "Image": "sha256:template",
        }
        self.extra = {
            "State": {"Running": True},
            "Config": {"Labels": {MANAGED_LABEL: "true", SLOT_LABEL: "2"}},
        }
        self.stopped = []
        self.removed = []

    def inspect(self, name):
        return self.template if name == "solver" else self.extra

    def managed(self):
        return [{"Labels": {MANAGED_LABEL: "true", SLOT_LABEL: "2"}, "Names": ["/solver_2"]}]

    def stop(self, name):
        self.stopped.append(name)

    def remove(self, name):
        self.removed.append(name)


class ResourcePolicyTest(unittest.TestCase):
    def test_high_cpu_and_low_memory_warn_without_limiting_capacity(self):
        service = capacity_service(
            {"cpu_percent": 94.5, "memory_total_bytes": 16 * GIB,
             "memory_used_bytes": 12 * GIB}, demand=2,
        )
        result = service.capacity_snapshot()
        self.assertTrue(result["warning"])
        self.assertTrue(result["resource_pressure_warning"])
        self.assertFalse(result["limited"])
        self.assertEqual(result["resource_memory_available_bytes"], 4 * GIB)
        self.assertIn("CPU", result["warning_message"])
        self.assertIn("메모리", result["warning_message"])

    def test_unmeasured_resources_remain_explicitly_unknown(self):
        service = capacity_service({"cpu_percent": None, "memory_total_bytes": None,
                                    "memory_used_bytes": None})
        result = service.capacity_snapshot()
        self.assertEqual(result["resource_measurement"], "unmeasured")
        self.assertIsNone(result["resource_cpu_percent"])
        self.assertIsNone(result["resource_memory_available_bytes"])
        self.assertFalse(result["resource_pressure_warning"])
        self.assertFalse(result["warning"])

    def test_missing_monitor_does_not_break_capacity(self):
        service = capacity_service({})
        service.app.state.resource_monitor = None
        self.assertEqual(service.capacity_snapshot()["resource_measurement"], "unmeasured")

    def test_surplus_busy_solver_is_retained_but_idle_one_is_removed(self):
        for idle in (False, True):
            with self.subTest(idle=idle), tempfile.TemporaryDirectory() as folder:
                engine = FakeEngine()
                scaler = SolverAutoscaler(
                    engine, template_name="solver", container_prefix="solver_",
                    control_path=Path(folder) / "control.json", static_count=1,
                    storage_root=Path(folder),
                )
                with patch("ctf_agent.solver_autoscaler.validate_slot_container"), patch(
                    "ctf_agent.solver_autoscaler._slot_is_idle", return_value=idle
                ):
                    result = scaler.reconcile({"desired": 1, "slots": [1]})
                self.assertEqual(engine.stopped, ["solver_2"] if idle else [])
                self.assertEqual(engine.removed, ["solver_2"] if idle else [])
                self.assertEqual(result["retained"], 0 if idle else 1)

    def test_local_recommendation_respects_cpu_and_memory_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cgroup = root / "cgroup"
            cgroup.mkdir()
            (cgroup / "cpu.max").write_text("600000 100000", encoding="ascii")
            meminfo = root / "meminfo"
            meminfo.write_text("MemAvailable: 67108864 kB\n", encoding="ascii")
            self.assertEqual(recommended_solver_concurrency(
                cgroup=cgroup, meminfo=meminfo, logical_cpus=16, override=""
            ), 3)
            meminfo.write_text("MemAvailable: 10485760 kB\n", encoding="ascii")
            self.assertEqual(recommended_solver_concurrency(
                cgroup=cgroup, meminfo=meminfo, logical_cpus=16, override=""
            ), 1)
            self.assertEqual(recommended_solver_concurrency(
                cgroup=cgroup, meminfo=meminfo, logical_cpus=16, override="12"
            ), 12)


if __name__ == "__main__":
    unittest.main()
