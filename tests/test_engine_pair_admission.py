"""No chosen engine without independently prepared IR and KH."""
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
from app.engine_admission import ENGINES, engine_pair_readiness, require_engine_ready_pair


class EnginePairTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.status = {
            n: {"mode": "managed", "engines": {core: "not-installed" for core in ENGINES}}
            for n in ("ir", "kh")
        }
        self.client = type("Mock", (), {})()
        async def read(n):
            return self.status.get(n, {"status": "error"})
        self.client.get_engine_inventory = AsyncMock(side_effect=read)

    async def test_no_engine_is_ready_on_fresh_core(self):
        states = await engine_pair_readiness("ir", "kh", self.client)
        self.assertEqual(set(states), set(ENGINES))
        self.assertEqual(set(states.values()), {"not-installed"})
        for core in ENGINES:
            with self.assertRaises(HTTPException) as failed:
                await require_engine_ready_pair(core, "ir", "kh", self.client)
            self.assertEqual(failed.exception.status_code, 409)

    async def test_engine_installation_is_independent_on_both_nodes(self):
        self.status["ir"]["engines"]["backhaul"] = "ready"
        self.assertEqual((await engine_pair_readiness("ir", "kh", self.client))["backhaul"], "not-installed")
        self.status["kh"]["engines"]["backhaul"] = "ready"
        await require_engine_ready_pair("backhaul", "ir", "kh", self.client)
        with self.assertRaises(HTTPException):
            await require_engine_ready_pair("frp", "ir", "kh", self.client)
        self.status["kh"] = {"status": "error"}
        with self.assertRaises(HTTPException):
            await require_engine_ready_pair("backhaul", "ir", "kh", self.client)

    async def test_malformed_and_unreachable_signed_inventory_fail_closed(self):
        self.status["ir"]["engines"]["backhaul"] = "ready"
        self.status["kh"]["engines"]["backhaul"] = "ready"
        self.status["kh"]["engines"]["frp"] = "unexpected"
        states = await engine_pair_readiness("ir", "kh", self.client)
        self.assertEqual(set(states.values()), {"unavailable"})
        with self.assertRaises(HTTPException) as rejected:
            await require_engine_ready_pair("backhaul", "ir", "kh", self.client)
        self.assertEqual(rejected.exception.status_code, 409)

        self.status["kh"] = {"mode": "managed", "engines": {"backhaul": "ready"}}
        self.assertEqual(
            (await engine_pair_readiness("ir", "kh", self.client))["backhaul"],
            "unavailable",
        )

        self.client.get_engine_inventory = AsyncMock(side_effect=TimeoutError())
        self.assertEqual(
            set((await engine_pair_readiness("ir", "kh", self.client)).values()),
            {"unavailable"},
        )

    async def test_invalid_nodes_and_engines_are_denied(self):
        for left, right in (("", "kh"), ("ir", ""), ("ir", "ir")):
            state = await engine_pair_readiness(left, right, self.client)
            self.assertEqual(set(state.values()), {"select-nodes"})
        self.client.get_engine_inventory.assert_not_awaited()
        with self.assertRaises(HTTPException) as error:
            await require_engine_ready_pair("invented", "ir", "kh", self.client)
        self.assertEqual(error.exception.status_code, 422)


if __name__ == "__main__":
    unittest.main()
