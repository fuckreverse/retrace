import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tenet.ida.sync import NavigationSync


class _FakeAdapter(object):
    def __init__(self, ea=0x1000, image_base=0x100000000):
        self._ea = ea
        self._image_base = image_base
        self.jump_calls = []
        self.image_base_reads = 0

    def current_ea(self):
        return self._ea

    def jumpto(self, ea):
        self._ea = ea
        self.jump_calls.append(ea)

    def get_image_base(self):
        self.image_base_reads += 1
        return self._image_base


class _FakeTenetClient(object):
    def __init__(self):
        self.cursor = {"inst_id": 0, "pc": "0x1000"}
        self.search_map = {}
        self.search_results = {}
        self.search_calls = []
        self.navigate_calls = []
        self.image_base_calls = []

    def get_cursor(self):
        return dict(self.cursor)

    def search_pc(self, pc_hex, offset=0, limit=100, nearest_to_inst_id=None):
        self.search_calls.append((pc_hex, offset, limit, nearest_to_inst_id))
        result = self.search_results.get((pc_hex, offset, nearest_to_inst_id))
        if result is None:
            result = self.search_results.get((pc_hex, offset))
        if result is not None:
            payload = {
                "inst_ids": list(result.get("inst_ids", [])),
                "has_more": bool(result.get("has_more", False)),
                "next_offset": result.get("next_offset"),
            }
            if "nearest_inst_id" in result:
                payload["nearest_inst_id"] = result.get("nearest_inst_id")
            return payload
        return {"inst_ids": list(self.search_map.get(pc_hex, []))}

    def navigate(self, inst_id):
        self.navigate_calls.append(inst_id)
        self.cursor = {"inst_id": inst_id, "pc": "0x{0:X}".format(0x1000 + inst_id)}
        return dict(self.cursor)

    def set_image_base(self, image_base):
        self.image_base_calls.append(image_base)
        return {"ok": True, "new_image_base": image_base}


class NavigationSyncTests(unittest.TestCase):
    def test_selects_nearest_occurrence_not_first(self):
        adapter = _FakeAdapter(ea=0x3000)
        client = _FakeTenetClient()
        client.cursor = {"inst_id": 100, "pc": "0x3000"}
        client.search_map["0x3000"] = []
        client.search_results[("0x4000", 0, 100)] = {
            "inst_ids": [10, 90, 130],
            "nearest_inst_id": 90,
        }

        sync = NavigationSync(adapter, client)

        sync.tick_once()  # warm up cursor state
        adapter._ea = 0x4000
        sync.tick_once()

        self.assertEqual([("0x4000", 0, 100, 100)], client.search_calls)
        self.assertEqual([90], client.navigate_calls)
        self.assertEqual("0x105A", client.cursor["pc"])

    def test_uses_backend_nearest_result_without_pagination(self):
        adapter = _FakeAdapter(ea=0x3000)
        client = _FakeTenetClient()
        client.cursor = {"inst_id": 520, "pc": "0x3000"}
        client.search_map["0x3000"] = []
        client.search_results[("0x4000", 0, 520)] = {
            "inst_ids": [100, 250],
            "has_more": True,
            "next_offset": 256,
            "nearest_inst_id": 518,
        }

        sync = NavigationSync(adapter, client)

        sync.tick_once()
        adapter._ea = 0x4000
        sync.tick_once()

        self.assertEqual(
            [("0x4000", 0, 100, 520)],
            client.search_calls,
        )
        self.assertEqual([518], client.navigate_calls)

    def test_large_conceptual_exec_count_still_uses_single_backend_query(self):
        adapter = _FakeAdapter(ea=0x3000)
        client = _FakeTenetClient()
        client.cursor = {"inst_id": 17000, "pc": "0x3000"}
        client.search_map["0x3000"] = []
        client.search_results[("0x5000", 0, 17000)] = {
            "inst_ids": [1],
            "has_more": True,
            "next_offset": 16384,
            "nearest_inst_id": 16999,
            "exec_count": 20000,
        }

        sync = NavigationSync(adapter, client)

        sync.tick_once()
        adapter._ea = 0x5000
        sync.tick_once()

        self.assertEqual([("0x5000", 0, 100, 17000)], client.search_calls)
        self.assertEqual([16999], client.navigate_calls)

    def test_feedback_loop_suppression_after_tenet_to_ida_jump(self):
        adapter = _FakeAdapter(ea=0x1000)
        client = _FakeTenetClient()
        client.cursor = {"inst_id": 50, "pc": "0x5000"}

        sync = NavigationSync(adapter, client)
        sync.tick_once()

        self.assertEqual([0x5000], adapter.jump_calls)
        self.assertEqual([], client.search_calls)
        self.assertEqual([], client.navigate_calls)

        sync.tick_once()
        self.assertEqual([], client.search_calls)

    def test_no_duplicate_navigation_for_same_ida_cursor(self):
        adapter = _FakeAdapter(ea=0x2000)
        client = _FakeTenetClient()
        client.cursor = {"inst_id": 5, "pc": "0x2000"}
        client.search_map["0x2000"] = []
        client.search_map["0x6000"] = [200]

        sync = NavigationSync(adapter, client)

        sync.tick_once()
        adapter._ea = 0x6000
        sync.tick_once()
        sync.tick_once()

        self.assertEqual([200], client.navigate_calls)
        self.assertEqual(1, len(client.search_calls))

        adapter._ea = 0x1000 + 200
        sync.tick_once()
        self.assertEqual([200], client.navigate_calls)

    def test_constructor_has_no_navigation_side_effects(self):
        adapter = _FakeAdapter(ea=0x1000, image_base=0x180000000)
        client = _FakeTenetClient()

        sync = NavigationSync(adapter, client)

        self.assertIsNotNone(sync)
        self.assertEqual([], client.search_calls)
        self.assertEqual([], client.navigate_calls)
        self.assertEqual([], adapter.jump_calls)


if __name__ == "__main__":
    unittest.main()
