"""pp-scan 统计逻辑的单元测试（合成数据，不跑编译）。"""

import json
import pathlib
import tempfile
import unittest

from tools.experiment.pp_scan import summarize_contracts


def contract_row(api: str, admission: str, allocation: str, guard: str) -> dict:
    return {
        "schema_version": "bw.rust-contract/0.1",
        "run_id": "t",
        "api_id": api,
        "foreign_symbol": "sym",
        "contract": {
            "hand_off": {},
            "capture_admission": admission,
            "guard": guard,
            "allocation": allocation,
            "evidence": [],
        },
    }


def gap_row(api: str, reasons: list[str]) -> dict:
    return {
        "schema_version": "bw.rust-contract/0.1",
        "run_id": "t",
        "api_id": api,
        "foreign_symbol": None,
        "contract": None,
        "gaps": reasons,
    }


class SummarizeContractsTest(unittest.TestCase):
    def write_contracts(self, rows):
        tmp = tempfile.mkdtemp()
        path = pathlib.Path(tmp) / "rust-contracts.jsonl"
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        return path

    def test_tier_a_r_and_a_a_are_counted(self):
        rows = [
            contract_row("api_a", "permits_non_static_capture", "unresolved", "none"),
            contract_row("api_b", "requires_static_capture", "rust_retains_and_may_free_early", "none"),
            gap_row("api_c", ["safe_entry_lineage_unresolved"]),
        ]
        stats = summarize_contracts(self.write_contracts(rows))
        self.assertEqual(stats["handoffs_total"], 3)
        self.assertEqual(stats["assembled"], 2)
        self.assertEqual(stats["gapped"], 1)
        self.assertEqual(stats["tier_a_r"], 1)
        self.assertEqual(stats["tier_a_a"], 1)
        self.assertEqual(stats["gap_reasons"], {"safe_entry_lineage_unresolved": 1})

    def test_guard_distribution(self):
        rows = [
            contract_row("api_a", "permits_non_static_capture", "unresolved", "none"),
            contract_row("api_b", "permits_non_static_capture", "unresolved", "ties_slot_to_subject"),
            contract_row("api_c", "permits_non_static_capture", "unresolved", "owner_holds_callback"),
            contract_row("api_d", "permits_non_static_capture", "unresolved", "unresolved"),
        ]
        stats = summarize_contracts(self.write_contracts(rows))
        self.assertEqual(stats["guard_none"], 1)
        self.assertEqual(stats["guard_ties"], 1)
        self.assertEqual(stats["guard_owner_holds"], 1)
        self.assertEqual(stats["guard_unresolved"], 1)
        self.assertEqual(stats["tier_a_r"], 4)

    def test_empty_input(self):
        stats = summarize_contracts(self.write_contracts([]))
        self.assertEqual(stats["handoffs_total"], 0)
        self.assertEqual(stats["assembled"], 0)
        self.assertEqual(stats["tier_a_r"], 0)
        self.assertEqual(stats["tier_a_a"], 0)


if __name__ == "__main__":
    unittest.main()
