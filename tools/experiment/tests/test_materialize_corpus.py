"""Tests for the corpus materializer.

The extraction path is the security-relevant part: a .crate archive is
attacker-controlled input once the corpus selection includes anything the
operator did not author, so members that escape the corpus root must be
rejected rather than written.
"""

import io
import json
import pathlib
import tarfile
import tempfile
import unittest

from tools.experiment.materialize_corpus import (
    MaterializeError,
    materialized_record,
    read_manifest,
    safe_extract,
)


def build_archive(path: pathlib.Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


def add_link(path: pathlib.Path, name: str, target: str) -> None:
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("demo-1.0.0/Cargo.toml")
        info.size = 0
        tar.addfile(info, io.BytesIO(b""))
        link = tarfile.TarInfo(name)
        link.type = tarfile.SYMTYPE
        link.linkname = target
        tar.addfile(link)


class SafeExtractTests(unittest.TestCase):
    def test_extracts_a_single_rooted_archive(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive = root / "demo.crate"
            build_archive(
                archive,
                [("demo-1.0.0/Cargo.toml", b"[package]\n"), ("demo-1.0.0/src/lib.rs", b"")],
            )
            extracted = safe_extract(archive, root / "out")
            self.assertEqual(extracted.name, "demo-1.0.0")
            self.assertTrue((extracted / "Cargo.toml").is_file())

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive = root / "evil.crate"
            build_archive(archive, [("../escaped.rs", b"pwned")])
            (root / "out").mkdir()
            with self.assertRaises(MaterializeError):
                safe_extract(archive, root / "out")
            self.assertFalse((root / "escaped.rs").exists())

    def test_rejects_absolute_member(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive = root / "evil.crate"
            build_archive(archive, [("/etc/pwned", b"pwned")])
            with self.assertRaises(MaterializeError):
                safe_extract(archive, root / "out")

    def test_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive = root / "evil.crate"
            add_link(archive, "demo-1.0.0/link", "/etc/passwd")
            with self.assertRaises(MaterializeError):
                safe_extract(archive, root / "out")

    def test_rejects_multiple_top_level_directories(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            archive = root / "two.crate"
            build_archive(archive, [("a-1.0.0/Cargo.toml", b""), ("b-1.0.0/Cargo.toml", b"")])
            with self.assertRaises(MaterializeError):
                safe_extract(archive, root / "out")


class ManifestTests(unittest.TestCase):
    def test_rejects_an_empty_manifest(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest = pathlib.Path(raw) / "corpus.jsonl"
            manifest.write_text("\n\n", encoding="utf-8")
            with self.assertRaises(MaterializeError):
                read_manifest(manifest)

    def test_reports_the_offending_line_for_invalid_json(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest = pathlib.Path(raw) / "corpus.jsonl"
            manifest.write_text('{"a":1}\nnot json\n', encoding="utf-8")
            with self.assertRaises(MaterializeError) as caught:
                read_manifest(manifest)
            self.assertIn(":2:", str(caught.exception))


class MaterializedRecordTests(unittest.TestCase):
    def setUp(self):
        self.record = {
            "schema_version": "v3.2.corpus_manifest.1",
            "corpus_id": "corpus.test",
            "crate_id": "crate:demo:1.0.0",
            "crate_name": "demo",
            "version": "1.0.0",
            "source_kind": "crates_io",
            "source_ref": "crates.io:demo:1.0.0",
            "selection_reason": ["pure_rust"],
            "intake_status": "accepted",
            "intake_notes": [],
        }

    def test_rewrites_source_kind_and_records_provenance(self):
        updated = materialized_record(
            self.record, pathlib.Path("/corpus/demo-1.0.0"), "abc123", None
        )
        self.assertEqual(updated["source_kind"], "local_archive")
        self.assertEqual(updated["source_ref"], "/corpus/demo-1.0.0")
        self.assertIn("materialized_from=crates_io:crates.io:demo:1.0.0", updated["intake_notes"])
        self.assertIn("archive_sha256=abc123", updated["intake_notes"])

    def test_keeps_the_original_record_unchanged(self):
        materialized_record(self.record, pathlib.Path("/corpus/demo-1.0.0"), "abc123", None)
        self.assertEqual(self.record["source_kind"], "crates_io")
        self.assertEqual(self.record["intake_notes"], [])

    def test_writes_relative_refs_when_asked(self):
        updated = materialized_record(
            self.record,
            pathlib.Path("/corpus/demo-1.0.0"),
            None,
            pathlib.Path("/corpus"),
        )
        self.assertEqual(updated["source_ref"], "demo-1.0.0")

    def test_omits_the_digest_note_when_nothing_was_downloaded(self):
        updated = materialized_record(self.record, pathlib.Path("/corpus/demo-1.0.0"), None, None)
        self.assertFalse(
            any(note.startswith("archive_sha256=") for note in updated["intake_notes"])
        )

    def test_result_still_serializes_as_one_jsonl_record(self):
        updated = materialized_record(
            self.record, pathlib.Path("/corpus/demo-1.0.0"), "abc123", None
        )
        line = json.dumps(updated, sort_keys=True)
        self.assertNotIn("\n", line)
        self.assertEqual(json.loads(line)["source_kind"], "local_archive")


if __name__ == "__main__":
    unittest.main()
