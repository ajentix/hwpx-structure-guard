from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from zipfile import ZIP_STORED, ZipFile

from hwpx_guard import GuardError, compare, inspect
from hwpx_guard.cli import main


HEAD = "http://www.hancom.co.kr/hwpml/2011/head"
PARAGRAPH = "http://www.hancom.co.kr/hwpml/2011/paragraph"
SECTION = "http://www.hancom.co.kr/hwpml/2011/section"
HEADER = f'<head xmlns="{HEAD}"/>'


class IndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def fixture(self, name="sample.hwpx", body="", header=HEADER, extra=()):
        destination = self.directory / name
        section = f'<sec xmlns="{SECTION}" xmlns:hp="{PARAGRAPH}">{body}</sec>'
        with ZipFile(destination, "w") as archive:
            archive.writestr("mimetype", "application/hwp+zip", compress_type=ZIP_STORED)
            archive.writestr("Contents/header.xml", header)
            archive.writestr("Contents/section0.xml", section)
            for member, content in extra:
                archive.writestr(member, content)
        return destination

    def test_hierarchy_move_with_same_node_order_is_detected(self):
        reference = self.fixture(body="<hp:p><hp:run/></hp:p><hp:p/>")
        candidate = self.fixture("candidate.hwpx", body="<hp:p/><hp:run/><hp:p/>")
        report = compare(inspect(candidate), inspect(reference))
        self.assertFalse(report["equivalent"])
        self.assertIn("child_count", report["xml_differences"][0]["changes"])

    def test_namespace_prefixes_do_not_change_equivalence(self):
        reference = self.fixture()
        candidate = self.fixture("candidate.hwpx", header=f'<hh:head xmlns:hh="{HEAD}"/>')
        self.assertTrue(compare(inspect(candidate), inspect(reference))["equivalent"])

    def test_comment_and_processing_instruction_ignored_as_documented(self):
        reference = self.fixture(body="<hp:p/>")
        candidate = self.fixture("candidate.hwpx", body="<!-- example --><?sample value?><hp:p/>")
        self.assertTrue(compare(inspect(candidate), inspect(reference))["equivalent"])

    def test_text_whitespace_is_significant(self):
        reference = self.fixture(body="<hp:p>text</hp:p>")
        candidate = self.fixture("candidate.hwpx", body="<hp:p> text</hp:p>")
        self.assertFalse(compare(inspect(candidate), inspect(reference))["equivalent"])

    def test_second_section_is_compared(self):
        section = f'<sec xmlns="{SECTION}"/>'
        reference = self.fixture(extra=(("Contents/section1.xml", section),))
        candidate = self.fixture("candidate.hwpx")
        report = compare(inspect(candidate), inspect(reference))
        self.assertFalse(report["equivalent"])
        self.assertIn({"part": "Contents/section1.xml", "kind": "missing_part"}, report["xml_differences"])

    def test_unresolved_value_never_appears_in_cli_report(self):
        reference = self.fixture()
        candidate = self.fixture("candidate.hwpx", body='<hp:p styleIDRef="private-synthetic-value"/>')
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            status = main(["compare", str(candidate), str(reference)])
        self.assertEqual(status, 1)
        self.assertNotIn("private-synthetic-value", captured.getvalue())
        self.assertNotIn(str(self.directory), captured.getvalue())
        json.loads(captured.getvalue())

    def test_malformed_xml_cli_error_does_not_echo_document_content(self):
        candidate = self.fixture(header="<private-synthetic-value>")
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            status = main(["inspect", str(candidate)])
        self.assertEqual(status, 2)
        self.assertNotIn("private-synthetic-value", captured.getvalue())
        self.assertNotIn(str(self.directory), captured.getvalue())
        json.loads(captured.getvalue())

    def test_invalid_crc_is_reported_without_traceback(self):
        candidate = self.fixture(body="<hp:p>synthetic-value</hp:p>")
        candidate.write_bytes(candidate.read_bytes().replace(b"synthetic-value", b"synthetic-other"))
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            status = main(["inspect", str(candidate)])
        self.assertEqual(status, 2)
        self.assertNotIn("Traceback", captured.getvalue())
        self.assertNotIn("synthetic", captured.getvalue())

    def test_utf8_bom_supported(self):
        candidate = self.fixture(header=b"\xef\xbb\xbf" + HEADER.encode())
        self.assertEqual(inspect(candidate).report()["status"], "PASS")

    def test_invalid_utf8_zip_name_is_reported_without_traceback(self):
        candidate = self.fixture(extra=(("private-synthetic-name", b"x"),))
        payload = bytearray(candidate.read_bytes())
        offset = payload.find(b"PK\x01\x02")
        while payload[offset:offset + 4] == b"PK\x01\x02":
            filename_length, extra_length, comment_length = struct.unpack_from("<HHH", payload, offset + 28)
            filename_start = offset + 46
            if payload[filename_start:filename_start + filename_length] == b"private-synthetic-name":
                struct.pack_into("<H", payload, offset + 8, 0x800)
                payload[filename_start] = 255
            offset += 46 + filename_length + extra_length + comment_length
        candidate.write_bytes(payload)
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            status = main(["inspect", str(candidate)])
        self.assertEqual(status, 2)
        self.assertNotIn("Traceback", captured.getvalue())
        self.assertNotIn("synthetic", captured.getvalue())
        json.loads(captured.getvalue())

    def test_declared_unsupported_encoding_with_spaces_is_rejected(self):
        candidate = self.fixture(header='<?xml version="1.0" encoding = "iso-8859-1"?>' + HEADER)
        with self.assertRaisesRegex(GuardError, "UTF-8"):
            inspect(candidate)

    def test_mimetype_must_be_first_physical_member(self):
        candidate = self.directory / "reordered-directory.hwpx"
        with ZipFile(candidate, "w") as archive:
            archive.writestr("Contents/header.xml", HEADER)
            archive.writestr("mimetype", "application/hwp+zip", compress_type=ZIP_STORED)
            archive.writestr("Contents/section0.xml", f'<sec xmlns="{SECTION}"/>')
        payload = candidate.read_bytes()
        with ZipFile(io.BytesIO(payload)) as archive:
            directory_start = archive.start_dir
        offset = directory_start
        records = []
        while payload[offset:offset + 4] == b"PK\x01\x02":
            record_size = 46 + sum(struct.unpack_from("<HHH", payload, offset + 28))
            records.append(payload[offset:offset + record_size])
            offset += record_size
        candidate.write_bytes(payload[:directory_start] + records[1] + records[0] + records[2] + payload[offset:])
        with self.assertRaisesRegex(GuardError, "mimetype"):
            inspect(candidate)


if __name__ == "__main__":
    unittest.main()
