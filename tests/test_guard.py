from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

from hwpx_guard import GuardError, Limits, compare, inspect
from hwpx_guard.cli import main


HEAD = "http://www.hancom.co.kr/hwpml/2011/head"
PARAGRAPH = "http://www.hancom.co.kr/hwpml/2011/paragraph"
SECTION = "http://www.hancom.co.kr/hwpml/2011/section"
HEADER = f'<hh:head xmlns:hh="{HEAD}"><hh:charPr id="0"/><hh:paraPr id="0"/></hh:head>'
SECTION_XML = f'<hs:sec xmlns:hs="{SECTION}" xmlns:hp="{PARAGRAPH}"><hp:p paraPrIDRef="0"><hp:run charPrIDRef="0"><hp:t>Synthetic example</hp:t></hp:run></hp:p></hs:sec>'


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, name="sample.hwpx", header=HEADER, section=SECTION_XML, extra=None):
        path = self.root / name
        with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("mimetype", "application/hwp+zip", compress_type=ZIP_STORED)
            archive.writestr("Contents/header.xml", header)
            archive.writestr("Contents/section0.xml", section)
            for member, payload in extra or []:
                archive.writestr(member, payload)
        return path

    def test_valid_package_and_read_only(self):
        path = self.fixture()
        before = path.read_bytes()
        self.assertEqual(inspect(path).report()["status"], "PASS")
        self.assertEqual(path.read_bytes(), before)

    def test_equal(self):
        document = inspect(self.fixture())
        self.assertTrue(compare(document, document)["equivalent"])

    def test_unresolved_reference(self):
        document = inspect(self.fixture(section=SECTION_XML.replace('charPrIDRef="0"', 'charPrIDRef="private-reference"')))
        self.assertEqual(document.issues[0]["kind"], "unresolved_reference")
        self.assertNotIn("private-reference", json.dumps(document.report()))

    def test_duplicate_definition(self):
        header = HEADER.replace('<hh:charPr id="0"/>', '<hh:charPr id="0"/><hh:charPr id="0"/>')
        self.assertEqual(inspect(self.fixture(header=header)).issues[0]["kind"], "invalid_definition_ids")

    def test_namespace_change_detected(self):
        reference = inspect(self.fixture())
        candidate = inspect(self.fixture("changed.hwpx", section=SECTION_XML.replace(PARAGRAPH, "urn:synthetic")))
        self.assertFalse(compare(candidate, reference)["equivalent"])

    def test_order_change_detected(self):
        prefix = f'<hs:sec xmlns:hs="{SECTION}" xmlns:hp="{PARAGRAPH}">'
        reference = inspect(self.fixture(section=prefix + '<hp:p/><hp:run/></hs:sec>'))
        candidate = inspect(self.fixture("changed.hwpx", section=prefix + '<hp:run/><hp:p/></hs:sec>'))
        self.assertFalse(compare(candidate, reference)["equivalent"])

    def test_tail_change_detected(self):
        reference = inspect(self.fixture())
        candidate = inspect(self.fixture("changed.hwpx", section=SECTION_XML.replace('</hp:t>', '</hp:t>tail')))
        self.assertFalse(compare(candidate, reference)["equivalent"])

    def test_attributes_change_detected(self):
        reference = inspect(self.fixture())
        candidate = inspect(self.fixture("changed.hwpx", section=SECTION_XML.replace('<hp:p ', '<hp:p id="1" ')))
        self.assertFalse(compare(candidate, reference)["equivalent"])

    def test_attribute_order_ignored(self):
        first = SECTION_XML.replace('<hp:p ', '<hp:p id="1" ')
        second = SECTION_XML.replace('paraPrIDRef="0"', 'paraPrIDRef="0" id="1"')
        self.assertTrue(compare(inspect(self.fixture(section=first)), inspect(self.fixture("other.hwpx", section=second)))["equivalent"])

    def test_binary_change_detected_without_filename_disclosure(self):
        reference = inspect(self.fixture(extra=[("BinData/private-name.bin", b"first")]))
        candidate = inspect(self.fixture("other.hwpx", extra=[("BinData/private-name.bin", b"second")]))
        report = compare(candidate, reference)
        self.assertFalse(report["equivalent"])
        self.assertNotIn("private-name", json.dumps(report))

    def test_doctype_rejected(self):
        section = '<!DOCTYPE sec [<!ENTITY example "x">]>' + SECTION_XML
        with self.assertRaisesRegex(GuardError, "DTD"):
            inspect(self.fixture(section=section))

    def test_utf16_rejected(self):
        with self.assertRaisesRegex(GuardError, "UTF-8"):
            inspect(self.fixture(section=SECTION_XML.encode("utf-16")))

    def test_malformed_xml_rejected(self):
        with self.assertRaisesRegex(GuardError, "Malformed"):
            inspect(self.fixture(section="<invalid>"))

    def test_root_namespace_rejected(self):
        with self.assertRaisesRegex(GuardError, "namespace"):
            inspect(self.fixture(header=HEADER.replace(HEAD, "urn:other")))

    def test_traversal_rejected(self):
        with self.assertRaisesRegex(GuardError, "Unsafe"):
            inspect(self.fixture(extra=[("../escape", b"x")]))

    def test_symlink_rejected(self):
        member = ZipInfo("link")
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(GuardError, "Unsafe"):
            inspect(self.fixture(extra=[(member, b"target")]))

    def test_duplicate_member_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            path = self.fixture(extra=[("Contents/header.xml", HEADER)])
        with self.assertRaisesRegex(GuardError, "Duplicate"):
            inspect(path)

    def test_limits(self):
        path = self.fixture()
        for limits in [Limits(archive_bytes=1), Limits(member_bytes=1), Limits(total_bytes=1),
                       Limits(members=1), Limits(xml_nodes=1), Limits(xml_depth=1)]:
            with self.subTest(limits=limits), self.assertRaises(GuardError):
                inspect(path, limits)

    def test_compression_ratio_limit(self):
        path = self.fixture(extra=[("BinData/repeated.bin", b"x" * 100_000)])
        with self.assertRaisesRegex(GuardError, "ratio"):
            inspect(path)

    def test_xml_node_limit_applies_across_parts(self):
        path = self.fixture(extra=[("Contents/section1.xml", SECTION_XML)])
        with self.assertRaisesRegex(GuardError, "complexity"):
            inspect(path, Limits(xml_nodes=8))

    def test_missing_member_rejected(self):
        path = self.root / "empty.hwpx"
        with ZipFile(path, "w"):
            pass
        with self.assertRaisesRegex(GuardError, "Required"):
            inspect(path)

    def test_invalid_zip_rejected(self):
        path = self.root / "not-zip.hwpx"
        path.write_bytes(b"not zip")
        with self.assertRaisesRegex(GuardError, "ZIP"):
            inspect(path)

    def test_reports_hide_content_and_paths(self):
        path = self.fixture("private-filename.hwpx", section=SECTION_XML.replace("Synthetic example", "Private content"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["inspect", str(path)])
        self.assertEqual(status, 0)
        self.assertNotIn("private-filename", output.getvalue())
        self.assertNotIn("Private content", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    def test_cli_difference_status(self):
        reference = self.fixture()
        candidate = self.fixture("different.hwpx", section=SECTION_XML.replace("example", "different"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["compare", str(candidate), str(reference)]), 1)

    def test_cli_error_status_hides_paths(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            status = main(["inspect", str(self.root / "sensitive.hwpx")])
        self.assertEqual(status, 2)
        self.assertNotIn("sensitive", output.getvalue())


if __name__ == "__main__":
    unittest.main()
