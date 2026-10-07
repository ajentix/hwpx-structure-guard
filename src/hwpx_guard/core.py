from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import xml.etree.ElementTree as ElementTree
import zlib
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile


HEAD = "http://www.hancom.co.kr/hwpml/2011/head"
PARAGRAPH = "http://www.hancom.co.kr/hwpml/2011/paragraph"
SECTION = "http://www.hancom.co.kr/hwpml/2011/section"
SECTION_PATH = re.compile(r"Contents/section(?:0|[1-9][0-9]*)\.xml\Z")
REFERENCES = {
    "paraPrIDRef": "paraPr",
    "charPrIDRef": "charPr",
    "borderFillIDRef": "borderFill",
    "tabPrIDRef": "tabPr",
    "styleIDRef": "style",
    "nextStyleIDRef": "style",
}


class GuardError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 32 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    member_bytes: int = 16 * 1024 * 1024
    members: int = 1024
    compression_ratio: int = 200
    xml_nodes: int = 100_000
    xml_depth: int = 128


@dataclass
class Document:
    sha256: str
    member_hashes: dict[str, str] = field(repr=False)
    parts: dict[str, ElementTree.Element] = field(repr=False)
    issues: list[dict]

    def report(self) -> dict:
        return {
            "schema_version": 1,
            "scope": "bounded-package-and-selected-reference-checks",
            "sha256": self.sha256,
            "member_count": len(self.member_hashes),
            "xml_part_count": len(self.parts),
            "status": "PASS" if not self.issues else "FAIL",
            "issues": self.issues,
            "rendering_verified": False,
        }


def _parse_xml(payload: bytes, limits: Limits) -> ElementTree.Element:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise GuardError("Only UTF-8 XML is supported") from None
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise GuardError("XML DTD, entity declarations and NUL bytes are forbidden")
    declaration = re.match(r"\s*<\?xml\b[^?]*encoding\s*=\s*['\"]([^'\"]+)['\"]", text)
    if declaration and declaration[1].lower() not in {"utf-8", "utf8", "us-ascii"}:
        raise GuardError("Only UTF-8 XML is supported")
    depth = 0
    node_count = 0
    try:
        parser = ElementTree.iterparse(io.StringIO(text), events=("start", "end"))
        for event, _node in parser:
            if event == "start":
                depth += 1
                node_count += 1
                if depth > limits.xml_depth or node_count > limits.xml_nodes:
                    raise GuardError("XML complexity limit exceeded")
            else:
                depth -= 1
        return parser.root
    except ElementTree.ParseError:
        raise GuardError("Malformed XML") from None


def _reference_issues(parts: dict[str, ElementTree.Element]) -> list[dict]:
    issues = []
    header = parts["Contents/header.xml"]
    definitions = {}
    for kind in sorted(set(REFERENCES.values())):
        identifiers = [node.get("id") for node in header.iter(f"{{{HEAD}}}{kind}")]
        present = [identifier for identifier in identifiers if identifier is not None]
        definitions[kind] = set(present)
        if len(present) != len(identifiers) or len(set(present)) != len(present):
            issues.append({"kind": "invalid_definition_ids", "definition": kind})
    for part, root in sorted(parts.items()):
        for index, node in enumerate(root.iter()):
            if not node.tag.startswith((f"{{{HEAD}}}", f"{{{PARAGRAPH}}}")):
                continue
            for attribute, definition in REFERENCES.items():
                value = node.get(attribute)
                if value is not None and value not in definitions[definition]:
                    issues.append({
                        "kind": "unresolved_reference",
                        "part": part,
                        "node_index": index,
                        "attribute": attribute,
                    })
    return issues


def inspect(path: Path | str, limits: Limits | None = None) -> Document:
    limits = limits or Limits()
    with Path(path).open("rb") as source:
        payload = source.read(limits.archive_bytes + 1)
    if len(payload) > limits.archive_bytes:
        raise GuardError("Archive size limit exceeded")
    try:
        with ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > limits.members:
                raise GuardError("Archive member count limit exceeded")
            names = [entry.filename for entry in entries]
            if len(set(names)) != len(names):
                raise GuardError("Duplicate archive members are forbidden")
            total_size = 0
            for entry in entries:
                member_path = PurePosixPath(entry.filename)
                if (not entry.filename or member_path.is_absolute()
                        or ".." in member_path.parts or "\\" in entry.filename
                        or ":" in entry.filename or "\x00" in entry.orig_filename
                        or stat.S_ISLNK(entry.external_attr >> 16)):
                    raise GuardError("Unsafe archive member")
                if entry.flag_bits & 1:
                    raise GuardError("Encrypted archive members are unsupported")
                if entry.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
                    raise GuardError("Only stored and deflated archive members are supported")
                total_size += entry.file_size
                if entry.file_size > limits.member_bytes or total_size > limits.total_bytes:
                    raise GuardError("Uncompressed size limit exceeded")
                if entry.file_size > max(1, entry.compress_size) * limits.compression_ratio:
                    raise GuardError("Compression ratio limit exceeded")
            if not {"mimetype", "Contents/header.xml", "Contents/section0.xml"}.issubset(names):
                raise GuardError("Required HWPX members are missing")
            if (entries[0].filename != "mimetype" or entries[0].header_offset != 0
                    or entries[0].compress_type != ZIP_STORED
                    or archive.read("mimetype") != b"application/hwp+zip"):
                raise GuardError("HWPX mimetype must be first, stored and application/hwp+zip")
            parts = {}
            member_hashes = {}
            xml_node_count = 0
            for entry in entries:
                data = archive.read(entry)
                member_hashes[entry.filename] = hashlib.sha256(data).hexdigest()
                if entry.filename == "Contents/header.xml" or SECTION_PATH.fullmatch(entry.filename):
                    parts[entry.filename] = _parse_xml(data, limits)
                    xml_node_count += sum(1 for _node in parts[entry.filename].iter())
                    if xml_node_count > limits.xml_nodes:
                        raise GuardError("XML complexity limit exceeded")
            if parts["Contents/header.xml"].tag != f"{{{HEAD}}}head":
                raise GuardError("Unexpected HWPX header namespace or root")
            for name, root in parts.items():
                if name != "Contents/header.xml" and root.tag != f"{{{SECTION}}}sec":
                    raise GuardError("Unexpected HWPX section namespace or root")
    except (BadZipFile, NotImplementedError, RuntimeError, EOFError, UnicodeError, zlib.error):
        raise GuardError("Unreadable or unsupported ZIP package") from None
    return Document(hashlib.sha256(payload).hexdigest(), member_hashes, parts, _reference_issues(parts))


def _node_records(root: ElementTree.Element) -> list[tuple]:
    return [
        (node.tag, tuple(sorted(node.attrib.items())), node.text or "", node.tail or "", len(node))
        for node in root.iter()
    ]


def compare(candidate: Document, reference: Document) -> dict:
    differences = []
    for part in sorted(candidate.parts.keys() | reference.parts.keys()):
        if part not in candidate.parts or part not in reference.parts:
            differences.append({"part": part, "kind": "missing_part"})
            continue
        candidate_nodes = _node_records(candidate.parts[part])
        reference_nodes = _node_records(reference.parts[part])
        if len(candidate_nodes) != len(reference_nodes):
            differences.append({"part": part, "kind": "node_count"})
        for index, (candidate_node, reference_node) in enumerate(zip(candidate_nodes, reference_nodes)):
            changes = [
                name for name, candidate_value, reference_value in zip(
                    ("tag", "attributes", "text", "tail", "child_count"), candidate_node, reference_node
                ) if candidate_value != reference_value
            ]
            if changes:
                differences.append({"part": part, "node_index": index, "changes": changes})
    non_xml_candidate = {name: value for name, value in candidate.member_hashes.items() if name not in candidate.parts}
    non_xml_reference = {name: value for name, value in reference.member_hashes.items() if name not in reference.parts}
    return {
        "schema_version": 1,
        "scope": "ordered-xml-structure-and-other-member-byte-digests",
        "candidate_sha256": candidate.sha256,
        "reference_sha256": reference.sha256,
        "equivalent": not differences and non_xml_candidate == non_xml_reference,
        "candidate_issues": candidate.issues,
        "reference_issues": reference.issues,
        "xml_differences": differences,
        "other_members_equal": non_xml_candidate == non_xml_reference,
        "rendering_verified": False,
    }
