# HWPX Structure Guard

A small, dependency-free Python CLI for read-only HWPX package checks and ordered XML comparison. It does not open desktop applications, extract archives to disk, make network requests, or modify input files.

## Install

Requires Python 3.10 or later.

```sh
python -m pip install .
hwpx-guard inspect document.hwpx
hwpx-guard compare candidate.hwpx reference.hwpx
```

Both commands emit JSON. Exit status is `0` for a passing check or equivalent valid documents, `1` for reference issues or a comparison difference, and `2` for unsupported, unsafe, unreadable, or malformed input.

## What it checks

- Bounded ZIP processing (stored/deflated members), duplicate members, path traversal, symlinks, encryption and suspicious compression ratios
- A first, uncompressed `mimetype` member with the value `application/hwp+zip`
- Required header and first section, UTF-8 XML, expected root namespaces, bounded XML depth and node count
- Selected header definitions and references: paragraph properties, character properties, border fills, tabs and styles
- XML element order, expanded namespace names, attributes, text, tail text and hierarchy
- Byte digests of other package members, including images and metadata

XML namespace prefixes and attribute order do not affect comparison. Whitespace text, tail text and document content do affect it. ZIP timestamps and compression choices do not affect comparison. XML comments and processing instructions are ignored by the parser. A differing generated metadata member can make two visually identical documents compare unequal.

Reports omit document text, raw attribute values, input paths and nonstandard member names. Reports still contain file hashes, structural positions and counts. Treat them as potentially sensitive metadata, not as automatically safe public artifacts.

## Important limits

This is not a complete HWPX schema validator, renderer, HWP converter, document sanitizer, malware scanner or proof of visual fidelity. It does not certify provenance, native application compatibility, page count, font substitution, clipping, signatures or legal acceptability. In particular, a structural PASS must not be reported as a visual QA PASS. No customer documents or templates are included.

Default bounds are a 32 MiB archive, 64 MiB total uncompressed data, 16 MiB per member, 1,024 members, compression ratio 200, XML depth 128 and 100,000 nodes across all parsed XML parts. Trusted integrations can pass a `Limits` object to the Python API. Conservative checks can reject otherwise legitimate files. Do not remove limits to accept untrusted inputs in a long-running service.

```python
from hwpx_guard import compare, inspect

report = compare(inspect("candidate.hwpx"), inspect("reference.hwpx"))
assert report["equivalent"]
```

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m pip wheel --no-deps . -w dist
```

All test documents are minimal synthetic ZIP/XML packages constructed in temporary directories. They are not production templates and are not claims of application-renderable document validity.

MIT licensed. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md) and [PUBLICATION.md](PUBLICATION.md).
