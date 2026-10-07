# Security and privacy

The CLI reads local files only. It never sends documents or reports to a service, extracts archive members, opens a desktop application or downloads dependencies at runtime.

The parser has explicit size, compression, depth and node limits. XML DTDs and entity declarations are rejected. These checks reduce risk but are not a sandbox. Apply operating-system resource limits when processing hostile inputs at scale. Files with confidential contents should stay in a trusted local environment.

Reports intentionally omit raw XML text, attribute values, local paths and arbitrary asset filenames. Document hashes, counts and structural positions can still reveal relationships between documents. Do not publish reports without reviewing their metadata.

Do not attach confidential input files to public issues. Provide a minimal synthetic reproducer instead. Report vulnerabilities using the repository's private vulnerability reporting feature when available; otherwise contact a maintainer privately before disclosing exploit details.
