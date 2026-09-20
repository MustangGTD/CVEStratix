# Release checks

- Python 3.12: syntax compilation, --version and offline unittest suite passed.
- 14 tests: inputs, simple CPE conversion, missing version, exact/mismatched versions,
  numeric range boundaries, unresolved configuration caveats, pagination, partial failures,
  XML host filtering, IPv6 commands, complete mocked workflow/reports, default full TCP command,
  HTTP redirect/TLS behavior, and untrusted text rendering.
- Live NVD query for Apache HTTP Server 2.4.49 retrieved 69 records across the reported query
  result set in the release environment. CVE-2021-41773 was found with version evidence and
  publication timestamp 2021-10-05T09:15:07.593. Counts can change as NVD updates.
- Nmap is not installed in the build environment. Its command generation and XML parsing were
  tested, but a real Nmap/Kali scan was NOT performed here. Run your first test on your own server.
- No exploitation or external research-tool execution was performed.

Run: `python -m unittest discover -s tests -v`
