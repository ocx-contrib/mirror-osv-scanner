# Stable smoke test — assert on the contract (exit code, version shape, scan
# behavior), never on help/version prose. osv-scanner reworks its banners and
# table output freely; the version digits, the scan exit codes, and the JSON
# result shape are the contract.
OSV = "osv-scanner.exe" if ocx.target_platform.os == ocx.os.Windows else "osv-scanner"

# Tier 1 + 2: liveness + version SHAPE (not a vendor string, not the exact version).
r_version = ocx.run(OSV, "--version")
expect.ok(r_version)
expect.matches(r_version.stdout, r"\d+\.\d+\.\d+")

# Tier 3: functional behavior. Scan a hermetic Python lockfile and assert on the
# CONTRACT, not prose:
#   - exit 0  → scanned, no vulnerabilities found
#   - exit 1  → scanned, vulnerabilities found (requests 2.20.0 has known CVEs)
# Both are a successful scan; any other code is a crash. JSON output is machine
# stable — it always carries a top-level "results" key. The file MUST be named
# `requirements.txt`: osv-scanner picks its extractor by filename, so a renamed
# lockfile yields "could not determine extractor" and exit 127.
ocx.write_file("requirements.txt", "requests==2.20.0\n")
r_scan = ocx.run(OSV, "scan", "source", "--format", "json", "-L", "requirements.txt")
expect.contains([0, 1], r_scan.exit_code)
expect.contains(r_scan.stdout, "results")
