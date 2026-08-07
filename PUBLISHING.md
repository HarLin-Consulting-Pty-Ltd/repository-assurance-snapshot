# Publishing state

The package is installable from the public GitHub release without a package-registry account:

```bash
python -m pip install "repository-assurance-snapshot @ git+https://github.com/HarLin-Consulting-Pty-Ltd/repository-assurance-snapshot.git@v0.1.2"
```

## Python registry gate

As checked on 2026-08-08, the Python Package Index returned `404 Not Found` for
`repository-assurance-snapshot`, which is consistent with the distribution name
being unused at that moment. This is not a reservation.

HarLin's canonical Credentials Pad does not currently list a PyPI publishing
identity or token. Do not create an account, upload a distribution or treat the
name as reserved without a sanctioned HarLin identity and a fresh availability
check.

Before a future registry release:

1. Confirm the authorised legal publisher and public support route.
2. Create a scoped API token for the intended registry and store it in the
   canonical Credentials Pad without placing it in repository files or logs.
3. Rebuild from a clean tree and validate wheel and source archive contents.
4. Install the wheel into a clean environment and run the CLI smoke test.
5. Upload to TestPyPI first; verify metadata and installability from the public
   page before any production upload.
6. Upload the exact already-tested hashes to PyPI and record the public receipt.

Publishing to a registry is distribution, not revenue. The economic event for
this experiment remains a verified A$49 human-reviewed snapshot order or another
verified value transfer.
