# Contributing

Hardware reports and focused fixes are welcome. The current release has one RZ616 hardware report; include evidence when adding a device, OS version or feature to the tested range.

## Report a problem

Include:

- Driver/app release, macOS version and build, and CPU architecture.
- Wi-Fi PCI ID, card model and board model.
- Network band, security mode, relevant boot arguments, and steps to reproduce.
- Whether scanning, joining, DHCP and traffic succeed; for speed reports, include the test method and comparison conditions.
- Reviewed output from `bash scripts/collect-logs.sh`, especially connection events, BA state and receive diagnostics.

Remove passwords, private network identifiers and unrelated personal information before posting. Do not upload the app's saved `networks.json`, a full EFI, or an unreviewed raw log archive.

## Change and verify

Preserve original author and third-party notices. For a hardware layout change, cite the source file and pinned commit, explain field offsets and add a fixture that exercises a real protocol boundary. Avoid combining a new chip feature with unrelated refactoring.

Run the relevant host checks and build on macOS:

```sh
bash tests/run_all.sh
bash scripts/build.sh
```

Test reconnects and traffic on hardware for connection/data-path changes. Record the exact card, OS build, firmware and network configuration. Mark untested behavior explicitly; successful host tests alone are not a compatibility report.

A pull request should state the failure it fixes, the resulting behavior, the evidence behind firmware/register layouts, and what was tested. Keep generated build output, credentials, private logs and complete EFI configurations out of source changes.

See [NOTICE.md](NOTICE.md) for source pins and licenses, and [docs/PORTING.md](docs/PORTING.md) for the port's structure and current boundaries.
