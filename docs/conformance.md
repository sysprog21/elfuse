# Conformance Harness

The harness runs registered Linux test suites on elfuse and a QEMU reference.
It records suite status separately from the expectation verdict. The command
reference is in [testing.md](testing.md#conformance-tests).

## Results

`run` writes `results.json` below `<results>/<suite>/<backend>/<stamp>-<pid>/`.
That file is the canonical artifact: `schema_version: 1`, `kind: run`, run
metadata, derived counts and gate, and case records. Loading rejects a gate or
count that disagrees with the cases. An empty run is red.

Each attempt records `normal`, `timeout`, `signal`, or `transport`, elapsed
microseconds, output paths, and an exit code or signal when applicable. Case
statuses are `PASS`, `FAIL`, `SKIP`, `CONF`, `WARN`, `BROK`, `TIMEOUT`,
`CRASH`, `INCONSISTENT`, and `ERROR`. Verdicts are `as_expected`,
`unexpected_failure`, `unexpected_pass`, `flaked`, `filtered`, and `error`.

JSON list output also has `schema_version: 1` and a `kind` field. Requested
machine data uses stdout. Diagnostics use stderr.

Exit codes are:

- `0`: the operation succeeded or the run is green.
- `1`: a completed run or artifact check is red.
- `2`: the command, configuration, or operation is invalid.
- `3`: a non-writing pin or selection check found drift.
- `77`: an optional prerequisite is absent. `--require` and `CONF_REQUIRE=1`
  promote it to `2`.

## IDs and Selection

Case IDs have one of these forms:

```text
<suite>:<group>
<suite>:<group>/<case>[/<parameter>...]
```

Selectors and expectation matchers use shell globs across the complete ID.
A bare group selector also selects its cases. An unmatched selector is an
error.

A selection file assigns each upstream launch group to `pr`, `full`, or a
declined group with a reason. PR groups run in both scopes. Enabled entries
may set `timeout_s` and suite-specific case filters.

## Expectations

Expectation files are JSONC and accept comments and trailing commas. A suite
has a base file, one leaf per backend, and optional `flaky.jsonc`. Files contain
ordered actions; the last matching non-quarantine action wins. The first
effective action is `expect_pass` for `*`.

Actions are `expect_pass`, `expect_failure`, `expect_conf`, `skip`, and
`quarantine`. Every non-pass action needs a reason. `quarantine` is valid only
in `flaky.jsonc`; it runs the case alone for at most three attempts and reports
test mismatches as `flaked`. Harness errors remain red. A full run rejects
matchers that select no case.

A skipped expectation prevents launch. `--bootstrap` launches skipped cases
and records status without applying expectations. `expectations seed` derives
actions from bootstrap statuses or red verdicts. It refuses harness errors.

## Payloads and Pins

Payloads live below `externals/payloads/` and are not committed. A fingerprint
hashes the pin and builder inputs. `manifest.json` records the fingerprint and
each staged file or symlink. Verification detects missing, extra, changed, and
stale content before a run starts.

Pins are schema-checked JSON. `pins update` validates the new pin before
replacing the file.

## Suite Interface

`tests/conformance/providers/__init__.py` is the static suite registry;
`Provider` in `providers/base.py` declares what a suite supplies.

The shared runner owns expectation loading, skip handling, unresolved batch
reruns, quarantine retries, result ordering, and judgment. Providers map
suite output to statuses. Backends return process invocations. A provider
translates host paths through `backend.guest_path()` before putting them in
argv; `Backend.run` forwards argv unchanged, because only the provider knows
which elements are paths. QEMU records non-timeout shell statuses as exit
codes. Providers interpret `128+n` through the suite contract because the
shell cannot distinguish it from a plain exit with the same value.

The elfuse backend starts one `build/elfuse --timeout 0` process for each
command. The QEMU backend starts one VM through `tests/qemu-runner.sh`, shares
the repository read-only at `/mnt/host`, and executes commands over SSH.

## Make and CI

The Make targets take their suite list from the registry through
`scripts/conformance suites`. An empty registry makes suite targets print
`SKIP`; harness selftests still run.

`.github/workflows/conformance.yml` runs QEMU before elfuse and gates on the
required `Conformance (make test-conformance)` job. Pull requests use the PR
scope. Schedules and `scope=full` dispatches use the full scope.
