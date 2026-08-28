# Conformance testing

The harness under `tests/conformance/` runs suites against `elfuse` and a
Linux reference in QEMU. It judges each case against checked-in expectations.
Providers adapt suites; backends execute commands; selection, retries,
judgment, reporting, payloads, and the CLI are shared.

## Quick start

```sh
make elfuse
bash tests/fetch-fixtures.sh
make conformance-payloads
make test-conformance
make test-conformance-full BACKEND=all
make test-conformance TEST='<suite>:<group>/*' BACKEND=qemu
```

`BACKEND` accepts `elfuse` (default), `qemu`, `all` (QEMU first), or `host`
for the fake selftest suite. `TEST` accepts canonical ids or globs. See
[usage.md](usage.md#conformance-testing) for setup and maintenance commands.

## Interface

`scripts/conformance` is the entry point; the make targets are aliases.

```
scripts/conformance [--backend elfuse|qemu|all|host] [--results DIR] [--jobs N]
                    [--bootstrap] [--require] [--no-retry] [--dry-run] [-v]
                    <suite> pr | full | test ID [ID...]
scripts/conformance <suite> list [--scope pr|full] [--json]
scripts/conformance <suite> seed RESULTS_DIR [--reason TEXT] [--write]
scripts/conformance <suite> fingerprint | verify | payload | audit | regen
scripts/conformance <suite> update [--check] [--ref REF]
scripts/conformance lint | gate RESULTS_DIR | report DIR | selftest | update
```

Exit codes are:

- `0`: green.
- `1`: a red verdict, backend failure, bad verified payload, or selection
  drift.
- `2`: invalid input or configuration, including malformed data, lint errors,
  stale expectations, and manifest mismatches.
- `3`: `update --check` found pin drift.
- `77`: a prerequisite is absent. `--require` or `CONF_REQUIRE=1` promotes
  this to `2`; make prints an unpromoted `77` as `SKIP`.

`gate DIR` re-derives the exit code from `results.json`. `report DIR` renders
all results below a directory as a Markdown table.

## Test ids and results

Every case has one id:

```
<suite>:<group>
<suite>:<group>/<case>[/<parameter>...]
```

The group is part of the id because different launch units may define the
same case name. Expectation matchers use the same grammar plus shell globs;
`*` spans `/`.

Each attempt records an execution class (`normal`, `timeout`, `signal`, or
`transport`), host wall time, and an exit code or signal when applicable. A
case has a suite status and a judge verdict. Keeping them separate shows both
what happened and whether it was expected.

Statuses are `PASS`, `FAIL`, `SKIP`, `CONF`, `WARN`, `BROK`, `TIMEOUT`,
`CRASH`, `INCONSISTENT`, and harness `ERROR`. Verdicts are `as_expected`,
`unexpected_failure`, `unexpected_pass`, `flaked`, `filtered`, and `error`.
`CONF` remains distinct from pass and fail. Timeouts, crashes, inconsistent
reports, and harness errors satisfy no expectation.

`results.json` is authoritative. Loading it rejects stored gates or counts
that disagree with the cases, and an empty case set is red. `junit.xml` and
`summary.txt` are derived views.

## Selection

A suite selection accounts for every upstream launch group at the pin. An
enabled group has scope `pr` or `full`, and may set a positive `timeout_s` or
an `only` list of case globs. A declined group requires a reason. `pr` groups
run in both scopes; `full` groups run only in the full sweep.

Loading rejects unknown keys, duplicate groups, and groups that are both
enabled and declined. `<suite> audit` compares the selection with upstream.
Decline groups only when the guest cannot provide their prerequisite or they
have no Linux contract; record elfuse failures as expectations.

`test ID...` resolves ids against the full selection and rejects unmatched
names with nearby ids, so a typo cannot produce an empty green run.

## Expectations

Expectation files are JSONC with trailing commas. A suite has a shared base,
one backend leaf that includes it, and `flaky.jsonc`. Files contain ordered
actions; the last matching action wins. The first effective action is
`expect_pass` for `*`, so new upstream cases fail until triaged.

```jsonc
{
  "actions": [
    { "include": "ltp.jsonc" },
    { "type": "expect_failure",
      "reason": "chmod through a /proc fd follows the symlink chain",
      "tracking": "#123",
      "matchers": ["ltp:chmod09"] },
    { "type": "skip",
      "reason": "wedges the VM before the test framework starts",
      "matchers": ["ltp:ptrace06"] },
  ],
}
```

Actions are `expect_pass`, `expect_failure`, `expect_conf`, `skip`, and
`quarantine`. Non-pass actions require a reason and may carry `since` and
`tracking`. Quarantine is legal only in `flaky.jsonc`; it permits retries
without changing the expected status. Loading enforces sorted,
suite-namespaced matchers. A full run rejects stale matchers.

The judge is red for regressions and unexpected passes. A gated run does not
launch skipped cases; `--bootstrap` launches them. A suite-reported `SKIP` is
`filtered`. Only quarantined cases retry, up to three attempts. A later
expected result after a red attempt is `flaked`.

## Seeding

`<suite> seed RESULTS_DIR` proposes expectation actions. Bootstrap results
seed non-passing statuses; gated results seed only red verdicts. Harness
errors are refused because the case did not run.

Complete multi-case groups with one outcome collapse to
`<suite>:<group>/*`. Named test runs never collapse groups. Every proposal
uses `--reason` or a provisional `seeded from` reason that lint rejects until
triage. `--write` appends to the backend leaf, preserves its leading comment
block, and lints the directory.

## Providers and backends

A provider enumerates cases and maps suite outcomes to statuses. It does not
retry, judge, or load expectations. `run_batch` handles cases with one batch
key. The runner isolates unresolved cases through `run_single`, so a batch
crash is attributed to its cause.

A backend executes one argv and returns an invocation. Both backends use an
isolated scratch directory and fixed environment.

The elfuse backend starts one `build/elfuse --timeout 0` process per case,
disables core dumps, sets an 8 MiB stack, and reaps orphaned fork children.
Timeouts kill the process group and perform one bounded wait. A session lock
covers start through stop because guest `/dev/shm` is shared by elfuse
processes for the same user.

The QEMU backend holds one VM under `build/conformance/qemu.lock`. It starts
the VM through `tests/qemu-runner.sh --state-file` and uses a fresh SSH
connection for each command. A sentinel distinguishes the remote exit from
transport loss; a local SSH deadline is a timeout. Artifacts return through
`ssh cat` because the guest has no SFTP server. The VM sees the repository on
read-only 9p, so payloads remain below the repository root.

## Payloads and pins

Payloads are pinned upstream artifacts staged under
`externals/payloads/<suite>/` and never committed. Pins live in
`tests/conformance/<suite>/pins.json` and are schema-checked on load.

A payload fingerprint hashes its pins and builder inputs. It does not use
mtimes, so a recipe edit invalidates the cache even with one-second make
timestamps. `manifest.json` records the fingerprint, staged files, symlinks,
and writable directory prefixes. A lane reports missing or stale payloads as
`77`, then verifies the entire tree before starting a backend.

Payloads survive `make clean` and `make distclean`; `make clean-payloads`
removes them. `<suite> update` fetches, validates, and atomically replaces
pins. `--check` reports without writing, and fetch failures return `2` rather
than claiming drift.

## CI and pin updates

`.github/workflows/conformance.yml` owns the schedule and the stable required
check `Conformance (make test-conformance)`. The workflow reader verifies that
the gate reaches every macOS job. Pull requests have no path filter because a
required workflow that never starts remains pending.

One Mac serves Build and the conformance lanes. A wait job polls Build because
a shared concurrency group would cancel instead of queue. Nightly and
`scope=full` dispatches set `CONF_SCOPE=full`; other runs use `pr`.
`update_check` reports pin drift without writing.

To update a suite:

1. Run `make update-pins`, or use `UPDATE_CHECK=1` to report only.
2. Rebuild with `make conformance-payloads`.
3. Run `<suite> audit` and `<suite> regen` for upstream selection changes.
4. Bootstrap, seed, triage, and rerun each backend under the gate.
5. Fold the pin, selection, and expectation changes into the suite commit.

## Selftests

`make test-conformance-harness` runs the hermetic fake suite, selection and
expectation lint, runner tests, and CLI tests. It needs neither a payload nor
a VM and is part of `make check`.
