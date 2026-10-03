# Driving the frama-c MCP server

Loaded from `elfuse-verify` when the `frama-c` MCP server is connected and a
proof needs to be worked goal by goal. Everything here is about reading a
result from that server correctly. None of it changes what makes a proof
land: that is `make verify` plus `make verify-mutants`, from the Makefile.

## Using the server

The loop itself is in the `elfuse-verify` body. One step it leaves out:
retrying the unproved goals distinguishes "not proved" from "not proved yet",
so check that before rewriting a contract that only needed a longer timeout.

Three of the server's behaviors are worth knowing before you read a result
from it:

- `check` gates its verdict on evidence the run actually read, not on an
  empty `incomplete[]`. It carries codes for the shapes that pass silently
  otherwise: a statement contract or generalized
  invariant dropped as "not yet supported (skipped)", a union write proved
  "might be unsound", an undefined logic function "interpreted as reads
  nothing", a postcondition that got no goal because the function has a
  caller, and a dead branch only WP's smoke tests see. A verdict that arrives
  with one of those codes is not the proof you asked for.
- Per-goal WP cache provenance comes from `ast-utils`, not from the summary
  line. The "(Cached)" word is printed for every cacheable goal in an updating
  cache mode, hit or miss, so it does not say a verdict was replayed. When it
  matters whether a number is fresh, read the provenance or run with
  `cache: "None"` as the calibration below does.
- `analyze_concurrency` screens loaded sources for race and lock-order
  candidates. That is directly useful here, because the ordering block in
  `src/syscall/internal.h` is prose and nothing proves the tree obeys it. Read
  the level honestly: the scan is syntactic, a candidate is evidence and not a
  race, and an absent candidate is not a proof of safety, because the
  strongest thing a lexical lockset supports is that two accesses name one
  lock. It is also bounded. `max_events` defaults to 10,000 and clamps at
  100,000, `max_candidates` defaults to 2,000 and clamps at 20,000, and the
  scan has its own time budget that can stop it mid-file; `scan_complete`
  reports that last one. An enumeration that hit any of those is partial, and
  reading it as complete is the one way this tool produces a wrong answer.

Read the `self_check` result rather than the absence of an error: a degraded
server still answers, and the answer looks like a normal response.
`frama_c.status: ok` says only that the binary runs. The fields that decide
whether the interactive path works at all are `socket_spawn`, and
`wp.available` / `eva.available` under `capabilities`.

Do not read a failed `socket_spawn` as a missing `ast_utils` plugin without
checking. Its probes are time-bounded, so on a loaded host they time out and
report `error` or `unknown` for a plugin that is installed and works. Seen
here at load 75 on 8 cores: `socket_spawn` reported "the probe process exited
or never created one" and `ast_utils` came back `unknown`, while
`frama-c -load-module ast_utils_plugin -print-libc` succeeded immediately and
the plugin sat in Frama-C's plugin directory the whole time. `opam_switch_hint`
timing out in the same report is the tell. Confirm with that one-line load
before concluding anything, and re-run `self_check` on a quiet machine; only
if the plugin is genuinely absent is the install
`cd ast-utils && dune install` in the frama-c-mcp checkout.

`reload_project` does not take a raw preprocessor string. It takes structured
flags, and an unknown key is accepted and dropped rather than refused, so a
call carrying `cpp_extra_args` parses with none of them and then fails on a
header that is on the real include path. Mirror `FRAMAC_CPP_ARGS` field by
field instead; for this tree that is

```
include_paths:  ["frama-c-stubs", "src", "build"]
force_includes: ["prelude.h", "macos-libc.h"]
machdep:        "gcc_x86_64"
```

Those three lines are `FRAMAC_INCLUDE_DIRS`, `FRAMAC_FORCE_INCLUDES` and
`FRAMAC_DATA_MODEL` from `mk/verify.mk`, and they are reproduced here only to
show the shape; take the live values from `make print-verify-profiles` below
rather than from this block, which nothing gates.

`nostdinc` and `isystem_paths` are fields, and they are not optional detail on
this platform: without them the real macOS headers win over the modeled libc,
and a file whose parse depends on that shadowing loads as a different program.
Two measurements from when they could not be expressed, both worth knowing
because they are what a load under the wrong headers looks like.
`src/syscall/sys.c` parsed under the `mk/verify.mk` flags and failed without
them, on a `_Static_assert` over `struct rusage` that only holds against the
modeled header, which put it and six others in `parse_surface`'s blocked set.
The tool reports fewer files parsing than actually do, so take the number from
the probe rather than from it.

The flags are not the only way the two can differ, and the other way reads as
a hard proof failure. On `src/syscall/net.c` the server reported `recv_at`'s
`pointer_alignment` obligation unproved, surviving `retry_unproved` at double
the budget, which is its own strongest test for a goal that is unprovable
rather than slow. Under `mk/verify.mk` the same three functions discharge 6 of
6 and that obligation is never generated. The cause is RTE, not the header:
the kernel's generator and WP's own are different analyses, the kernel emits
`pointer_alignment` assertions and WP's does not, and the server was starting
Frama-C with `-rte` where the recipe passes `-wp-rte`. Fixed upstream, but the
shape is worth keeping: a `pointer_alignment` goal the build never generates
is the signature of the wrong RTE generator, not of a hard proof.

So the rule is not "distrust the server", it is "pass the flags". A profile
from `make print-verify-profiles` carries both, and `nostdinc` must be stated
for a profile to be proof evidence at all. When you load by hand instead, pass
`nostdinc` and `isystem_paths` yourself, or you are measuring another program.

What any of that proves, and what it does not:

- The MCP's default WP model is not what every target uses. A goal that
  discharges under defaults says nothing about whether `make verify-<name>`
  passes. Always mirror the target's own `VERIFY_<NAME>_MODEL`.
- A prover budget is wall-clock, so on a saturated machine a goal can reach it
  whatever its difficulty. Read `wp_timeout_triage` before believing a timeout
  verdict: it carries `host_load_per_cpu` in its evidence and drops to
  `confidence: low` above one runnable thread per CPU, and again when the
  reading is `"unavailable"`, since an unread host is not a quiet one. Only a
  measured quiet host earns `confidence: high`.
- Re-running is not re-measuring, and this is the trap. WP's cache defaults to
  `update`, so it stores timeout verdicts too and replays them. Measured here:
  the same six functions, run under load (one-minute average 40 to 61 on 8
  cores) and again at load 3.3, produced the identical `proof_receipt` sha256,
  with every timeout goal carrying `from_cache: true`. The second run proved
  nothing and looked exactly like the first.

  The response says so now. `measurement` reports `replayed`, `unproved` and
  `unproved_replayed`, and `every_unproved_goal_was_replayed` is the one to
  read: when it is true the run attempted none of its own failures, and
  `wp_timeout_triage` drops to `confidence: low` saying so. Pass
  `cache: "None"` to prove everything in the run. It is the same distinction
  `proof_coverage` draws between `fresh_valid` and `cached_valid`, and it
  costs a re-prove, so spend it when a verdict is about to become a decision.
- `retry_unproved` settles slow against unprovable, and nothing else. It
  re-runs the timed-out goals at double the budget and reports which flip, so
  an empty `flipped` means more time is not the fix. It does not check that the
  program under it is the one you meant: on `src/syscall/net.c` a goal survived
  it and was still an artifact of the wrong header environment. Rule out the
  load, the cache, and the flags before reading it as a property of the code.
- The connected server is whatever binary is installed, which can lag the
  source tree. A behavior described here that the running server does not show
  means the installed binary predates it, not that the description is wrong;
  `self_check` reports the server version.

It also answers the coverage question rather than just the green/red one,
which is how you find a target that passes because it is proving less than you
thought. `proof_coverage` is the tool for that:

```
# denominator: every defined function of the loaded project
proof_coverage {}

# denominator: the function set that target declares
proof_coverage {verify_profile: "<target>", detail: "full"}
```

It measures stored conclusions, not the last run, so it reports nothing until
`store_function_conclusion` has filed a receipt from a `run_wp` on the real
project. With nothing loaded and nothing stored it answers `0 of 0`,
`incomplete`, and an empty function list rather than an error, which is easy to
skim as a clean report. Check the denominator before reading the percent.

Sandbox receipts are refused on purpose: a sandbox proves an extracted copy
whose uncontracted callees are stubs. Merge the annotations back, re-run WP on
the main project, and store that receipt.

Read a row's `reason` as the instruction, and treat an empty one as the only
thing that counts. Three of them come up here more than the others:

- `stale_source` after a single edit. A receipt hashes the whole loaded file
  set, not the one file its function lives in, so touching any source reds the
  entire report. Expect it; it is not a signal about the function you edited.
- `unverified_callee`, propagated through the call chain. Fix what
  `blocking_callees` names first.
- `proved_under_a_goal_filter`, meaning the run passed `prop` and left the
  unselected obligations unattempted. That is the "proving less than you
  thought" case caught by name.

One limit on the number, on top of the two rules above. It reads WP only, so
`complete` is a statement about proof obligations generated by the ACSL, RTE
and WP configuration that produced those receipts. A requirement no contract
states is not an uncovered row, it is absent from the denominator entirely, so
coverage cannot tell you the property table is complete.

## Calibrate the server before trusting a number from it

Run one already-green target through it and compare the obligation count with
what the matching `make verify-<name>` reports. Use `iov`: three functions, one
header, and a known answer of 40 of 40.

```
make verify-<name>                  # the answer, for name=iov
reload_project {verify_profiles: <make print-verify-profiles>,
                verify_profile: "iov"}
run_wp         {verify_profile: "iov", cache: "None"}
```

The counts must match exactly. Every wrong conclusion this file records came
from skipping that check, and each was invisible without it:

- The server refused all but one target outright with
  `invalid WP model 'typed'`, comparing the name case-sensitively where
  Frama-C does not care. A profile emitted faithfully from the recipe was
  rejected by the tool whose whole purpose is to run that recipe's proof.
- With that fixed it answered 42 obligations to the recipe's 40, both extras
  `pointer_alignment` on one function, because it started Frama-C with kernel
  `-rte` where the recipe passes `-wp-rte`. Those are different analyses and
  the larger one is not the target's.
- `caveat`, which one target is proved under, is accepted by Frama-C and named
  nowhere in `-wp-h`, so a list built from that help text called it invalid.

None of those announced themselves. Each produced a confident, well-formatted
answer about a program the build system does not prove, and `retry_unproved`
confirmed one of them. Two numbers side by side is the cheapest thing that
catches the whole class, and it costs one target.

## Making the MCP prove what the Makefile proves

`make print-verify-profiles` emits the `verify_profiles` JSON for all of
`mk/verify.mk`, one entry per target, carrying the sources, functions, model,
machdep, include paths, defines, provers, timeout and a `reproduce` command.
It comes from the same variables the `verify-<name>` recipe consumes, so a
profile and a Makefile run cannot disagree about what a target proves. Emit
it, never hand-write it: a hand-written function set is the drift the whole
mechanism exists to prevent.

That property is only as good as the sharing. The two lists the profile and the
recipe both need, include directories and force-includes, live in
`FRAMAC_INCLUDE_DIRS` and `FRAMAC_FORCE_INCLUDES`; `FRAMAC_CPP_ARGS` turns them
into `-I` and `-include` flags with `patsubst`, and the emitter passes them
through as the bare directories and headers the schema wants. Spelling either
list twice is the bug this arrangement exists to prevent, and it is not
hypothetical: they were duplicated at first, under a comment claiming they
could not drift. If you add an include path, add it there and check both sides
move:

```
make print-verify-profiles FRAMAC_INCLUDE_DIRS="... extra" | grep extra
make -n verify-align       FRAMAC_INCLUDE_DIRS="... extra" | grep -- -Iextra
```

The emitter refuses rather than emitting a profile that cannot be used: no
sources, no functions, an empty or blank model, no provers, a non-positive
timeout, a `CPP_DEFS` token that is not a `-D`, or no targets at all. Each
names the make variable to look at. That matters because the server's own
refusal comes much later and names none of them: a profile missing one required
field is accepted for loading and then rejected by every `run_wp` and every
`store_function_conclusion` that names it, which reads as a broken target
rather than as an empty variable on the command line that produced it.

That closes the loop between the two tools:

```
make print-verify-profiles                      # from the build system
reload_project {verify_profiles: <that JSON>, verify_profile: "<target>"}
run_wp         {verify_profile: "<target>"}
store_function_conclusion {function, status: "verified",
                           proof_receipt_sha256, verify_profile: "<target>"}
proof_coverage {verify_profile: "<target>", detail: "full"}
```

The JSON goes in as the object or as its text: the `verify_profiles` parameter
is untyped, so a client that stringifies it is not making a mistake, and the
server decodes either. Naming the profile is what makes each step mean the
target rather than the server's defaults. A run that deviated from the profile
is refused as that target's evidence rather than quietly accepted, and a
conclusion stored without one records what was proved but not what it settles.

Three things to know when feeding it in. The profile carries `nostdinc` and
`isystem_paths` alongside the include paths, all four from the same
`mk/verify.mk` variables the recipe uses, so the load the server makes is the
one the recipe makes. The model strings are the
Makefile's own spelling (`typed`, `caveat`, `Bytes`), which is the point:
normalizing them here would make the profile prove something the recipe does
not. And every profile carries `rte: true`, because every `verify-<name>`
recipe passes `-wp-rte`: that flag decides which obligations exist at all, so a
load without it gives a strictly smaller set. The server treats it as part of
the load identity, so a non-RTE load is refused as that target's evidence
rather than quietly accepted, and a profile that omits it can load sources but
cannot be proof evidence.

`rte: true` means WP's generator specifically, not Frama-C's kernel one. The
difference and what it costs are under "Using the server" above; the field
cannot express it, so the calibration above is the only way to see it.
