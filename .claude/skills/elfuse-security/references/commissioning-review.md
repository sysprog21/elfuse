# Commissioning a security review

The habits in the `elfuse-security` body are the reviewer's. These are the
requester's, and they decide whether the reviewer's are reachable at all.

- Name a target and invite the null result. A request to make something
  secure presumes a defect, and a reviewer with a turn to justify will
  produce one. Asking for a verdict on a named diff, clean included, is what
  makes a clean answer worth anything.
- Require a file and a line for every claim, checked against the source
  rather than recalled, and read through something that returns the file
  verbatim. A shell here may be wrapped by a filter that elides content, and
  a claim built on elided output reads exactly like one that is true.
- State the threat model, or ask for it before the review rather than after.
  Without it a reviewer reports what the guest does to itself, and the
  out-of-scope list in the body gets rediscovered a category at a time.
- Ask what each gate deliberately does not check, not only whether it
  passed. That question is what turns the gate list in the body into review
  scope, and every docstring there states its own limit.
- Use two independent reviewers, both held to the citation rule, then hand
  each surviving candidate to a reviewer that did not raise it, is asked to
  refute it, and is not shown either verdict. Without the citation rule a
  second opinion is a second guess, and a checker that sees the conclusion
  first confirms it.

The shape:

```
Review <target> for security.
Threat model: <state it, or ask for it first>.
Verify every claim against the source and cite file:line.
Say which paths were walked and which were not.
Each finding: root cause, every sink, the concrete fix.
Report clean if clean.
```
