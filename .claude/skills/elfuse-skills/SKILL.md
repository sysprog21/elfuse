---
name: elfuse-skills
description: Writing and editing the elfuse skill files themselves - frontmatter, the description as a pointer, what belongs in a references file, and the gate.
---

# Writing an elfuse skill

The skills are documentation that an agent loads instead of rediscovering the
tree, so they are priced differently from `docs/`. A description is loaded on
every turn whether or not it fires; a body is loaded whole the moment it does.
Both halves are written against that price.

## The gate

`make check-skill-refs` runs `scripts/check-skill-refs.py` over every skill
plus any routing document named on the command line. It checks the mechanical
half: the frontmatter name matches the directory, backticked paths resolve to
exactly one file, `make <target>` names a real target, a quoted section name
exists in the docs file nearest it, and a named sibling skill exists.

It cannot check whether a sentence is true. That half rots silently and only a
reader catches it, which is why a claim here names the file that carries the
real contract rather than restating what the contract currently says.

## The description is a pointer

It does two jobs: say what the material is, then list the branches that should
reach it. Each branch appears once. A synonym for a branch already listed is
the same branch written twice, and it costs on every turn.

Cut anything the body already carries. A description that summarizes the
sections is paying always-on rent for a table of contents.

Set `disable-model-invocation: true` when only a human will ever type the
name. The description then costs nothing and becomes a one-line human summary.
Leave it off when the agent should reach the skill on its own, or when a
sibling skill names it.

## The body

The shape the tree already uses, and the reason for it:

- A rule is stated with the consequence of breaking it, because the
  consequences here are guest-visible and delayed. A rule with no consequence
  attached reads as a preference and gets traded away.
- The authority is named at the point of use: the header comment, the lock
  order comment, the docs section. A skill is a working summary, so every one
  of them closes with the tracked sources that win when the two disagree.
- Numbers are recomputed rather than carried. A count quoted from a document
  reads as verified.
- A fact has one owning skill. The others name that skill and stop, because a
  second copy is the one that drifts. `scripts/check-skill-refs.py` catches a
  verbatim run of 20 words or more outside fences and the sources section; a
  shorter copy or a paraphrase only a reader catches.
- Material that only one branch reaches goes in a `references/` file beside the
  `SKILL.md`, reached by a pointer sharp enough to fire on its own. The gate
  checks those files too. Material every branch needs stays inline; splitting
  it buys nothing and risks the pointer being skipped.

`elfuse-conventions` binds this prose the same as any other surface in the
tree: no em dash, third person, and no register the machine writes in.
When the task reduces a skill rather than adding one, read
`.claude/skills/elfuse-conventions/references/prose-reduction.md`; keep
reusable decisions and omit case-specific evidence.

## Authoritative sources

- `scripts/check-skill-refs.py` - the module docstring states exactly what is
  checked and what is deliberately left unchecked.
