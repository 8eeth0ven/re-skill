# Library Maintenance

This is the active maintenance guide for the English `re` skill. Start at
[SKILL.md](SKILL.md) for task routing. Each branch INDEX owns its article list;
do not duplicate those lists or manually maintained line counts here.

## Scope and Compatibility

- Keep the installed skill name `re` and existing paths stable. Existing host tasks,
  relative links, scripts, and local state may refer to them.
- Preserve method coverage, examples, case distinctions, acceptance gates, numerical
  limits, and device/research boundaries when editing prose.
- Keep active instructions and explanatory comments in English. Exact API names,
  match strings, payload bytes, source titles, historical outputs, and compatibility
  paths may retain their original language.
- Treat `data/`, `tools-env/`, environment snapshots as preserved resources, not prose to reorganize. Preserve the
  discovery log's dates, measured values, source locations, dispositions, and statuses during
  editorial translation; do not turn old observations into new tests.
- The optional local historical quality audit, `quality-audit.md`, records earlier
  findings under older Chinese directory names. It is excluded from Git and may
  be absent in a fresh clone. Its results describe that audit, not the current
  machine. Do not recreate obsolete directories from those historical labels.

## Safe Update Sequence

1. Back up the existing directory, including hidden files, local state, installed
   tools, raw data, and uncommitted changes. Verify the archive before editing.
2. Record the pre-existing working-tree changes so they are preserved in the update.
   Assign independent writers disjoint files when using parallel agents.
3. Update the authoritative route and the corresponding article together. Keep
   external rule section references stable. For new tools, follow the radar's
   catalog-and-smoke-test process; an entry alone does not establish usability.
4. Run structural checks and review the changed execution examples. Validate paths
   containing spaces and quotes whenever shell initialization changes.
5. Record what was tested and what remains unverified. Recheck dated local tool
   observations before presenting them as current capability.

## Local Validation

Run from the skill root, or pass its path explicitly:

```bash
python3 scripts/validate_library.py
python3 scripts/validate_library.py --json
```

The standard-library validator checks local Markdown links and headings, branch
index coverage, two-column index tables, a concise English domain description and essential workflow routes,
Python syntax, and Bash syntax. It skips raw data and installed environments,
and never imports the analysis scripts or invokes a device, scanner, installer,
or external service. The historical audit and discovery log are exempt from
active-link checks.

Validate YAML with the skill loader or the skill-creator validator available in
the host environment. Structural validation does not prove that live tools,
vulnerability examples, or device-dependent procedures work.

For patch-byte changes, run the existing offline self-check using the installed
RE environment:

```bash
tools-env/.venv/bin/python techniques/16-quick-ref/verify_patch.py
```

Keep task-generated reports outside the knowledge body. When an offline mock
validates orchestration or path handling, label it as a mock rather than a real
APK, firmware, or hardware result.

## Knowledge Intake, Renames, and Evidence Review

Follow [knowledge engineering](docs/knowledge-engineering.md) for new articles,
same-family variant dossiers, source attribution, decay warnings, and the
project-to-library promotion gate. Preserve existing articles and branch meanings;
legacy metadata remains pending until reviewed rather than being fabricated.

Run both gates after an article move, rename, new INDEX row, or intake:

```text
python scripts/validate_library.py --json
python scripts/validate_knowledge.py path/to/changed-article.md --strict --json
```

Use the installed host's Python name (`python3`, `python`, or `py -3`), or prefix
with `uv run --no-sync python`. Both gates must exit zero for the intended change.
The structural gate checks the whole library's routes, including legacy indexes;
the metadata gate checks declared claims, ids, evidence and the selected draft.
`legacy-pending` is not a claim that all old evidence has been reviewed. Keep stable
article ids across renames and update inbound links, owning INDEX rows, and local
evidence paths in the same change. Never delete an old article to make a check pass.

Use `python scripts/validate_knowledge.py --review-due` for a manual review queue.
Record a rerun only when one actually happened; elapsed age or an inaccessible old
attachment does not rewrite the historical observation. No hosted service or
automatic target testing is required for these gates.

## Recurring Regression Checks

- Standard YAML delimiters and an indented/folded description; legacy task phrases retained in the optional usage-scenario vocabulary; no escaped `\---` delimiters.
- Branch links are relative to their containing file. From `platforms/INDEX.md`
  or `techniques/INDEX.md`, the skill entry is `../SKILL.md`.
- Avoid duplicated empty table columns, isolated rows, and references to renamed
  articles hidden inside prose or code comments.
- Keep APK-stage producer/consumer dependencies explicit. Distinguish a target
  turnaround time from the sum of stage ceilings; preserve timeout fallback paths.
- Name temporary device artifacts with `re_`, track their ownership, and restore
  only changes made by the current task. Keep labeled research evidence.
- Daily 09:00 radar execution requires a host scheduler. Copying the library does
  not migrate that schedule or establish a live MCP connection.
- Known-CVE version matches and firmware rule hits remain candidates until the
  workflow's evidence and impact gates have been passed.
