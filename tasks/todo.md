# GitHub Actions deployment

- [x] Prune dangling images on EC2 after successful startup, with warning-only failure.
- [x] Validate the script for publication.

Cleanup review: `bash -n` and diff checks passed. Mocked Docker checks confirmed
cleanup follows healthy startup, cleanup failure is nonfatal, and failed startup
skips cleanup. No live pruning was performed.

- [x] Remove the known-hosts secret requirement and accept the first SSH host key per run.
- [x] Update deployment documentation and validate workflow syntax.

Host-key change review: YAML parsing, all four workflow shell steps (`bash -n`),
and `git diff --check` passed. No live deployment was run.

- [x] Inspect upstream deployment scripts and clean-checkout test requirements.
- [x] Configure existing tests and a container startup check for pull requests and main.
- [x] Configure publishing to Docker Hub and deploying the exact image over SSH on main.
- [x] Document repository secrets, host prerequisites, snapshots, and recovery.
- [x] Validate workflow syntax, shell syntax, and self-contained tests.

Deployment follows the existing EC2 layout: `vulnapps`, `vulnapps-data`, and
`127.0.0.1:8001`. Configuration comes from GitHub Secrets. Deployment runs are
serialized; a failed image pull or database snapshot must leave the old service running.

Review: 90 existing self-contained tests passed on Python 3.12; actionlint,
`bash -n`, and `git diff --check` passed. No new tests were added. The local
Docker daemon is stopped, so image build/startup and live deployment remain
unverified. CI gates deployment on the image build/startup check. Application
settings use individual repository secrets; CI assembles the env-file. No live
deployment has been performed.

# Prune scoring redesign to decided subset (A/B/D/E/H/J keep, C/F/G/I delete)

See `/Users/nuno/.claude/plans/playful-marinating-gray.md` for full context/rationale.

## Safety
- [x] Back up vulnapps.db before schema changes

## Migrations
- [x] Delete 026, 027, 029, 031, 033
- [x] Edit 028_chains.sql (drop chain_milestones)
- [x] Edit 032_benchmark_corpus.sql (rename columns directly)
- [x] Apply live-DB reconciliation (drop tables/columns, rename columns, clean _migrations)

## Backend core
- [x] Rewrite app/scoring.py
- [x] Rewrite app/services/scoring.py
- [x] Edit app/routers/api/scans.py
- [x] Edit app/routers/api/apps.py
- [x] Edit app/services/scans.py
- [x] Edit app/services/vulns.py
- [x] Edit app/services/apps.py
- [x] Confirm app/seed.py / app/services/dashboard.py need no changes

## Frontend
- [x] Edit ScanDetail.jsx
- [x] Edit ScanCompare.jsx
- [x] Edit AppDetail.jsx
- [x] Edit AppForm.jsx
- [x] Confirm VulnDetail.jsx / VulnForm.jsx need no changes

## Tests & docs
- [x] Trim tests/test_scoring.py
- [x] Trim tests/test_scoring_revisions.py
- [x] Prune AppBuilder.md
- [x] Minimal fix to tools/import_scan.py (remove milestone POST call)

## Verification
- [x] pytest full suite (38 passed; 1 pre-existing unrelated collection error in test_api_endpoints.py, confirmed present before any of today's changes via git stash)
- [x] Frontend: `npm run build` succeeds (60 modules, no errors)
- [x] Backend: booted the server against the live DB and curled the changed endpoints —
      GET /api/scans/2 (get_scan), GET /api/apps/1/compare (compare_scans), GET
      /api/apps/1/revisions all 200 with the expected trimmed shape (no scorings/
      milestones/binary_weighted/severity_band/corpus_signed_off/config_groups keys
      anywhere); POST /api/apps/1/rescore, /configurations, /benchmark, /scans/2/scorings,
      /scans/2/score all correctly 404 (routes removed)
- [x] compute_metrics sanity: finding_milestones/chain_milestones/scorings were all 0 rows
      before deletion (checked at the start), so old and new weighted_rate are identical —
      the pre-milestone fallback (full credit on match) was already every row's behavior

# Many-to-many finding matches (one finding → several vulns/chains)

## Why

`scan_findings` has a single `matched_vuln_id` and a single `matched_chain_id`
(mutually exclusive), so a finding can be credited for exactly one thing. Two
real gaps follow from that, both hit on live scan data:

1. Scan 330: three separate findings (path traversal, SSRF, directory listing)
   each explicitly read `jwt.php` and quoted the hardcoded HS256 secret, but all
   three were matched to their own access vuln (TP-014 / TP-027 / TP-013), so
   `CODE-001` scored as missed. Fixed by hand (re-pointed 4733), which cost
   TP-013 its second piece of evidence — a trade, not a fix.
2. A scan that reports ONE clean chain narrative naming its 3 members gets
   either the chain OR one member, never the chain plus its members — while a
   scan that redundantly re-reports each member separately gets all four. Same
   discovery, different score, purely because of how the report was written up.

Fixing the data model removes both, and removes the need for the awkward
"only credit the chain's member if no other finding already covers it"
conditional — under many-to-many nothing is being stolen, matches are additive.

## Decisions to confirm before coding

- [x] `tp` stays "count of DISTINCT in-scope vulns with >= 1 match", so one
      finding covering 3 vulns == three findings covering 1 each (symmetric, no
      precision inflation: the denominator is `tp + fp_groups`, and FP stays
      per-finding).
- [x] A finding MAY match a chain and that chain's member vulns at the same
      time — that is the point. The importer's content rule is unchanged: only
      assert the chain when every member is actually demonstrated.
- [x] Severity accuracy stays an OR over findings per vuln (already the rule),
      so a multi-vuln finding reporting one severity is not penalised per member.
- [x] Legacy columns get dropped in migration 040 (SQLite 3.53 here, DROP COLUMN
      supported, no index references them) rather than left as dead mirrors.
- [x] NOT in scope: sibling-chain fairness (CHAIN-004 vs CHAIN-011) and the
      findings-vs-chains list asymmetry — both are separate open questions below.

## Safety

- [x] Snapshot prod DB before 040 runs there. NOT done by hand — the deploy
      pipeline takes its own snapshot before container replacement
      (aws/setup-ec2.sh), which is what will cover the real run. Verified
      locally instead: ran 040 against a copy of the live DB, 44 vuln matches
      backfilled with zero loss, both columns dropped, CHECK rejects a row
      with neither or both ids.
- [x] Land as one change: the join table becomes the single source of truth, so
      any missed reader must fail loudly rather than read a stale mirror.

## Migration (040_finding_matches.sql)

- [x] `finding_matches(finding_id -> scan_findings ON DELETE CASCADE,
      vuln_id -> vulnerabilities ON DELETE CASCADE NULL,
      chain_id -> chains ON DELETE CASCADE NULL,
      CHECK ((vuln_id IS NOT NULL) + (chain_id IS NOT NULL) = 1))` — the CHECK
      migration 039 said it could not add via ALTER is expressible here.
- [x] Partial unique indexes on `(finding_id, vuln_id)` and `(finding_id, chain_id)`;
      plain index on `finding_id`.
- [x] Backfill every existing non-null `matched_vuln_id` / `matched_chain_id`.
- [x] Verify row counts match pre-migration non-null counts, then
      `ALTER TABLE scan_findings DROP COLUMN matched_vuln_id` / `matched_chain_id`.

## Backend core

- [x] One hydration helper that loads matches for a set of finding ids and
      attaches `matched_vuln_ids` / `matched_chain_ids` lists to each finding
      dict, so downstream Python works on lists instead of doing its own SQL.
- [x] `app/scoring.py`: `matched_ids` union over lists (230-232); `pending` =
      zero matches (257-258); severity accuracy iterates (finding, vuln) pairs
      (278); `chain_direct_matches` union over lists (322-324).
- [x] `app/services/scans.py`, the big surface: SQL joins (190, 201-202),
      `pending_count` subquery (212), `vuln_finding_counts`/`_details` (356-362),
      submit auto-match (477-493), `match_finding` write path (610-703),
      `mark_finding_fp` (728), matched-ids query (769-772), `set_finding_ignored`
      (842), promote (986), `rematch_scan` (1046-1051), comparison/detection
      matrix (1151-1263).
- [x] `app/services/dashboard.py` (285-296), `app/services/scanners.py` (104-105),
      `app/services/vulns.py` (485, the delete-guard count).

## API

- [x] `POST /scans/{id}/findings/{fid}/match` takes `{vuln_ids: [], chain_ids: []}`
      as full replacement (idempotent). Keep legacy `{vuln_id: N|null}` /
      `{chain_id: N|null}` as sugar — a stale copy of the importer exists at
      `~/dev/ai-pentest-agent/scripts/import_scan_to_vuln_apps.py`.
- [x] Response returns both list and scalar shapes for the same reason.
- [x] Audit log records set add/remove, not scalar old -> new.

## Frontend

- [x] `ScanDetail.jsx`: the single `<select>` at ~675 becomes multi-select;
      badge logic at 630-631, 666, 718-721 reads lists; `matchedIds`/chain set
      at 73-76 unchanged in spirit.
- [x] `ScanCompare.jsx`: detection matrix already consumes `matched_vuln_ids`
      per scanner — confirm unaffected.

## Importer (tools/import_scan.py)

- [x] LLM JSON schema: `matched_vuln_db_ids: []` / `matched_chain_db_ids: []`,
      still parsing the singular keys for older prompts/responses.
- [x] `SYSTEM_PROMPT_MAP`: state the rule this unblocks — credit every member
      vuln whose mechanism the finding's own evidence explicitly demonstrates,
      and additionally the chain when all members are demonstrated.
- [x] `_enforce_source_kind`: a chain-source file may now assert chain + members;
      a standalone-source file still may not assert a chain.
- [x] Correction loop in `submit_to_vulnapps`: set comparison, not scalar.

## Tests & docs

- [x] `tests/test_scoring.py`, `test_scoring_revisions.py`: one finding crediting
      N vulns scores identically to N findings crediting one each.
- [x] New: chain + members from a single finding; migration backfill correctness;
      CHECK rejects a row with both/neither id.
- [x] `tests/test_api_endpoints.py`: list body, legacy scalar body, clearing.
- [x] `tests/test_import_scan_validation.py`: list-shaped LLM output, legacy
      singular parse, `_enforce_source_kind` under the new rule.
- [x] AppBuilder.md: schema, scoring semantics, API shape, importer rule.

## Verification

- [x] Full suite green (186 passed).
- [x] Post-deploy check against prod (v1.171, run 36070042467). 040 applied:
      the API serves matched_vuln_ids/matched_chain_ids as lists and the
      scalar columns are gone. Backfill lost nothing — 330 tp45/fp5/pending0
      (70 findings), 331 tp37/fp4/pending0 (44), 332 tp30/fp0/pending0 (32),
      all unchanged from the pre-migration triage, and CODE-001 still reads
      MATCHED on all three (the Detection Matrix gap that started this).
      No finding carries >1 match yet, as expected: nothing has re-imported.
- [x] Re-check catalog/vulnapps count reconciliation per the CLAUDE.md rule.

# Open questions to discuss later

Not action items — flagged for a design discussion, not yet resolved or implemented.

## Sibling-chain scoring fairness

This session (TaintedPort, app 305) we registered `CHAIN-011` as a sibling of the
existing `CHAIN-004` — both reach the identical outcome (forge a genuinely-signed
admin JWT using the real hardcoded secret) via two different entry vectors
(`CHAIN-004` via SSRF reading `jwt.php`; `CHAIN-011` via plain directory-listing
reading the same file). This mirrors an existing precedent, `CHAIN-002`/`CHAIN-003`,
also two sibling chains reaching the same "admin claim forgery" outcome via
different JWT-verification bugs. The `chains`/`chain_members` schema
(`migrations/028_chains.sql`) only supports a flat AND-list of members per chain —
there's no way to express "satisfied by path A's members OR path B's members" as
one chain entity, so registering siblings is the only way to credit either path
today.

Concern raised: because each sibling chain is scored as its own fully independent
ground-truth entity (each contributing its own weight to recall's denominator in
`app/scoring.py`), a scan that fully demonstrates ONE path but not the other shows
the un-demonstrated sibling as a missed/false-negative chain, dragging down
recall — even though the scan demonstrated the exact same real-world outcome via
an equally valid route, and even if it found every individual member vulnerability
involved across both paths (just didn't connect them into a second explicit
end-to-end finding). Not clear this is fair.

Angles to discuss (not decided):
- Should sibling chains for the same outcome count as satisfied for recall if ANY
  one is fully demonstrated — i.e. treat siblings as an OR-group for scoring even
  though they're stored as separate rows?
- Should the schema change to support alternative-path groups directly?
- Is there a way to flag "these N chains are siblings for outcome X" so scoring or
  the UI can present/credit them as one conceptual unit?

## Findings vs. chains list-naming asymmetry on the scan detail page — RESOLVED 2026-09-28

Resolved: chain reports appear in Findings (with a `chain` marker, `is_chain`), and the
ground-truth section is renamed **Chain Credit**. Original note kept below.


For individual vulnerabilities, the scan detail page's "Findings" list shows the
scanner's own raw submitted findings (the scanner's claims). But for chains, the
page's "chains" section instead shows the app's registered ground-truth chains
(the catalog's chain entities), NOT the scanner's own submitted chain-claims. So
the same page mixes two different frames: one section is "what did the scanner
report" (findings), the other is "what does the ground truth contain" (chains)
rather than "what chain-findings did the scanner report." Confusing/asymmetric —
flagged for a design discussion (e.g. should there be a distinct "chain findings"
concept surfaced the same way individual findings are, or should the existing
findings list simply also surface which findings were matched via
`matched_chain_id` inline, or something else). Not resolved or implemented.

## Scan filters and grouping (2026-09-25)
- [x] Fetch and merge nunoloureiro/main, preserving local catalog metadata.
- [x] Replace long filter menus with keyboard-accessible searchable dropdowns.
- [x] Support multiple labels with explicit all/any matching and shareable URL parameters.
- [x] Add scanner/app/label aggregate rows with counts, per-scan means, and expandable details.
- [x] Preview with deterministic local mock data and verify desktop filtering, grouping, empty states, keyboard input, and browser history.
- [x] Update AppBuilder specification and record verification.

Review: production frontend build and git diff whitespace checks pass. Eight backend tests
cover label matching and label permissions. Browser checks confirm keyboard selection,
all/any results, chip removal, URL restoration, aggregate means excluding absent metrics,
and expandable scan details. Mock server is read-only with 18 synthetic scans; no live
service was modified. Responsive changes are out of scope per Miguel.

### Grouped statistical summaries
- [x] Show mean, sample standard deviation, min–max, and measured/total sample count per metric.
- [x] Handle absent metrics, single observations, and constant observations explicitly.
- [x] Verify two focused Node statistics tests, production build, and rendered mock values (AI PenTest TP mean 16, std 4; Nuclei TP n=2/3, mean 17, std 2.8).

### Desktop UX and statistical interpretation
- [x] Separate filters, optional results view, and Quality/Counts summaries.
- [x] Show compact mean ± standard deviation with ranges; expose formulas in a disclosure.
- [x] Compute precision/recall/F1 per scan before macro averaging; exclude undefined ratios.
- [x] Verify 157 self-contained backend tests on Python 3.12, three Node statistics tests,
  production build, and desktop browser flows for all/any labels, views, and reset.
- [x] Open upstream PR #5 with only the scan-discovery change.

### Comparable groups and sample sizes
- [x] Add scanner-version and app + scanner-version + exact-label-set grouping.
- [x] Always show measured/total sample counts and clarify small-sample interpretation.
- [x] Verify five Node tests, production build, and browser grouping/singleton display.

### Weighted scoring toggle
- [x] Default grouped quality to canonical weighted detection; retain explicit unweighted metrics.
- [x] Batch current-revision scoring inputs for authorized rows only; preserve legacy list cost.
- [x] Verify score parity across app/corpus revisions, chain credit, and empty denominators.
- [x] Pass 158 backend tests, six Node tests, frontend build, and browser toggle/reload checks.
- [x] Refresh PR screenshots for both scoring modes.

### Review corrections
- [x] Use canonical counts consistently in grouped statistics and scan rows.
- [x] Hide results until the matching query/user request completes; preserve editable filters.
- [x] Preserve selections on no-match Enter; keep reset separate from search matches.
- [x] Add request-state/count-source/autocomplete regression coverage and run npm test in the
  Docker frontend stage used by CI before building assets.
Review validation: 10 Node tests and production build pass. Browser regression verification
was blocked by automatic approval review (initial timeout and rejected retry); the temporary
mock delay was removed. No production data or review comments changed.

### Group extremes and app-scoped filters
- [x] Show metric-aware Best/Worst; retain neutral Min/Max for available points.
- [x] Hide redundant Team filter for app-scoped views and prevent hidden team constraints.
- [x] Verify metric direction/missing-data regression, all frontend tests, and build.

### Run performance chart
- [x] Add optional run scatter view: conservative F0.5 vs cost by default, selectable duration and quality metrics.
- [x] Reuse canonical scoring, preserve filter/history scope, and exclude unavailable axis values explicitly.
- [x] Enforce scan-detail metadata permissions on list responses with regression coverage.
- [x] Exercise deterministic preview fixtures, add calculation tests, verify build, and independently review.
Validation: 14 frontend tests, 159 backend tests, and production build pass. Local browser
verified chart rendering, duration/weighted axes, run selection, and missing-data counts.

Chart review: stabilized scanner colors across axes/filters, preserved distinct small-value
ticks, simplified chart prose, and added the green dashed upper-left directional guide.
Production build and frontend tests pass; live preview confirms the guide renders.

## The `benchmark_verified` flag is inert — it is a label, not a rule

`apps.benchmark_verified` (migration 032) and `vulnerabilities.weight_verified`
exist to tell hand-checked scoring numbers apart from what migration 024
guessed from severity (~55k vulns across 217 apps). Only the *writing* half was
ever built.

Verified 2026-09-25, reading the code rather than the comments:
- `benchmark_verified` is written by `PUT /api/apps/{id}`
  (`app/services/apps.py:413`) and read by the frontend for display. Nothing
  else reads it.
- `get_dashboard` (`app/services/dashboard.py:41`) aggregates over all *visible*
  apps — visibility, scanner, severity, label, tech, app_id, team. No filter on
  the flag, so a comparison can silently mix hand-checked apps with ones whose
  weights are just severity in disguise. That mixing is the exact thing
  migration 032's header says it exists to prevent.
- There is no benchmark export. The only export route,
  `/api/apps/{app_id}/vulns/export` (`app/services/vulns.py:173`), is a plain
  CSV of every vuln, gated on view permission alone.
- The `N tiers unreviewed` badge (`AppDetail.jsx`) is display-only and renders
  solely when the flag is on. It blocks nothing.

Consequence: the badge tooltip claiming an app "is excluded from benchmark
exports" is false today, and so is "The benchmark export refuses until they are
reviewed." Wording left untouched on purpose — the choice below is the user's.

Not decided. Either (a) build the filtering, so dashboard aggregation can
exclude apps whose numbers were never checked, or (b) correct the copy to
describe the flag as the curation marker it actually is. Only worth doing when
a cross-app comparison is actually wanted; for a single app it changes nothing.

For reference, app 305 (TaintedPort) as of 2026-09-25: flag off, 57 vulns /
12 chains, 28 of 57 with `weight_verified = 0`, tiers 38 commodity /
19 business_logic (so tiers were partly hand-assigned — the backfill only ever
writes commodity).

## TP severity breakdown + reachable Ignore (2026-09-25)

### Severity breakdown next to true positives
- [x] `list_scans`: add `tp_critical..tp_info` subqueries mirroring `tp_subquery`
      exactly (same `invalidated_at_revision IS NULL` scope) plus
      `AND lower(v.severity) = ?`, so the breakdown always sums to the
      `tp_count` shown beside it. Params go before `sev_params` — SELECT-clause
      placeholders bind in order of appearance.
- [x] ScansList: render the four buckets inline next to TP, reusing the existing
      `sev-pill` component/CSS rather than a new badge family. Show `info` only
      when non-zero so the row stays narrow but never under-reports the sum.
- [x] ScanCompare: derive the breakdown client-side from `filteredMatrix`, the
      same rows that produce the displayed `tp`, so it tracks the severity
      filter instead of contradicting it. No backend change needed there.
- [x] Catalog severity (`row.vuln.severity`), never the scanner's reported
      severity — decided with the user. The two differ, and that gap is what
      `severity_accuracy` measures; weights use the catalog side too.

### Ignore reachable from any state
- [x] ScanDetail: Ignore is currently offered only on Pending
      (`!hasMatch && !is_false_positive`), so FP -> Ignore means mapping to a
      vuln, unmapping, then ignoring. Backend `set_finding_ignored` already
      clears matches and the FP flag, so the restriction is pure UI.
- [x] Add the missing reverse: nothing calls `setIgnored(id, false)`, so an
      ignored finding can only leave that state sideways via FP.
- [x] Say what will be discarded in the button title and the audit message,
      now that ignoring can throw away a mapping or an FP grouping.

### Verification
- [x] Backend test: breakdown sums to `tp_count`; ignoring a matched finding
      clears its matches; ignoring an FP clears the flag and `fp_group`.
- [x] Full suite + frontend build/tests.

Review (TP split + Ignore): the split needed three producers to agree, not one —
`compute_metrics` (canonical), `list_scans` SQL (so the plain list matches its own
`tp_count`, which the scorer's can differ from), and `ScanCompare` client-side (so it
follows the severity filter). An upstream test caught the first attempt: the list's
`metrics` payload must stay scalar-only because the grouped view averages every field in
it, so `tp_by_severity` is stripped there and flattened onto `tp_*` columns instead.
Ignore needed no backend change — `set_finding_ignored` already cleared matches and the FP
flag — only the button condition, plus the un-ignore button that never existed and an audit
message that now names what was discarded. 197 backend tests, 14 frontend, build clean.

## Change Log page (2026-09-25)

- [x] Every commit on main is a release, since minor = commit count. A commit's minor is its
      ancestor count, NOT its row in `git log` — they diverge at the first merge commit, and
      numbering by position would misnumber everything below it. One `rev-list --parents`
      call, reachability via integer bitmasks.
- [x] Merge commits kept (they increment the version) but flagged and collapsed behind a
      toggle, rather than filtered out and breaking the mapping.
- [x] Baked at build time like COMMIT_COUNT — the image has no `.git`. Optional `COPY
      CHANGELOG.jso[n] ./` so a build without the generator still succeeds; `get_changelog()`
      falls back to git, then to `[]`.
- [x] `build_entries()` falls back `main` -> `HEAD`: a CI checkout of a PR is detached with
      no local `main`, and this page is too cosmetic to fail a build over.
- [x] Admin-only: commit messages describe internals the app's own pages do not.
- [x] Verified against real history — 186 entries, newest `v1.186`, matching what
      `/api/version` reports; 401 unauthenticated, correct payload as admin.

## Chains: severity, content-based chain findings, Promote -> Chain (2026-09-28)

Triggered by scan 330: COS reported 4 chains; the 3 not in the catalog could only
be marked FP (3 of its 5 FP groups). Decisions with the user:
- A chain is steps that each enable the next, reaching an outcome none reaches
  alone. "Three independent ways to $0" (COS financial fraud) is NOT a chain:
  credit all the vulns it shows (done live: TP-054 + TP-019 + TP-021).
- Cracking a LEAKED hash is attacker work, not "using the published test login";
  a weak password policy (strlen >= 8 only) affects likelihood/severity, it is not
  a disqualifier. So both COS takeovers are chains -> CHAIN-013 / CHAIN-014, High.
- Chain-ness comes from what the finding says, never from which folder it was in.
- Chains get their own severity; weight derives from it, like vulns.

- [x] Migration 041: `chains.severity` (backfill from impact_weight) and
      `scan_findings.is_chain` (backfill 1 where a finding already matches a chain).
- [x] Chain create/update take severity, derive impact_weight; weight-only callers
      still work (severity derived back). Scoring's Chained-tier split uses it.
- [x] Importer: model returns `is_chain` from content; chain matches allowed only on
      is_chain findings, from any file. Folder name drops to a soft prompt hint; the
      folder-based hard backstop (`_enforce_source_kind`) goes.
- [x] Submit stores `is_chain`; Findings list shows a "chain" marker.
- [x] Promote -> Chain: create chain (title, severity, member vulns) from a finding,
      open a revision, map the finding to it.
- [x] Chain editor on the app page: severity/title/members, plus Add chain.
- [x] Rename scan page "Chains" -> "Chain Credit" (it is the ground-truth scorecard).
- [x] Catalog: CHAIN-013/014 in KnownVulnerabilities.txt; register + map on scan 330;
      reconcile counts per CLAUDE.md.
- [x] Tests, AppBuilder, deploy, verify on prod.

Review: live on v1.192. Migration 041 backfilled all 12 chains to critical. On scan 330 the
three FP'd COS chains were re-triaged: financial fraud credits TP-054 + TP-019 + TP-021 (not
a chain); the two takeovers credit every vuln they show and are registered as CHAIN-013
(TP-017 -> TP-024 -> TP-020) and CHAIN-014 (TP-053 -> TP-024 -> TP-028), both High. Scan 330:
TP 45 -> 46 (TP-028), FP groups 5 -> 2, precision 90.0% -> 95.8%, chained 4 -> 6 found.
Counts reconcile: 14 chains / 57 vulns in both catalog and vulnapps; finding counts
unchanged (70 / 44 / 32). Scans 331 and 332 now score against 14 chains rather than 12 —
the revision mechanism doing its job, not a regression.

## Importer: extract first, map second; provenance on every scan (2026-09-28)

Triggered by 10 TaintedPort scans that arrived pre-mapped by COS's own publishing
step (one finding per catalog entry, bodies copied from the wrong source finding).
Those 10 are ON HOLD pending the user's talk with whoever imported them -- no changes.

Found while scoping:
- Extraction and mapping are ONE LLM call per file today, with the catalog in view,
  so the model can reshape findings to fit the answer key (the COS failure shape).
- The importer sends matcher identity + run details; the server stores none of it.
  The columns exist only on prod (leftovers of the scoring prune), not in migrations.
- The migration runner marks a whole file applied on the first "duplicate column",
  silently skipping every later statement in that file.

- [x] Runner: on "duplicate column", replay the file statement by statement
      (split with sqlite3.complete_statement), skipping only existing columns.
- [x] Migration 042: provenance (imported_by, importer_version, importer_commit,
      extractor_version, extractor_prompt_sha256) + the prod-only run-detail columns
      (matcher_version, matcher_prompt_sha256, model, model_version, reasoning_effort,
      harness_version, token_budget, seed, run_group, trial_index).
- [x] Submit route + service store them; web-form submissions say "vulnapps web form".
- [x] Scan page shows provenance ("imported by: unknown" when absent).
- [x] Importer phase 1 EXTRACT per file, no catalog in the prompt.
- [x] Importer phase 2 MAP: catalog + numbered extracted findings -> mapping fields
      only, batched. Text fields always come from phase 1; mapper output must line
      up 1:1 with the extracted list or the import stops.
- [x] Defaults: extract claude-sonnet-5, map claude-opus-5; --extract-model /
      --map-model; per-phase token counts printed.
- [x] Importer reports its version: vulnapps v<major>.<commits> of its checkout,
      commit, dirty flag.
- [ ] Tests, AppBuilder, deploy, verify a real dry-run import.

## PENDING — when the new TaintedPort version (secrets moved to env) is live

Waiting on the user: they will run the TaintedPort agent with the "move three hardcoded
secrets" prompt (JWT signing secret, gift-card AES key, tracking-link secret -> runtime env
vars via php-fpm env[], fail closed, new values), then clone the app in vulnapps as a NEW
version. Nothing below happens before that; the current TaintedPort app (id 305) keeps its
catalog as-is.

Before starting, confirm with the user:
- [ ] Which vulnapps app id is the new version, and its version string.
- [ ] The agent's verification report passed, in particular:
  - the SSRF can still read `partner_public.pem`;
  - HS256-with-the-PEM + `iss=partner` is still accepted as admin, via both /files/ and the
    SSRF (CHAIN-016 depends on it);
  - length extension (#53) and CBC bit-flip (#54) still work without the key/secret.

Catalog changes for the NEW version only (vulnapps new app + KnownVulnerabilities.txt, together):
- [ ] Remove CODE-001 (#33 Hardcoded JWT Signing Secret) — no longer present.
- [ ] Remove CHAIN-004 (#27 SSRF + #33) and CHAIN-011 (#13 Directory Listing + #33): both
      forged admin tokens with the stolen JWT secret, which no longer exists.
- [ ] Add CHAIN-016: SSRF -> read partner_public.pem -> RS256->HS256 algorithm confusion ->
      admin token forgery. Members #27 + #45, Critical (27). The SSRF sibling of CHAIN-006
      (#13 + #45), the way CHAIN-004 was the sibling of CHAIN-011.
- [ ] Text-only updates (drop #33 as an enabler; keep #11/#12/#45):
  - #23 (admin trusts the is_admin claim);
  - #58 (confused-identity password/email change — its enablers list #27+#33 / #13+#33);
  - #13 (its Critical rating cites the JWT secret; the database dump alone still justifies Critical);
  - #27 (its description walks through reading jwt.php);
  - #53/#54 — must not imply the secret/key is recoverable from source, and #53 must keep
    stating the 14-byte secret length.
- [ ] Do NOT add catalog entries for the hardcoded gift-card key / tracking secret in the new
      version; they no longer exist there.
- [ ] Reconcile counts per CLAUDE.md: vulns and chains in KnownVulnerabilities.txt ==
      the new app in vulnapps. Expected 56 vulns (57 - CODE-001) and 14 chains
      (15 - 2 + 1), unless the clone differs.
- [ ] Verify the new app's chain list in the UI shows CHAIN-016 with the right members and
      severity.

Still open on the CURRENT app (305), not blocked by the above:
- [ ] Hardcoded gift-card key / tracking secret: they were real in the current version
      but have no catalog entry, so two findings on Snyk COS a2096f0f (27 Sep) are credited
      TP-053 / TP-054 / CODE-001 for flaws they never showed. Decide: add two entries
      (CWE-798, High, commodity) to app 305's catalog, or leave app 305 alone and just
      re-credit those findings.
- [x] The 16 review items on the normal scans (330, 331, 332, 346, 347, 348, 349), one by
      one (4 wrong, 10 doubtful, 2 missed credits) — done 2026-09-29. Rules settled on the
      way: a claimed-but-not-shown step earns no credit; a white-box scan may credit a
      precisely identified flaw without running it; a finding the report withdrew for low
      impact is still credited (now in the mapping prompt); a real finding outside the
      catalog is Ignored, never FP. Net: scan 346 TP 32->29 (gift-card finding ignored;
      TP-053/TP-054/TP-022 no longer credited), 348 TP 21->20 (TP-011), 330 TP 46->47
      (TP-023 on the directory-listing finding). The ten held scans (333-343, Crucible
      350) stay untouched pending the user's conversation with whoever imported them —
      except one change made before the hold: the v940 "Hardcoded JWT signing secret"
      finding re-credited CODE-001 -> TP-012.

## Reviewed weighted F₀.₅ (2026-10-17)
- [x] Add reviewer FP penalties and canonical weighted precision/F₀.₅.
- [x] Gate headlines, group statistics, chart points and comparison winners on completed review.
- [x] Keep the scan list compact and conservative estimates inside detail disclosures.
- [x] Preserve current-main combined app coverage and chain promotion behavior.
- [x] Verify migration/state transitions, backend/frontend checks and screenshot evidence.

Validation: 225 self-contained backend tests pass on Python 3.12 (CI's production-data
API exclusion), plus 24 affected state-transition/migration tests after the final chain
cleanup assertion. All 18 frontend tests, production build and diff checks pass.
Independent backend/frontend reviews completed; fixed rematch retaining an old reviewer
penalty and covered chain promotion on current main. Real browser checks against a
disposable migrated DB verify review/save/reset/reload, group sample eligibility, chart
exclusions, Quality/Counts coverage footer, weighted winner and severity suppression.
Four screenshots under docs/screenshots/weighted-f05 use synthetic data only.
