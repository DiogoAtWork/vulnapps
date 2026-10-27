# Lessons

## NEVER broad-kill the user's applications
**Mistake:** Ran `pkill -f "Google Chrome"` to clean up headless renders. This
killed the user's real Chrome — 100+ open tabs lost, history wiped (no restore
prompt). Unacceptable, irreversible damage.

**Rule:** Never use `pkill`/`killall` with a pattern that can match a user-facing
app. For a headless browser, always launch with a dedicated
`--user-data-dir=<scratch>`, capture the launched PID (`$!`), and kill only that
exact PID — never a process I didn't start.

## Verify the actual failing environment before diagnosing
**Mistake:** Diagnosed a prod "blank page" as a memory bomb, then as browser
cache-skew — both wrong — without first reproducing against the exact prod state
(which DB the container actually loaded + Cloudflare + a fresh browser).

**Rule:** Reproduce the real symptom end-to-end first. For a blank SPA: verify
server-side state (the DB the running container opened) AND capture the real
browser console/network against prod in an isolated profile, before theorizing.

## Verify field constraints from the code, never assume from a UI widget type

**Mistake:** Claimed `scan.scan_date` was "date-only granularity" because the
inline editor uses `<input type="date">`. Wrong — `scan_date` is stored as free
TEXT and rendered verbatim, so it fully supports an optional `HH:MM` time
(e.g. `2026-05-19 07:01`), and `parse_scan_start` already accepts
`YYYY-MM-DD HH:MM`. I even wrote an importer prompt forcing `YYYY-MM-DD`, which
would have discarded start times from reports.

**Rule:** Before stating what a field can/can't hold, check the storage layer
(schema/migration + how it's read/written), not just one input widget. A
`type="date"` editor is a *widget limitation*, not a *data constraint* — say so
precisely and don't generalize it to the whole field.

## Always validate finding/chain counts after a scan import or catalog change

**Mistake:** Trusted that a scan import produced one vulnapps finding per
report source item without ever counting. Scan 330 (TaintedPort, app 305)
turned out to have 70 findings on vulnapps against only 61 distinct source
items in the report (57 `vulnerabilities/` files + 4 `vulnerability_chains/`
files). Root cause: the importer's per-file LLM extraction doesn't reliably
clamp to one finding per source file — when a file bundles multiple root
causes (e.g. a CSRF+XSS+localStorage-theft+account-takeover chain) or
mentions a sub-detail in passing (e.g. a `setup_db.php` aside inside a
directory-listing finding), it sometimes peels those off as separate DB
findings. All 9 excess findings traced back to real report content (no
fabrications) and 6 of the 9 were already correctly matched to the right
vuln, so the practical damage here was low — but it was only luck, and it
went undetected until explicitly counted.

**Rule:** After importing a scan, count distinct source items in the report
(one per file under `vulnerabilities/` + `vulnerability_chains/`, cross-checked
against the report's own `vulnerabilities.csv`/`vulnerability_chains.csv` row
counts or `penetration_test_report.json`'s array lengths) and compare against
the finding count on vulnapps. Same discipline after any catalog edit: the
count of vuln/chain entries in `KnownVulnerabilities.txt` should reconcile
with the count of `TP-*`/`CODE-*`/`PRBL*` vulns and `CHAIN-*` chains
registered for that app on vulnapps. A mismatch doesn't necessarily mean
something's wrong (could be a harmless duplicate match), but it must be
explained, not assumed away. (Also added to CLAUDE.md as a standing rule.)

## The vulnapps API authenticates with `Authorization: Bearer`, not `X-API-Key`

**Mistake:** Verifying migration 040 on prod, queried
`https://vulnapps.net/api/scans` with an `X-API-Key` header. The API ignored
it and served the *anonymous* view: scan 330 came back `{"detail": "Scan not
found"}` and the scan list held 2 rows instead of the real set. That is
exactly what a wiped database looks like, moments after a deploy that ran a
destructive migration (two `DROP COLUMN`s). Almost reported data loss to the
user. Re-running with `Authorization: Bearer` returned all three scans intact
with unchanged metrics.

**Why it's dangerous:** `get_scan` deliberately collapses "not authorized"
into "not found" so private scans can't be enumerated (`app/services/scans.py`,
the vuln-0005/vuln-0008 fix). So a bad credential is indistinguishable from a
missing row by design — silence and 404 are the *intended* response, not a
signal.

**Rule:** Use `Authorization: Bearer $VULNAPPS_API_KEY` (the importer's own
header, `tools/import_scan.py`). Before concluding that prod data is missing,
prove the request was authenticated — query a row that is definitely visible,
or check that the response isn't the public-only subset. Never report data
loss on the strength of a 404 alone.

## Scan discovery separates filtering from aggregation
For scan labels, support combining multiple labels with explicit all/any matching.
When asked for group by, show aggregate metrics first with optional drill-down;
sectioning the original scan list alone does not meet the aggregation use case.

For this scan-filter work, keep verification focused on desktop; responsive redesign is out of scope.

Grouped scan metrics need statistical summaries (mean, standard deviation, range, sample count), not only averages or collapsible lists. Keep grouping optional.

## Verify a permission boundary by exercising it, not by reading the check

**Mistake:** Shipped an admin-only endpoint by copying the surrounding
convention (`_require_admin`) and called it done. Probing the deployed route
with a deliberately *narrow* API key returned 200 where 403 was expected: every
route in the admin router checked `user["role"] == "admin"` and never consulted
`api_key_scope`, so a `read` or `vuln-mapper` key minted by an admin reached all
of them, user management included. The scope was a label, not a limit. Matching
the local convention reproduced the convention's bug.

**Rule:** When adding an endpoint behind an authorization check, test it with a
credential that *should* be refused, not only one that should pass. For this
codebase the axes are independent — `role` (who) and `api_key_scope` (what this
credential may do) — so a role check alone never constrains a key. Ask "which
credential would I expect to bounce here?" and send it.

## A test module that configures the app at import time is ordering-dependent

**Mistake:** Adding `tests/test_admin_scope.py` broke `tests/test_api_endpoints.py`
at collection with "unable to open database file". Nothing was wrong with either
file. `app/config.py` reads DATABASE_PATH once, at import, after `load_dotenv()`;
test_api_endpoints set that env var at module scope before importing the app, and
that only worked because it sorted first alphabetically. A new file starting with
"adm" imported `app.*` earlier, so `.env`'s DATABASE_PATH won instead.

**Rule:** Process-wide setup that must happen before the app is imported belongs
in `tests/conftest.py`, which pytest loads before any test module — never at the
top of a test file, where correctness depends on filename sort order. When a
seemingly unrelated new test file breaks an existing one, suspect import order
before suspecting the new test, and fix the ordering dependency rather than
renaming the file to dodge it.

## "Don't rely on the published credentials" is narrow — don't widen it

**Mistake:** The user said no chain may rely on the TaintedPort test credentials,
which are printed on the login page on purpose. I stretched that into "no chain
may involve a weak password", and argued for two rounds that the COS takeover
chains were not chains because each one cracks a leaked bcrypt hash. Those are
different things: reading a password off the login page is using information
the app hands out deliberately; cracking a hash the chain itself leaked is real
attacker work on stolen data. The user had to spell it out.

**Rule:** When the user states a constraint, apply it at the scope they stated
it, and if a case is near the edge, ask which side it falls on instead of
deciding and arguing. Here the test is *where the attacker got the secret*: off
the published login page = excluded; out of data the chain leaked = fine (its
difficulty informs severity, e.g. a length-only password policy makes a crack
likely). The same wrong reasoning was already written into the catalog (the
"Deliberately not a chain: #28" note) — after correcting a principle, grep for
the places it was already applied.

## Gate a commit on the test command's own exit status

**Mistake:** Ran `pytest ... | tail -1 && git commit && git push`. The pipeline's
exit status is `tail`'s, which always succeeds, so a failing test was committed
and pushed to main (and deployed). Caught only because I read the output line.

**Rule:** Never put a pipe between a verification command and `&&`. Capture the
status first — `pytest > log; rc=$?; tail log; [ $rc -eq 0 ] && git commit ...` —
or use `set -o pipefail`. Applies to any check that gates a commit, push or deploy.

## Check the stored data before predicting an edit's effect

**Mistake:** Told the user adding TP-013/CODE-001/TP-023/CHAIN-011 to a scan-330 finding
would not change the score, "each already credited elsewhere". TP-023 was not — I had
taken that from a dry run of the importer, which was never submitted. The score moved
46 -> 47 after the user had agreed on the basis of "no change".

**Rule:** Before stating the effect of a re-credit ("no score change", "TP 30 -> 29"),
query the stored scan for every vuln involved and check which other findings credit it.
A dry run, an audit file, or an earlier session's numbers are not the stored state. If
the check wasn't done, say the effect is unverified instead of asserting it.

## Rebase dependent scan UI changes before integration
When updating a PR that touches the same scan table as a newly merged change, fetch
main and rebase first. Preserve the approved individual layout while integrating
scoring changes in their requested views.
