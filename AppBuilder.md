# Vulnapps - Application Builder Spec

Complete specification to build the Vulnapps application from scratch.

---

## Overview

Vulnerability registry app where users register known vulnerable applications with their vulnerabilities, then submit scan results to measure scanner accuracy (TP, FP, FN, precision, recall, F1).

**Stack:** FastAPI (API-first) + SQLite (aiosqlite) + React SPA (Vite) + JWT auth (bcrypt + pyjwt)
**Target:** AWS t2.nano (512MB RAM) — must be lightweight
**Python:** >=3.8 (use `from __future__ import annotations` for type union syntax)

---

## Architecture

### API-First Design

The application follows an API-first architecture. All functionality is exposed through JSON REST endpoints under `/api`. The old Jinja2 template-based web routes are removed. A React SPA serves the frontend.

**Backend layers:**
1. **Route handlers** (`app/routers/api/`) — Thin JSON wrappers. Parse request, call service, return JSON or raise HTTPException.
2. **Service layer** (`app/services/`) — All business logic, database queries, permission checks. Services receive a `db` connection and `user` dict.
3. **Shared modules** — `matching.py`, `visibility.py`, `dependencies.py`, `auth.py` provide cross-cutting concerns.

**Frontend:** React SPA in `frontend/` built with Vite. Communicates exclusively via `/api` endpoints. JWT stored in `localStorage`.

**SPA serving:** FastAPI serves the built React app. Non-API, non-static paths that return 404 serve `frontend/dist/index.html` for client-side routing.

---

## Visual Design

Dark theme with orange accents:
- **Background:** Near-black (`#0a0a0a`), dark panels (`#18181b`)
- **Borders:** Dark gray (`#27272a`), hover (`#3f3f46`)
- **Primary accent:** Orange (`#f97316`), hover (`#fb923c`), dim (`rgba(249,115,22,0.15)`)
- **Text:** White (`#fafafa`) headings, `#a1a1aa` secondary, `#71717a` muted
- **Success/Error:** Green `#22c55e` for TP/good, Red `#ef4444` for FP/FN/bad
- **Severity badges:** critical=red, high=orange, medium=yellow, low=green, info=blue
- **Role badges:** user=gray, admin=red. Team roles: admin=red, contributor=orange, view=gray
- Custom CSS (no framework) — Tailwind-inspired utility classes, hand-written for minimal footprint
- Font: system font stack, monospace for code/IDs

---

## User Roles & Permissions

### Account-Level Roles (2)
| Role | Can do |
|------|--------|
| **user** (default) | Create private/team apps, submit scans on own apps, manage teams |
| **admin** | Everything + manage public apps/vulns/scans, manage users, manage labels |

- First registered user automatically becomes **admin**
- Subsequent users register as **user** by default
- Admin grants admin access via admin panel

### Team-Level Roles (3)
| Role | Can do within team |
|------|--------|
| **admin** | Manage team members, full control of team apps/vulns/scans |
| **contributor** | Create/edit apps, vulns, scans within the team |
| **view** | Read-only access to team apps, vulns, and scans |

### Authorization Rules

**Read access:**
- Unauthenticated: public apps, vulns, public scans on public apps
- Logged in: + own private apps/scans, team apps/scans (any team role)
- Admin: everything

**Write access to apps/vulns:**
- Public apps: admin only
- Private apps: app creator only
- Team apps: team admin or team contributor, or app creator

**Scan submission:**
- Public apps: admin only (users must clone to private first)
- Private apps: app creator
- Team apps: team admin or contributor

**Scan modification (match, FP, rematch, delete):**
- Scan submitter (owns the scan)
- Team admin/contributor (for team app scans)
- Admin (always)

### App Cloning
Any logged-in user can clone any app they can read. Cloning creates a private copy with all vulns (not scans).

---

## Project Structure

```
vulnapps/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, lifespan, SPA serving, middleware, API router includes
│   ├── config.py             # Settings from env vars (SECRET_KEY, DATABASE_PATH, TOKEN_EXPIRY_HOURS)
│   ├── database.py           # aiosqlite connection (Row factory), migration runner
│   ├── auth.py               # bcrypt hash/verify, JWT create/decode (HS256)
│   ├── dependencies.py       # get_current_user, require_user, require_admin, require_app_write, require_scan_write, get_team_role, require_scope
│   ├── matching.py           # Shared scan finding matching logic (DAST + SAST)
│   ├── scoring.py            # PURE scoring: weight scale, tiers, revision scope, compute_metrics
│   ├── visibility.py         # App/scan visibility filter (public/team/private)
│   ├── models.py             # Pydantic schemas
│   ├── seed.py               # TaintedPort seed data (25+ vulns, auto-seeded on first admin registration)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── api/              # API-first route handlers (thin JSON wrappers)
│   │   │   ├── __init__.py
│   │   │   ├── auth.py       # /api/auth — login, register, me
│   │   │   ├── account.py    # /api/account — profile, name, password, API keys
│   │   │   ├── apps.py       # /api/apps — app CRUD
│   │   │   ├── vulns.py      # /api/apps/{id}/vulns — vulnerability CRUD + import
│   │   │   ├── scans.py      # /api/scans — scan CRUD, findings, labels, compare, submit
│   │   │   ├── teams.py      # /api/teams — team CRUD, member management
│   │   │   └── admin.py      # /api/admin — user management, label management
│   ├── services/             # Business logic layer
│   │   ├── __init__.py
│   │   ├── auth.py           # Login, register, me, API key management, password/name updates
│   │   ├── apps.py           # App CRUD, cloning, visibility checks
│   │   ├── vulns.py          # Vulnerability CRUD, import (JSON/CSV)
│   │   ├── scans.py          # Scan CRUD, submit, matching, compare, metrics
│   │   ├── scoring.py        # Ground-truth revisions, scope queries, live scoring
│   │   ├── labels.py         # Label CRUD, scan-label association, admin label management
│   │   ├── teams.py          # Team CRUD, member management
│   │   └── users.py          # Admin user management (list, update, delete, profiles)
│   └── static/
│       └── logo.svg          # Shield + crosshair SVG logo (served at /static/logo.svg)
├── frontend/                 # React SPA (Vite)
│   ├── index.html            # HTML entry point
│   ├── package.json          # Dependencies: react, react-dom, react-router-dom
│   ├── vite.config.js        # Vite config with dev proxy to backend
│   ├── dist/                 # Built output (served by FastAPI in production)
│   └── src/
│       ├── main.jsx          # React entry point (imports style.css for Vite to hash + bundle)
│       ├── style.css         # Full dark theme CSS (bundled by Vite → content-hashed asset)
│       ├── App.jsx           # Router with all 19 page routes
│       ├── api/
│       │   └── client.js     # API client: fetch wrapper with JWT auth, auto-redirect on 401
│       ├── context/
│       │   └── AuthContext.jsx  # Auth state provider (login, register, logout, refreshUser)
│       ├── components/
│       │   ├── Navbar.jsx    # Top nav with auth-aware links
│       │   ├── Badge.jsx     # Severity/role badge component
│       │   ├── LabelBadge.jsx  # Color-coded scan label badge
│       │   ├── ConfirmButton.jsx  # Button with confirmation dialog
│       │   └── EmptyState.jsx    # Empty state placeholder
│       └── pages/
│           ├── Home.jsx          # Landing page
│           ├── Login.jsx         # Login form
│           ├── Register.jsx      # Registration form
│           ├── Account.jsx       # Account settings (name, password, API keys)
│           ├── AppsList.jsx      # App listing with search and filters
│           ├── AppDetail.jsx     # App detail with vulns table, scan count
│           ├── AppForm.jsx       # Create/edit app form (with clone support)
│           ├── VulnDetail.jsx    # Vulnerability detail
│           ├── VulnForm.jsx      # Create/edit vulnerability form
│           ├── ScansList.jsx     # Scans listing with filters (scanner, app, label, auth status)
│           ├── ScanDetail.jsx    # Scan detail with metrics, findings, missed vulns
│           ├── ScanSubmit.jsx    # Scan submission form (JSON/CSV upload or manual entry)
│           ├── ScanCompare.jsx   # Scan comparison with metrics and detection matrix
│           ├── TeamsList.jsx     # Teams listing
│           ├── TeamDetail.jsx    # Team detail with member management
│           ├── TeamForm.jsx      # Create team form
│           ├── AdminUsers.jsx    # Admin user management
│           └── AdminLabels.jsx   # Admin label management
├── migrations/
│   ├── 001_initial.sql       # Schema with all tables and indexes
│   ├── 002_tech_stack.sql    # App technologies table
│   ├── 003_rename_username_to_name.sql  # Rename username → name
│   ├── 004_static_scan_support.sql      # Add filename to vulns + findings
│   ├── 005_viewer_role.sql              # Add viewer role to users
│   ├── 006_teams.sql                    # Teams + team_members tables
│   ├── 007_app_visibility.sql           # App visibility + team_id
│   ├── ...                              # 008-023: incremental changes
│   ├── 024_vuln_weights.sql             # impact_weight + difficulty_tier (+ backfill)
│   ├── 025_ground_truth_revisions.sql   # revisions table, existed/known/invalidated, scans.corpus_revision
│   ├── 028_chains.sql                   # chains, chain_members (credited iff all members matched)
│   ├── 030_fp_group.sql                 # scan_findings.fp_group (FP clustering)
│   ├── 032_benchmark_corpus.sql         # apps.benchmark_verified, vulns.weight_verified
│   ├── 034_weight_verified_deploy_fix.sql  # deploy-pipeline fix (migration tracked by filename)
│   ├── 035_finding_reasoning.sql        # scan_findings.reasoning (LLM mapping rationale)
│   ├── 036_audit_log.sql                # audit_log table (scan/vuln history log)
│   ├── 037_audit_log_chains.sql         # widen audit_log.entity_type to allow 'chain'
│   ├── 038_scan_chain_credits.sql       # explicit human-adjudicated chain credit (see below)
│   ├── 039_finding_matched_chain.sql    # scan_findings.matched_chain_id (direct chain match)
│   ├── 040_finding_matches.sql          # finding_matches join table; one finding -> many vulns/chains
│   ├── 012_permissions_redesign.sql     # Collapse roles to user/admin, team roles to admin/contributor/view
│   ├── 013_api_keys.sql                 # API keys table with scopes
│   ├── 014_scan_labels.sql              # Labels + scan_labels junction table
│   ├── 015_scan_cost.sql                # cost REAL column on scans
│   └── 016_scan_tokens.sql              # tokens INTEGER column on scans
├── tools/
│   └── import_scan.py                  # CLI scan importer with LLM-assisted vuln mapping
├── tests/
│   └── __init__.py
├── tasks/
│   └── todo.md
├── requirements.txt
├── pyproject.toml
├── Dockerfile                          # Multi-stage build (Node 20 + Python 3.12)
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── DeployInstructions.txt
├── aws/
│   └── setup-ec2.sh
└── docker/
    └── nginx-host-vulnapps.conf
```

---

## Dependencies

### Backend (`requirements.txt`)
```
fastapi
uvicorn[standard]
python-multipart
aiosqlite
pyjwt
bcrypt
python-dotenv
httpx
anthropic[vertex]
pytest
pytest-asyncio
```

### Frontend (`frontend/package.json`)
```json
{
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.4",
    "vite": "^5.4.11"
  }
}
```

---

## Configuration (`app/config.py`)

Environment variables with defaults:
- `SECRET_KEY` — JWT signing key (default: `"change-me-in-production"`)
- `DATABASE_PATH` — SQLite file path (default: `"vulnapps.db"`)
- `TOKEN_EXPIRY_HOURS` — JWT token lifetime (default: `24`)

Uses `python-dotenv` to load `.env` file.

---

## Database Schema (migrations 001-042)

**Migration runner** (`app/database.py`): files run in order, tracked by filename in
`_migrations`, each with `executescript`. A `duplicate column name` error means that column
already exists (an earlier edited version of the file, or a manual reconciliation) — the runner
then resumes with the statements **after** the failing one (`_run_migration_script`; the error
names the column, statements are split with `sqlite3.complete_statement`). It used to record the
file as applied and silently skip everything after the duplicate. It deliberately does not run
statement by statement: table-rebuild migrations bracket their work in
`PRAGMA foreign_keys=OFF/ON`, which only takes effect between transactions, and a rebuild with
foreign keys still on cascades deletes.

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS apps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    category    TEXT,                                   -- Legacy, not used in UI
    created_by  INTEGER NOT NULL REFERENCES users(id),
    visibility  TEXT NOT NULL DEFAULT 'public',  -- public, team, private
    team_id     INTEGER REFERENCES teams(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    vuln_id       TEXT NOT NULL,                -- Custom ID e.g. "VULN-001"
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    vuln_type     TEXT,                         -- e.g. "XSS", "SQLi", "SSRF"
    http_method   TEXT,                         -- GET, POST, etc.
    url           TEXT,                         -- Affected URL/endpoint
    parameter     TEXT,                         -- Affected parameter (DAST)
    filename      TEXT,                         -- Affected file (SAST)
    description   TEXT,
    code_location TEXT,
    poc           TEXT,                         -- Proof of concept
    remediation   TEXT,
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, vuln_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id         INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    scanner_name   TEXT NOT NULL,               -- "ZAP", "Burp", etc.
    scan_date      TEXT NOT NULL,
    authenticated  INTEGER NOT NULL DEFAULT 0,
    is_public      INTEGER NOT NULL DEFAULT 1,
    notes          TEXT,
    cost           REAL,                        -- Private: scan cost in USD (migration 015)
    tokens         INTEGER,                     -- Private: LLM token count (migration 016)
    submitted_by   INTEGER NOT NULL REFERENCES users(id),
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_type       TEXT NOT NULL,
    http_method     TEXT,
    url             TEXT,
    parameter       TEXT,
    filename        TEXT,                         -- SAST finding filename
    -- matched_vuln_id / matched_chain_id were DROPPED in migration 040; a
    -- finding's matches live in finding_matches (below), because one finding
    -- can demonstrate several things at once.
    is_false_positive INTEGER NOT NULL DEFAULT 0,
    is_ignored      INTEGER NOT NULL DEFAULT 0,    -- "Ignored" state (migration 023)
    -- Rich detail fields (migration 019) — populated by scanners that emit full
    -- vuln-like reports (e.g. LLM-assisted scans). All nullable. Used to
    -- one-click "promote" an unmapped finding into a documented vulnerability.
    title           TEXT,
    severity        TEXT,
    description     TEXT,
    poc             TEXT,
    remediation     TEXT,
    code_location   TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_app ON vulnerabilities(app_id);
CREATE INDEX IF NOT EXISTS idx_scans_app ON scans(app_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id);

-- 002_tech_stack.sql
CREATE TABLE IF NOT EXISTS app_technologies (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id  INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    UNIQUE(app_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tech_app ON app_technologies(app_id);

-- 006_teams.sql
CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS team_members (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id  INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL DEFAULT 'view' CHECK(role IN ('admin','contributor','view')),
    UNIQUE(team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

-- Migration 013: API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash   TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT 'default',
    scope      TEXT NOT NULL DEFAULT 'read' CHECK(scope IN ('read','vuln-mapper','full')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

-- Migration 014: Scan labels
CREATE TABLE IF NOT EXISTS labels (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL DEFAULT '#f97316'
);

CREATE TABLE IF NOT EXISTS scan_labels (
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, label_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_labels_scan ON scan_labels(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_labels_label ON scan_labels(label_id);

-- Migration 024: severity weighting and difficulty tiers.
-- `severity` stays the DISPLAY field; `impact_weight` is the SCORING field and
-- may diverge from it where realized impact in the target app differs.
ALTER TABLE vulnerabilities ADD COLUMN impact_weight   INTEGER;  -- 1 | 3 | 9 | 27
ALTER TABLE vulnerabilities ADD COLUMN difficulty_tier TEXT;     -- commodity | business_logic | chained
-- Backfill: info/low→1, medium→3, high→9, critical→27; tier→'commodity'.
-- SQLite cannot add CHECK constraints via ALTER, so both are validated in
-- app/scoring.py (validate_weight / validate_tier) on every write path.

-- Migration 025: ground-truth revisions.
CREATE TABLE IF NOT EXISTS ground_truth_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL,
    reason     TEXT NOT NULL,   -- new_prior_vuln | weight_change | vuln_invalidated | corpus_change
    notes      TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_gt_revisions_app ON ground_truth_revisions(app_id);

ALTER TABLE vulnerabilities ADD COLUMN existed_since_revision  INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN known_since_revision    INTEGER DEFAULT 1;
ALTER TABLE vulnerabilities ADD COLUMN invalidated_at_revision INTEGER;
ALTER TABLE scans          ADD COLUMN corpus_revision          INTEGER;
-- Every existing app gets revision 1; every vuln existed_since/known_since 1;
-- every scan corpus_revision 1.

-- Migration 028: exploit chains. A chain is its own ground-truth entity with
-- its own weight; members keep theirs. Chains obey the revision scope rule.
-- Credited (full weight) only when every member is matched — matching members
-- independently is not evidence the chain was walked; there is no separate
-- chain-level partial-credit tracking.
CREATE TABLE IF NOT EXISTS chains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    chain_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    impact_weight INTEGER NOT NULL,
    description   TEXT,
    existed_since_revision  INTEGER DEFAULT 1,
    invalidated_at_revision INTEGER,
    UNIQUE(app_id, chain_id)
);
CREATE TABLE IF NOT EXISTS chain_members (
    chain_pk   INTEGER NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
    vuln_id    INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    PRIMARY KEY (chain_pk, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_chains_app ON chains(app_id);

-- Migration 030: false-positive clustering (the FP-side equivalent of
-- matched_vuln_id — findings describing one non-issue share a group key).
ALTER TABLE scan_findings ADD COLUMN fp_group TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_fp_group ON scan_findings(scan_id, fp_group);

-- Migration 032: flag hand-curated apps and hand-reviewed vulns.
-- benchmark_verified: this app's vulns have actually been reviewed (weights/
-- tiers hand-set, not just backfilled). Set via the UI (App edit → "Benchmark
-- corpus") or PUT /api/apps/{id} — never inferred from name/version.
ALTER TABLE apps ADD COLUMN benchmark_verified INTEGER NOT NULL DEFAULT 0;
-- weight_verified: this single vuln's contextual severity and tier have been
-- hand-reviewed, as opposed to still carrying the 024 backfill/placeholder.
ALTER TABLE vulnerabilities ADD COLUMN weight_verified INTEGER NOT NULL DEFAULT 0;
```

### Tech Stack
Apps have a one-to-many relationship with `app_technologies`. Each row stores a single technology name (e.g., "PHP", "Next.js"). In the form, users enter comma-separated values which are parsed and stored as individual rows. The `category` column in `apps` is legacy and not used in the UI.

### Scan Labels
Labels are user-defined, color-coded tags for scans. A many-to-many junction table (`scan_labels`) links scans to labels. Attaching an *existing* label to a scan only requires scan write access. *Creating* a brand-new label name is further restricted to global admins and team admins/contributors on the app's own team — a private app's own creator (who can submit/write to their own scan without any team role) still cannot coin a new label name, only attach one that already exists. Admin can also manage labels globally (CRUD) via `/api/admin/labels`. Labels are displayed as color-coded badges in the scans list and scan detail. The scans list supports filtering by label.

### Scan Cost, Tokens & Duration
Private fields on scans (`cost REAL`, `tokens INTEGER`, `duration INTEGER` seconds). Only visible to the scan owner, team members of the app's team, and admins, and editable inline on the scan detail page (Cost shows even when unset so it can be added). Used to track LLM-based scanner costs/effort.

The CLI importer extracts these from the scan report via the LLM (alongside scanner name and start date) and attaches them when present. Precedence: explicit `--cost`/`--tokens`/`--duration` flag > value the LLM read from the report. For tokens, if neither is available the importer falls back to its own mapping-LLM token count (`_llm_tokens`). Nothing is sent when a value is absent.

---

## Architecture Patterns

### Service Layer Pattern
All business logic lives in `app/services/`. Route handlers in `app/routers/api/` are thin JSON wrappers:
1. Parse request (query params, JSON body)
2. Call service function with `db`, `user`, and parsed args
3. Return JSON result or raise HTTPException for errors

Services raise `ValueError` (mapped to 400/404) or `PermissionError` (mapped to 403) — route handlers catch and convert to HTTP errors.

### Database Access
Routes and services use manual connection management:
```python
db = await get_connection()
try:
    # ... queries using db.execute() with parameterized SQL ...
finally:
    await db.close()
```
`get_connection()` returns an `aiosqlite.Connection` with `row_factory = aiosqlite.Row` (dict-like access) and `PRAGMA foreign_keys=ON`.

### Migration Runner
On startup (via FastAPI lifespan), all `.sql` files in `migrations/` are executed in sorted order using `executescript()`. Tracks applied migrations in a `_migrations` table to avoid re-running non-idempotent migrations (e.g., ALTER TABLE). Uses `CREATE TABLE IF NOT EXISTS` for idempotency in schema-creation migrations.

### Auth Flow
- **Login:** email + password (not username)
- **Register:** name (display name) + email + password
- **Frontend (React SPA):** JWT stored in `localStorage`, sent as `Authorization: Bearer <token>` header
- **API:** JWT or API key in `Authorization: Bearer <token>` header
- **API Keys:** Format `va_` + 32 hex chars. Stored as SHA-256 hash. Users generate/revoke from Account page.
  - Scopes: `read` (GET only), `vuln-mapper` (read + submit scans + match findings), `full` (all ops)
  - `get_current_user` detects `va_` prefix → looks up in `api_keys` table → loads user with `api_key_scope`
  - `require_scope(user, min_scope)` enforces scope hierarchy on all write endpoints. JWT users bypass scope checks.
- `get_current_user` middleware checks Bearer header (JWT or API key), injects result into `request.state.user`
- Role-based auth functions raise HTTPException 401/403:
  - `require_user` — any authenticated user
  - `require_admin` — admin role **and** `full` key scope (see **Security** below)
  - `require_app_write(request, db, app)` — admin, creator, or team contributor+
  - `require_scan_write(request, db, scan, app)` — admin, submitter, or team contributor+
  - `get_team_role(db, user_id, team_id)` — returns team role or None
  - `require_scope(user, min_scope)` — API key scope check
- Password hashing: bcrypt
- JWT payload: `{ sub: user_id, name, role, exp }`
- 24h token expiry, no refresh tokens

### Security
- Password hashes are excluded from the admin user list endpoint
- API key scope enforcement on all write endpoints
- All write operations check both authentication and authorization
- **Role and scope are independent, and admin routes require both.** `role` says
  who the caller is; `api_key_scope` caps what that particular credential may do
  (`read` < `vuln-mapper` < `full`; a JWT/cookie session has no scope and is
  unrestricted). Every route in `app/routers/api/admin.py` goes through
  `_require_admin`, which checks the role **and then** `require_scope(user, "full")`.
  Without the scope check a narrow key minted by an admin reached every admin
  route, user management included — the scope was a label rather than a limit.
  Role is checked first, so a `full`-scope key cannot buy admin for a non-admin.
  `tests/test_admin_scope.py` pins each case, including a structural test that
  every route in the admin router actually calls the gate.

### SPA serving & cache safety (blank-page guard)
The SPA catch-all (`app/main.py`) must not turn a cache-skewed deploy into a
silent blank page:
- **`index.html` is served with `Cache-Control: no-cache`** so browsers
  revalidate it every load. Otherwise a browser (or CDN) keeps an old
  `index.html` that points at a hashed asset a redeploy has purged.
- **Missing `/assets/*` requests return their real 404** — the catch-all
  excludes `/assets` (alongside `/api`, `/static`). Falling back to
  `index.html` for a purged asset would answer a `.js` request with
  `200 text/html`, which the browser refuses to execute as a module → a blank
  page with no 404 to explain it. Let it 404 loudly instead.
Hashed assets (`/assets/index-<hash>.js|css`) stay long-cacheable; only
`index.html` is revalidated. This is the durable fix for post-deploy blank
pages (the same class of skew the content-hashed CSS note above addresses).

### Input & Response Bounds (resource-exhaustion guard)
The vulnerability write path and the app-detail read path are bounded so no
single app can produce a multi-MB response. (A 2026-07 recon flood created
48k vulns on one app — one with a 1 MB title — turning `GET /api/apps/{id}`
into a 14 MB response that OOM-killed the 512 MB host.)

- **Per-app vuln cap** — `MAX_VULNS_PER_APP = 1000` (in `app/services/vulns.py`).
  `create_vuln` rejects over-cap creates with a 400 ("maximum … vulnerabilities");
  `import_vulns` stops at the remaining budget (partial import, returns count).
- **Field length caps** — `_FIELD_CAPS` in `app/services/vulns.py` truncates each
  vuln string field on create/update/import (e.g. title 500, description/poc/
  remediation 10000, url 2048). Truncation (not rejection) keeps bulk imports
  flowing; caps sit far above any legitimate value so real data is never trimmed.
- **Bounded reads** — `get_app` and `list_vulns` `LIMIT` the returned vuln list to
  `MAX_VULNS_PER_APP`. `get_app` computes `severity_counts` and `vuln_count` via
  SQL aggregates (accurate regardless of truncation) and returns `vuln_count` +
  `vulns_truncated`; the SPA's AppDetail shows `vuln_count` for the true total.
  This protects even a DB that still holds pre-cap flood data.
- **Cleanup tool** — `tools/cleanup_scan_garbage.sh <db>` removes recon/test
  garbage (all data owned by non-`@snyk.io` accounts) in two phases: a full
  user→apps→vulns/scans/findings preview, then a transactional delete + VACUUM
  on Enter (auto-backs up the DB first).

### First User = Admin + Seed Data
In the register service, when user count is 0, the new user gets `role='admin'`. All subsequent users get `role='user'`.

When the first admin registers, `seed_taintedport(db, user_id)` is called to populate the database with the TaintedPort app and all 25 known vulnerabilities. The seed function is idempotent — it checks if TaintedPort already exists before inserting.

### Seed Data: TaintedPort (`app/seed.py`)
Pre-populated app: **TaintedPort v1.0** — intentionally vulnerable wine store (PHP + Next.js + SQLite).

25 vulnerabilities seeded with full details (description, code_location, poc, remediation).

Each entry may also carry `impact_weight` (1/3/9/27) and `difficulty_tier`
(commodity | business_logic | chained). Where an entry omits them, seeding derives
the weight from `severity` and defaults the tier to `commodity` — the same
fallback migration 024 applied to existing databases. Those derived values are a
starting point, not a measurement: `impact_weight` is meant to reflect realized
impact in *this* app, and a placeholder tier makes the tier matrix claim every
flaw here is commodity, which is false for the price-manipulation, discount-bypass
and JWT-forgery entries. Both need a pass by hand. Seeding also inserts the app's
`ground_truth_revisions` row for revision 1.

The severity column below is contextual severity: it is what the flaw is worth *in this
application*, and `impact_weight` derives from it 1:1.


| ID | Title | Severity | Type |
|----|-------|----------|------|
| TP-001 | SQL Injection - Login Email | high | SQLi |
| TP-002 | SQL Injection - Wine Detail (ID in URL) | high | SQLi |
| TP-003 | SQL Injection - Wine Search | high | SQLi |
| TP-004 | SQL Injection - Wine Reviews | high | SQLi |
| TP-005 | Blind SQL Injection - Order Status Filter | high | SQLi |
| TP-006 | Reflected XSS - Login Email | medium | XSS |
| TP-007 | Reflected XSS - Wine Search | medium | XSS |
| TP-008 | Stored XSS - User Name (Profile) | medium | XSS |
| TP-009 | Stored XSS - Shipping Name (Checkout) | medium | XSS |
| TP-010 | Stored XSS - Wine Review Comment | medium | XSS |
| TP-011 | JWT 'none' Algorithm Accepted | high | Broken Authentication |
| TP-012 | JWT Signature Not Verified | high | Broken Authentication |
| TP-013 | Directory Listing | medium | Information Disclosure |
| TP-014 | Path Traversal - Wine Export | high | Path Traversal |
| TP-015 | Open Redirect on Login | medium | Open Redirect |
| TP-016 | Missing Security Headers | low | Security Misconfiguration |
| TP-017 | BOLA (IDOR) on Order Details | high | IDOR |
| TP-018 | BOLA / Mass Assignment on Profile Update | high | IDOR |
| TP-019 | Price Manipulation on Cart | high | Business Logic |
| TP-020 | Broken Access Control on 2FA Disable | high | Broken Access Control |
| TP-021 | Discount Code Bypass | high | Business Logic |
| TP-022 | Privilege Escalation via Mass Assignment on Registration | critical | Privilege Escalation |
| TP-023 | Privilege Escalation via JWT Claim Forgery | critical | Privilege Escalation |
| TP-024 | BOPLA - Excessive Data Exposure on Order Details | high | Data Exposure |
| TP-025 | BFLA - Broken Function Level Authorization on Order Status | high | Broken Access Control |
| TP-027 | SSRF via Wine Import URL | high | SSRF |
| TP-028 | SQLi -> TOTP Secret Extraction -> 2FA Bypass -> Account Takeover | critical | SQLi |
| TP-029 | Reflected XSS - Contact Form Preview (Server-Side) | medium | XSS |

Source: `/Users/nuno/dev/TaintedPort/KnownVulnerabilities.txt`

---

## API Routes (`/api`)

All endpoints return JSON. Auth via `Authorization: Bearer <token>` header (JWT or API key). Auto-generated Swagger UI at `/api/docs`, ReDoc at `/api/redoc`, OpenAPI spec at `/api/openapi.json`.

### API Root (`/api`)
`GET /api` — Returns API info and endpoint listing. Redirects to Swagger UI if `Accept: text/html`.

`GET /api/version` — No auth required. Returns `{"version": "v<major>.<minor>"}` — see **App
Version** above.

### Auth (`/api/auth`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| POST | `/api/auth/login` | None | Login with `{email, password}`, returns `{token, user}` |
| POST | `/api/auth/register` | None | Register with `{name, email, password}`, returns `{token, user}` |
| GET | `/api/auth/me` | User+ | Get current user profile |

### Apps (`/api/apps`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps` | None / read | List apps (visibility filtered). Query: `?q=`, `?filter=` |
| GET | `/api/apps/{id}` | None / read | App detail with vulns, tech stack, permissions |
| POST | `/api/apps` | User+ / full | Create app. Body: `{name, version, description, url, source_repository, source_commit, source_directory, visibility, team_id, tech_stack, clone_from}` |
| PUT | `/api/apps/{id}` | App write / full | Update app |
| DELETE | `/api/apps/{id}` | App write / full | Delete app |

Apps have optional `source_repository`, `source_commit` and `source_directory`
columns (migration 043).
Following testbed target manifests, the repository identifies the app source and
the commit pins its revision. Neither field claims that the live deployment runs
that revision. Repository URLs must use HTTP(S), include a host and contain no
credentials. A commit, when recorded, is a full 40- or 64-character hexadecimal
SHA. The optional directory identifies an app inside a monorepo using a relative
POSIX path without parent traversal. Missing values remain null. These fields do
not replace the deployment URL or release version; app descriptions explain the app.

Create/edit forms expose these fields. App details show a repository link and a
short commit label with the full SHA in its tooltip; GitHub commits link directly
to the revision. GitHub directories link to the pinned tree, or HEAD when no
commit is recorded. Cloning inherits source fields unless explicitly overridden.
On update, omitted source fields retain their values and explicit null clears
them, preserving metadata when older clients edit an app. App cards omit empty
release versions.

### Vulnerabilities (`/api/apps/{id}/vulns`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps/{id}/vulns` | None / read | List vulns for app |
| GET | `/api/apps/{id}/vulns/{vid}` | None / read | Vuln detail |
| POST | `/api/apps/{id}/vulns` | App write / full | Create vuln. `impact_weight` (1\|3\|9\|27) and `difficulty_tier` are required by the forms and validated server-side; omitted, the weight derives from `severity` and the tier defaults to `commodity`. Opens a `new_prior_vuln` revision when the app has scans |
| PUT | `/api/apps/{id}/vulns/{vid}` | App write / full | Update vuln. Omitting the scoring fields PRESERVES the stored values (never resets a hand-corrected weight). A changed `impact_weight` opens a `weight_change` revision |
| DELETE | `/api/apps/{id}/vulns/{vid}` | App write / full | Delete vuln. **409** if any finding matched it — invalidate instead |
| POST | `/api/apps/{id}/vulns/{vid}/invalidate` | App write / full | Retire from ground truth at a new revision. Body (optional): `{notes}`. Stays in scope for earlier revisions |
| POST | `/api/apps/{id}/vulns/import` | App write / full | Import vulns from JSON/CSV (file upload or JSON body). Optional `existed_since` (`all_along` \| `this_revision`, default `this_revision`) decides whether prior scans are re-scored against the batch |
| GET | `/api/apps/{id}/vulns/export` | None / read | Download all vulns for the app as a CSV file (`Content-Disposition: attachment`). Never capped by `MAX_VULNS_PER_APP` — unlike the list/detail endpoints, it's one file rather than a paginated response. Columns match what `import` reads, so an export round-trips through import unchanged. String cells starting with `=`, `+`, `-`, or `@` get a leading `'` to defuse spreadsheet formula injection |
| GET | `/api/apps/{id}/history` | App write | Audit-log entries for this app's vulnerabilities (created/updated/deleted/invalidated/bulk-imported), most recent first. Gated on app write access, not a separate role — see History Log below |

### Chains (`/api/apps/{id}/chains`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps/{id}/chains` | None / read | List chains, each with resolved ordered `members` |
| POST | `/api/apps/{id}/chains` | App write / full | Create. See **Exploit chains** above for the full field list and modeling rule |
| PUT | `/api/apps/{id}/chains/{pk}` | App write / full | Full update — title/description/weight/members |
| DELETE | `/api/apps/{id}/chains/{pk}` | App write / full | Hard delete |

### Scans (`/api/scans` + `/api/apps/{id}/scans`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/scans` | None / read | List scans with filters: `?app_id=`, `?scanner=`, `?latest=`, `?q=`, `?authenticated=`, `?label=`, `?filter=`. Returns scans, scan_labels_map, scanners list, apps list, all labels |
| GET | `/api/scans/{id}` | Varies / read | Scan detail with metrics, findings, missed vulns, labels |
| PUT | `/api/scans/{id}` | Scan write / vuln-mapper | Update scan metadata: `{scanner_name, scan_date, authenticated, notes}` |
| DELETE | `/api/scans/{id}` | Scan write | Delete scan |
| POST | `/api/apps/{id}/scans` | User+ / vuln-mapper | Submit scan. Body: `{scanner_name, scanner_version, scan_date, authenticated, is_public, notes, cost, tokens, duration, findings, labels}`. The server stamps `corpus_revision` with the app's latest revision. Each finding may include `{vuln_type, http_method, url, parameter, filename, title, severity, description, poc, remediation, code_location, fp_group}` |
| POST | `/api/scans/{id}/findings/{fid}/match` | Scan write / vuln-mapper | Set a finding's complete match set: `{vuln_ids: [int], chain_ids: [int]}` (full replacement; both empty clears it to Pending). One finding may credit several vulns and/or chains — see **Exploit chains**. The legacy single-value bodies (`{vuln_id: int\|null}` / `{chain_id: int\|null}`, mutually exclusive) are still accepted for older clients |
| POST | `/api/scans/{id}/findings/{fid}/mark-fp` | Scan write / vuln-mapper | Mark finding as false positive. Optional body `{fp_group}` clusters findings describing the same non-issue so precision counts them once |
| POST | `/api/scans/{id}/findings/{fid}/ignore` | Scan write / vuln-mapper | Set/clear the "Ignored" state. Body `{ignored: bool}` (default `true`). Callable from any state — ignoring clears any match/FP; clearing returns to Pending |
| POST | `/api/scans/{id}/findings/{fid}/promote` | App write / vuln-mapper | Promote a pending finding into a new vuln on the scan's app. Body: `{vuln_id, title, severity, vuln_type, http_method, url, parameter, filename, description, poc, remediation, code_location, impact_weight, difficulty_tier}` — missing fields fall back to the finding's stored values; `vuln_id` auto-generates as the next `DISC-NNN` slug if blank. **`existed_since` is REQUIRED** (`all_along` \| `this_revision`) — **400** without it. Always opens a `new_prior_vuln` revision. The finding is linked to the new vuln on success |
| POST | `/api/scans/{id}/rematch` | Scan write / vuln-mapper | Re-run automatic matching for all findings (in-scope vulns only) |
| GET | `/api/scans/{id}/history` | Scan write | Audit-log entries for this scan's findings (matched/unmatched/marked FP/ignored/promoted/rematched), most recent first. Gated on scan write access, not a separate role — see History Log below |
| GET | `/api/apps/{id}/revisions` | None / read | Ground-truth revision history + `latest_revision` |
| POST | `/api/apps/{id}/revisions` | App write / vuln-mapper | Open a revision: `{reason, notes}`. Required before a weight change takes effect |
| POST | `/api/scans/{id}/labels` | Scan write | Add label to scan: `{name, color}`. Upserts label, links to scan |
| DELETE | `/api/scans/{id}/labels/{label_id}` | Scan write | Remove label from scan |

### Scan Comparison (`/api/apps/{id}/compare`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/apps/{id}/compare` | None / read | Without `?scans=`: returns available scans. With `?scans=1,2,3`: returns comparison metrics + detection matrix |

### Labels (`/api/labels`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/labels` | None | List all labels (name, color) |

### Teams (`/api/teams`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/teams` | User+ | List teams (own teams; admin sees all) |
| GET | `/api/teams/{id}` | Team member+ | Team detail with members |
| POST | `/api/teams` | User+ | Create team (creator becomes team admin) |
| DELETE | `/api/teams/{id}` | Team admin+ | Delete team |
| POST | `/api/teams/{id}/members` | Team admin+ | Add member: `{email, role}` |
| PUT | `/api/teams/{id}/members/{uid}` | Team admin+ | Change member role: `{role}` |
| DELETE | `/api/teams/{id}/members/{uid}` | Team admin+ | Remove member |

### Account (`/api/account`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/account` | User+ | Account info + API keys |
| PUT | `/api/account/name` | User+ | Update display name: `{name}`. Returns new JWT token |
| PUT | `/api/account/password` | User+ | Change password: `{current_password, new_password}` |
| POST | `/api/account/api-keys` | User+ | Generate API key: `{name, scope}` — returns full key once |
| DELETE | `/api/account/api-keys/{id}` | User+ | Revoke API key (must own it) |

### Admin (`/api/admin`)
| Method | Path | Auth / Scope | Description |
|--------|------|-------------|-------------|
| GET | `/api/admin/users` | Admin | List all users (password hashes excluded) |
| PUT | `/api/admin/users/{id}` | Admin | Update user (name, email, role) |
| DELETE | `/api/admin/users/{id}` | Admin | Delete user (cannot delete self or admins) |
| GET | `/api/admin/labels` | Admin | List labels with scan_count |
| POST | `/api/admin/labels` | Admin | Create label: `{name, color}` |
| PUT | `/api/admin/labels/{id}` | Admin | Update label: `{name, color}` |
| DELETE | `/api/admin/labels/{id}` | Admin | Delete label and all associations |
| GET | `/api/admin/changelog` | Admin | Release history: `{version, entries[]}`, one entry per commit on main — see **Change Log** |

---

## React SPA Frontend

### Technology
- **Framework:** React 18 with Vite 5
- **Routing:** React Router DOM v6
- **Styling:** `frontend/src/style.css` (no CSS framework), imported in `main.jsx` so Vite
  bundles it into a **content-hashed** `/assets/index-<hash>.css` injected into `index.html`.
  This versions the CSS in lockstep with the JS bundle — a deploy can never leave a fresh
  `index.html` pointing at a CDN-cached stale stylesheet. (Do NOT move it back to
  `app/static/` + a manual `<link href="/static/style.css">`; that fixed URL is what caused
  post-deploy cache skew, and the Docker frontend stage only copies `frontend/`.)
- **Auth:** JWT stored in `localStorage`, sent as `Authorization: Bearer` header
- **API Client:** `frontend/src/api/client.js` — thin fetch wrapper with auto-401 redirect

### Responsive / Mobile (≤768px)
A single `@media (max-width: 768px)` block in `style.css` drives the mobile layout:
- **Navbar:** a `.navbar-toggle` burger button (hidden on desktop) toggles a slide-down
  `.navbar-nav.open` panel with stacked full-width links. The Admin menu is a click
  disclosure (`.nav-dropdown.open`, not hover) so it works on touch; `Navbar.jsx` closes
  the menu on route change via `useLocation`.
- **Layout:** forms (`.form-row`), `.detail-grid`, and `.card-grid` collapse to one column;
  `.page-header` stacks; search box goes full-width; container padding shrinks.
- **Tables:** row-oriented listing tables opt in with `class="cards-on-mobile"` and a
  `data-label="<Column>"` on each `<td>`. Below 768px the `<thead>` hides and each row
  becomes a bordered card with `td::before { content: attr(data-label) }` as the field
  label; empty cells (`td:empty`) and label-less action cells (`data-label=""`) are hidden.
  Genuinely 2D matrices (ScanCompare, Dashboard heatmap) stay on horizontal scroll instead.

### Vite Configuration
Dev server proxies `/api` and `/static` to `http://127.0.0.1:8000`, and sets `server.fs.allow: ['..']` so `main.jsx` can import `app/static/style.css` (which lives above the Vite root). Build output goes to `frontend/dist/` with content-hashed JS and CSS assets.

### Auth Context (`AuthContext.jsx`)
React context providing `{user, loading, login, register, logout, refreshUser}`. On mount, checks for stored token and calls `/api/auth/me` to restore session.

### Page Routes (19 pages)
| Route | Component | Description |
|-------|-----------|-------------|
| `/` | Home | Landing page |
| `/login` | Login | Login form |
| `/register` | Register | Registration form |
| `/account` | Account | Settings: name, password, API keys |
| `/apps` | AppsList | App listing with search |
| `/apps/new` | AppForm | Create app (supports `?clone_from=`) |
| `/apps/:id` | AppDetail | App detail + vulns table + scan/compare links |
| `/apps/:id/edit` | AppForm | Edit app |
| `/apps/:appId/vulns/new` | VulnForm | Create vulnerability |
| `/apps/:appId/vulns/:id` | VulnDetail | Vulnerability detail |
| `/apps/:appId/vulns/:id/edit` | VulnForm | Edit vulnerability |
| `/apps/:id/scans/new` | ScanSubmit | Submit scan (file upload or manual) |
| `/apps/:id/compare` | ScanCompare | Scan comparison |
| `/scans` | ScansList | All scans with filters |
| `/scans/:id` | ScanDetail | Scan metrics + findings + FN |
| `/teams` | TeamsList | Teams listing |
| `/teams/new` | TeamForm | Create team |
| `/teams/:id` | TeamDetail | Team detail + member management |
| `/admin/users` | AdminUsers | Admin user management |
| `/admin/labels` | AdminLabels | Admin label management |

### Shared Components
- **Navbar** — Auth-aware nav: Apps, Scans (logged-in), Teams (logged-in), Admin (admin), Account/Login/Register
- **Badge** — Severity/role colored badges
- **LabelBadge** — Color-coded scan label badge with optional remove button
- **ConfirmButton** — Button that shows confirmation dialog before action
- **EmptyState** — Placeholder for empty lists
- **HistoryLog** — Audit-trail table (When / Event), parameterized by `scanId` or `appId`. Fetches its own data and only renders when `canView` (the page's `can_edit` flag) is true — the real access control is the API's 403, this is UI polish. Used at the end of `ScanDetail.jsx` and `AppDetail.jsx` (see History Log below)

---

## Scan Submission & Matching

### API JSON Body
```json
{
  "scanner_name": "ZAP",
  "scan_date": "2026-03-09",
  "authenticated": false,
  "is_public": true,
  "notes": "optional",
  "cost": 0.05,
  "tokens": 12500,
  "labels": ["label-name"],

  "findings": [
    {"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"},
    {"vuln_type": "Missing Security Headers", "url": "/", "fp_group": "headers-noise"}
  ]
}
```

### Matching Logic (`app/matching.py`)

Shared `match_finding(finding, known_vulns)` function used by the scan service.

Uses a **scoring-based system** instead of binary matching. Each known vuln is scored against the finding; the highest score above a threshold (60) wins.

**vuln_type match is a hard gate** — candidates that don't match on vuln_type (via canonical aliases) are excluded entirely. This prevents matching an XSS finding to an SQLi vuln just because the URL matches.

**Scoring table:**
| Factor | Points | Notes |
|---|---|---|
| vuln_type match | 50 | Required — no match without this |
| URL exact match | 100 | Strongest signal |
| URL pattern match (placeholders) | 80 - 5*N | N = number of placeholder segments; min 50 |
| URL prefix glob (`/admin/*`) | 40 | Moderate signal |
| http_method match | 15 | Scanners sometimes differ |
| parameter exact match | 20 | Strong differentiator |
| parameter substring match | 10 | Handles `user_email` containing `email` |
| SAST filename exact match | 100 | Strong signal for file-level findings |

**A known vuln whose `url` is the global wildcard (`/*`) is never auto-matched
on category + URL score alone** (removed after an incident: a pass-the-hash
login bug, a 2FA-enrollment-without-reauth bug, and a TOTP-replay bug — three
unrelated findings — all auto-matched to an unrelated "JWT none-algorithm
accepted" vuln purely because vuln_type(50) + wildcard-URL(10) alone crossed
the 60 threshold for any finding sharing that broad category). Instead, a
wildcard-scoped vuln can still match, but only when the finding's own `title`
shares a meaningful keyword with the vuln's `title` — graded by how many words
overlap (50 + 10 + 5 per additional shared word beyond the first), so that a
tie between two same-category wildcard vulns (e.g. "JWT none-algorithm" vs
"JWT signature not verified") resolves to the more specific title match
instead of list order. A missing title on either side is "can't confirm," not
"allow." See `tests/test_matching.py` and `tasks/scanimport-resilience.md`.

**URL pattern handling:**
- Placeholder segments (`:id`, `{id}`, `(id)`, `<id>`, `[id]`) compiled to `([^/]+)` regex
- Trailing `/*` compiled to `(/.*)?` (matches zero or more trailing segments)
- `/*` alone compiled to `^/.*$` (matches any path)
- Query strings stripped from finding URLs before comparison
- Compiled regexes cached via `@lru_cache`

**Vuln type aliases** — expanded groups covering: SQLi, XSS, IDOR, auth bypass, access control, info disclosure, path traversal, open redirect, security misconfiguration, privilege escalation, data exposure, business logic, CSRF, SSRF, RCE, XXE, SSTI, NoSQL injection, prototype pollution, HTTP header injection, insecure deserialization, file upload, CORS, clickjacking, JWT, weak crypto, hardcoded secrets.

### One finding, several matches (`finding_matches`, migration 040)

A finding's matches live in a join table, not in a column on the finding:

```sql
CREATE TABLE finding_matches (
    finding_id INTEGER NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
    vuln_id    INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    chain_id   INTEGER REFERENCES chains(id) ON DELETE CASCADE,
    CHECK ((vuln_id IS NOT NULL) + (chain_id IS NOT NULL) = 1)   -- exactly one target per row
);
```

`scan_findings.matched_vuln_id` / `matched_chain_id` were dropped: a second source of truth
for the same fact is how the bugs below went unnoticed, and every reader moved in the same
change so a missed one fails loudly instead of reading a stale mirror. The `CHECK` is the one
migration 039 noted it could not add via `ALTER TABLE`.

Why it changed — two real gaps that the single-slot model could not express:

1. **Scan 330 (TaintedPort).** Three findings — path traversal, SSRF and directory listing —
   each explicitly read `api/config/jwt.php` and quoted the hardcoded HS256 secret. Each was
   matched to its own access vuln (TP-014 / TP-027 / TP-013), so `CODE-001` scored as MISSED
   despite being demonstrated three times over. There was no way to credit both: the only fix
   was re-pointing one finding, which cost its original vuln a piece of evidence.
2. **Chain-only reporting.** A scan reporting ONE clean chain narrative that names its three
   members got either the chain or one member — never the chain plus its members — while a
   scan that redundantly re-reported each member separately got all four. Same discovery,
   different score, purely from how the report was written up.

`app/services/finding_matches.py` is the only module that touches the table.
`scoring_service.fetch_findings` hydrates `matched_vuln_ids` / `matched_chain_ids` onto every
finding, so scoring, the comparison matrix, the dashboard and the per-scanner aggregates read
lists rather than issuing their own SQL. Writes go through `replace()` (full set replacement,
so callers are idempotent); marking a finding FP or Ignored clears its matches, and a deleted
finding cascades.

**Scoring is deliberately unchanged by this.** `tp` is still the count of DISTINCT in-scope
vulns with at least one match, and FP stays per-finding, so precision's denominator is
untouched. That is what keeps the metric symmetric (see **Metrics** below).

**Four finding states** (mutually exclusive — any transition clears the others):
| State | finding_matches rows | is_false_positive | is_ignored | Meaning |
|---|---|---|---|---|
| **TP** | >= 1 | 0 | 0 | Confident match (auto or manual) |
| **Pending** | none | 0 | 0 | No auto-match, awaiting manual review |
| **FP** | none | 1 | 0 | User explicitly marked as false positive |
| **Ignored** | none | 0 | 1 | Real-ish but irrelevant in context — consciously set aside (migration 023) |

- **Automatic matching**: Score >= 60 → TP. Score < 60 → **Pending** (not FP)
- **Manual mapping**: User maps pending finding to known vuln → TP
- **Mark FP**: User explicitly marks as FP → `POST /api/scans/{id}/findings/{fid}/mark-fp`
- **Ignore**: `POST /api/scans/{id}/findings/{fid}/ignore` body `{ignored: bool}` — `true` sets Ignored, `false` returns to Pending. Reachable from **every** state, not just Pending: the service clears any matches and the FP flag/group, so the states stay mutually exclusive. The UI offers Ignore on TP, FP and Pending rows alike, and an **Un-ignore** button on ignored ones. (Previously the button was conditional on Pending, so moving an FP to Ignored meant mapping it to some vuln, unmapping to get back to Pending, then ignoring; and nothing called the un-ignore path at all, so an ignored finding could only leave that state sideways by being marked FP.) Because ignoring can now discard a mapping or an FP grouping, the audit message names what went away (`… (dropped 2 existing matches)` / `… (was marked false positive)`)
- **Metrics**: Pending **and Ignored** findings are excluded from TP/FP. Ignored findings are neutral — they are neither TP nor FP, so precision/recall/F1 are unchanged by ignoring; they are also dropped from the scan-list Pending count and severity pills. `rematch` never auto-touches an ignored finding.
- **Compare page**: Pending and Ignored findings excluded from the FP matrix

The heuristic in `app/matching.py` is only the first pass — the CLI importer's LLM
makes the final call and corrects the match afterwards, including *clearing* a
match the heuristic wrongly applied (not just replacing it with a different
one — a gap fixed alongside the wildcard-vuln issue above). It also emits a
shared `fp_group` slug for false positives describing the same non-issue, and
a `reasoning` string per finding (`scan_findings.reasoning`, migration 035)
explaining why it did or didn't match — previously generated by the model and
printed to the terminal, but discarded before reaching the API.

Two matching modes based on finding content:

**DAST matching** (when finding has `url`):
Score based on vuln_type + URL pattern + http_method + parameter. If both finding and known vuln have URLs but they don't match, that candidate is skipped.

**SAST matching** (when finding has `filename` but no `url`):
Score based on vuln_type + filename exact match (case-insensitive).

### File Upload for Scan Submission

Scans can be submitted via file upload (JSON or CSV) in addition to manual form entry. If a file is uploaded, manual findings are ignored.

**JSON format:**
```json
{"findings": [{"vuln_type": "XSS", "http_method": "GET", "url": "/search", "parameter": "q"}, {"vuln_type": "Hardcoded Secret", "filename": "src/config.py"}]}
```

**CSV format:**
```
vuln_type,http_method,url,parameter,filename
XSS,GET,/search,q,
Hardcoded Secret,,,,src/config.py
```

### Metrics Computation

All metrics come from ONE pure function, `compute_metrics()` in `app/scoring.py` —
no DB access, no live app state. `app/services/scoring.py` fetches its inputs;
`scans.py` and `dashboard.py` consume its output. See **Scoring and Measurement**
below for the full normative definition; the summary:

```
TP        = count of UNIQUE matched vulns IN SCOPE (multiple findings on one vuln = 1 TP)
FP        = count of findings where is_false_positive = 1        (raw, kept for continuity)
FP groups = distinct fp_group among FPs + 1 per ungrouped FP     (used by precision)
Pending   = findings with NO finding_matches rows at all
            AND is_false_positive = 0 AND is_ignored = 0
            -- a finding matched DIRECTLY to a chain is fully resolved, not
            -- awaiting adjudication (real incident, scan 273: precision showed
            -- a range with "N pending" while the findings list had zero
            -- pending rows, because this check only looked at matched_vuln_id)
Ignored   = findings where is_ignored = 1  (neutral — excluded from precision/recall/F1)
FN        = in-scope vulns NOT matched by any finding in this scan

precision_upper = TP / (TP + FPgroups)                      -- every pending turns out real
precision_lower = TP / (TP + FPgroups + Pending)            -- every pending turns out an FP
recall          = TP / (TP + FN)
f1              = 2 * precision_upper * recall / (…)        -- upper bound, so F1 is
                                                            -- unchanged for adjudicated scans
weighted_found  = Σ over in-scope vulns and chains of impact_weight × credit
weighted_total  = Σ over in-scope vulns and chains of impact_weight
weighted_rate   = weighted_found / weighted_total            -- THE HEADLINE METRIC

severity_checked  = TP  -- every true positive is adjudicable, whether or not it reported a severity
severity_correct  = of those, count where the finding reported a severity == the vuln's ground-truth severity
severity_accuracy = severity_correct / severity_checked      -- 0 when severity_checked is 0
```

**A matched vuln always earns its full weight** — a match IS the evidence, there is no
partial credit. **A chain earns its full weight only when every member is matched** —
matching members independently is NOT evidence the chain was walked, so a chain with only
some members matched earns nothing; there is no separate chain-level credit tracking.

**TP counts unique vulns, not findings.** If 3 scanner findings all match the same known vuln, TP=1. This prevents inflated precision when scanners report the same vuln multiple times (e.g., "Missing CSP", "Missing HSTS", "Missing X-Frame-Options" all matching TP-016 "Missing Security Headers"). In the scan list SQL, this uses `COUNT(DISTINCT fm.vuln_id)` over `finding_matches`.
The converse also holds since migration 040: one finding may match SEVERAL vulns, and it
contributes one TP per distinct vuln. That keeps the metric symmetric — a scan that reports
one finding covering three vulns scores exactly the same as one that reports three findings
covering one each, so the score depends on what was demonstrated and not on how the report
was split up (locked in by `test_scoring.py`).

**FPs are clustered the same way.** Counting TP per vuln while counting FP per finding
made precision non-comparable across tools with different reporting granularity — three
findings on one real vuln scored 1 TP, three on one bogus issue scored 3 FP. Precision
uses `fp_groups`; the raw count is still shown beneath it when the two differ.

**Precision is a range until adjudication completes.** A scan with 5 TP, 0 FP and 50
pending findings used to report precision = 1.0 with nothing signalling that it was
meaningless. The bounds converge as findings are adjudicated; `adjudication_complete`
(pending == 0) says whether they have, and the comparison view suppresses the single
value until they do.

**Duplicate indicator:** When multiple findings match the same vuln, a badge shows "N findings" next to the matched vuln link.

**Severity accuracy** measures rating quality, not detection: of ALL TP findings, the
fraction whose reported severity exactly matches the matched vuln's ground-truth
`severity`. The denominator (`severity_checked`) is always `TP`, not just the findings
that happened to report a severity — a finding that reported no severity at all counts
against the scanner, the same as one that reported the wrong severity, since giving no
usable rating is still a failure to rate rather than a neutral non-event. (Before
2026-09-07, findings with no severity were excluded from the denominator entirely, which
let a scanner that reports severity on almost none of its findings show a misleadingly
high percentage — e.g. 8/9 = 88.9% when the scanner actually rated only 8 of its 35 true
positives.) The UI always shows `correct/checked` alongside the percentage rather than the
percentage alone. Detecting a critical SQLi and calling it "low" is a materially different
failure than a silent miss, and until this metric existed nothing on the comparison page
could see that difference.

Displayed in a metrics-grid: Weighted Detection (orange, headline, with `found/total pts`
beneath), TP (green), FP clusters (red), FN (red), Ignored (muted), Precision (orange, or a
yellow `lower–upper` range when unadjudicated), Recall/F1 (orange). Below it, the
difficulty-tier matrix. The heading carries `app@revN`.

---

## Scoring and Measurement

Normative. Vulnapps' primary use case is measuring how scanner/agent configurations
perform against curated ground truth, with the methodology published so third parties can
reproduce it. That demands more than count-based TP/FP/FN: ground truth has to be
versioned so a metric can be recomputed at the revision it was measured against.

### Weight scale (1 / 3 / 9 / 27)

| Weight | Class | Examples |
|---|---|---|
| 1 | Informational | version disclosure, verbose errors, missing headers |
| 3 | Medium | reflected XSS, open redirect, unauthenticated read of non-sensitive data |
| 9 | High | IDOR exposing another tenant's data, stored XSS with session theft, SSRF to internal service, single-step authz bypass |
| 27 | Critical | chained exploit reaching admin, cross-tenant write, auth bypass, RCE, business logic abuse with financial impact |

Log spacing is deliberate: with linear weights, nine informational findings would outscore
two criticals.

**`impact_weight` derives from `severity`.** Ground-truth severity IS contextual severity:
TP-013 is a directory listing, Low by convention, but in TaintedPort it exposes
`database.db` and the JWT signing key, so it is *stored* as critical. Once severity means
"what this is worth in this application", the map is 1:1 (info/low→1, medium→3, high→9,
critical→27) and there is no remaining case where the two should diverge. The column is
still stored because the revision scheme needs an immutable per-revision value, and an
explicit override is accepted, but it is exceptional rather than expected.

Write-path rule: a payload that omits `impact_weight` leaves the stored value alone — the
inline table editor sends only the columns it knows about — *unless* `severity` changed, in
which case the weight follows the new severity. A changed weight opens a `weight_change`
revision either way.

Why it matters — two configurations on a 30-vuln corpus worth 382 points:

| Config | Raw count | Weighted |
|---|---|---|
| A: all 12 commodity + 4 business logic (3 high, 1 crit) | 16/30 = 53% | 94/382 = 25% |
| B: 6 commodity + 9 business logic (5 high, 4 crit) + 2 chained | 17/30 = 57% | 227/382 = 59% |

Indistinguishable on raw counts, 2.4x apart weighted. `tests/test_scoring.py` reproduces
both figures exactly and fails if the scale or credit rules stop separating them.

### Difficulty tiers

`commodity` | `business_logic` | `chained`. **A reporting axis, never a multiplier** —
blending difficulty into the weight yields one opaque number and destroys the diagnostic.
The point is to see *where on the difficulty curve* a configuration improved.

**The split is about the nature of the defect, not about how findable it happens to
be.** `commodity` is a technical/input-handling flaw — injection, protocol,
crypto-implementation, config — a bug that exists independent of what this particular
app does. `business_logic` is a missing or client-trusted authorization/business-rule
check.

One refinement, settled 2026-09-28 for TaintedPort #53/#54 (SHA-256 length
extension on the tracking link, CBC bit-flip on the gift card): a crypto flaw in a token
**whose exploitation needs knowing what the app put inside it** is `business_logic`. A
scanner can flag the weak construction but not what to forge — which order id to
append, which bytes are the amount. What decides the tier is whether exploiting it needs
knowledge of this app, not the CWE family.

The business-logic side was corrected mid-session after TaintedPort's own BOLA/BFLA/BOPLA/mass-
assignment vulns (#17/18/20/22/24/25) were initially left `commodity` on the reasoning
that "a dedicated tool exists that checks for this OWASP API category" — that reasoning
doesn't hold: every such tool still has to be told, per endpoint, what's self-scoped and
what a privileged field is, which is exactly the "understanding what the app is for"
the tier exists to name, not a way around it. All six were reclassified to
`business_logic`, alongside TP-019/021/033/034 (price/discount/purchase/email-uniqueness
business rules — no generic technique substitutes for knowing this app's actual rule)
and TP-023/036 (each *contingent* on another vuln to be exploitable at all, and
mistagged `chained`/`commodity` on their own before this review — see **Exploit
chains** below). Default reporting view:

```
Tier             Ground truth   Found   Weighted rate
Commodity                  12      12            100%
Business logic             14       4             29%
Chained                     4       0              0%
Weighted total         382 pts     16             25%
```

Chains are reported in the `chained` row alongside vulns tagged `chained`. **This row is not a
4th bucket of the vuln count** — `commodity + business_logic` always equals `TP + FN` on its
own; `chained` is additional weight layered on top (each chain's own members are already
counted once under their own tier), which is why the tiers can sum to more than the vuln
total. The Compare Scans page surfaces this via a ⓘ hover tooltip on the "Chained" row label
(same `tooltip-wrap` pattern as the other metric labels), since seeing e.g. `27 + 14 + 4 = 45`
next to `41` known vulns without that context reads as a bug.

### Exploit chains

A chain is its own ground-truth entity with its own weight; its members keep their
individual weights.

**What counts as a chain (normative, settled on scan 330):** a sequence of distinct flaws
where each step hands the next what it needs, ending in an outcome none of the steps reaches
alone. *Several independent ways to the same outcome* is not a chain ("each of these alone
drives the order total to zero") — credit every vuln the finding shows instead. A step that
is attacker work rather than a flaw (cracking a hash the chain leaked, computing a TOTP code
from a stolen seed, self-registering) does not disqualify a chain; it is simply not a member,
and how likely it is to succeed (e.g. a weak password policy) informs the chain's severity.
No chain may depend on the app's deliberately published test credentials.

**Severity (migration 041).** `chains.severity` is what a curator sets; `impact_weight`
derives from it 1:1 exactly as for vulns (critical 27, high 9, medium 3, low 1). Before 041
chains stored only a weight, so every chain read as Critical by construction; the migration
backfills severity from the weight. `chains._severity_and_weight` resolves a write: severity
wins, a weight-only (pre-041) caller gets the severity derived back, an update with neither
keeps the chain's own. A severity change is a weight change and opens a `weight_change`
revision. The Chained tier's `found_by_severity` uses the chain's severity.

**Chain reports (`scan_findings.is_chain`, migration 041).** Whether a finding presents
itself as a chain, decided from its CONTENT, never from which folder of the report it came
from — scanners mix chain write-ups in with single-vuln findings. The importer's model sets
`is_chain`; `_enforce_chain_flag` is the mechanical backstop (an unflagged finding can never
be chain-credited; a flagged one matched to a chain keeps the chain as primary and any stray
primary vuln moves into `additional_vuln_db_ids`). The folder name survives only as a prompt
hint, which still helps against splitting one chain write-up into a finding per step. It
replaced `_enforce_source_kind`, which hard-cleared chain matches outside the chains folder.
A flagged finding whose chain is not registered still credits every vuln it demonstrates.
Mapping a finding to a chain sets the flag; unmapping never clears it. The Findings list
shows a `chain` marker.

**Promote → Chain** (`POST /api/scans/{id}/findings/{fid}/promote-chain`,
`scans.promote_finding_to_chain`). For a real chain the catalog is missing: registers it via
`chains.create_chain` (title defaults from the finding, severity, ≥2 existing member vulns in
step order), which opens a revision, then maps the finding to it while keeping any vulns it
already credits, flags it `is_chain`, and clears FP/ignored. A step the catalog lacks is
promoted as a vuln first, so every member is a flaw some scan showed. Before this, a novel
chain could only be marked FP — scan 330 lost three that way (3 of its 5 FP groups).
Offered on any finding not already matched to a chain.

**Editing.** The app page's Chains section (`AppDetail.jsx` `Chains`, sharing
`components/ChainForm.jsx` with Promote → Chain) shows severity and edits severity, title,
steps and description, and adds new chains. The scan page's chain section is titled
**Chain Credit**: it is the ground-truth scorecard (every chain, with found / confirmable /
missing status), whereas the scanner's own chain reports appear in Findings. The partial double-count is deliberate: demonstrating a chain end to
end is worth more than finding its parts separately.

**Vulns and chains are asymmetric on purpose:**

> For a vuln, the match IS the evidence. For a chain, matching its members is NOT evidence
> of chaining.

A chain is credited its full weight only when EVERY member is matched; otherwise it
contributes zero — there is no partial chain credit. The chain's weight sits *on top of*
its members, and that double count is only defensible when the chain requires all of its
members to actually be demonstrated together. The chain still sits in `weighted_total`, so
an unmatched chain costs points rather than vanishing.

**`difficulty_tier='chained'` is not a substitute for a real chain.** Until
`app/services/chains.py` existed, `chains`/`chain_members` had no write path at all — the
tables existed (migration 028) but nothing could ever populate them, so the only way a scan
could get "chained"-tier credit was a single vuln mistagged `difficulty_tier='chained'`. That
is exactly backwards: it lets a scanner earn chain-tier credit for flagging one isolated
finding, with no requirement that it ever demonstrated a multi-step pivot. The rule going
forward — reached after TaintedPort's TP-036 ("Pass-the-Hash") was found mistagged this
way: **a vuln whose exploitability has an external precondition (e.g. "needs a password hash
obtained elsewhere") is rated on its own standalone risk** (which is usually lower than the
"if fully chained" scenario — TP-036 dropped from `high`/`chained` to `medium`/`business_logic`
after this review), **and the amplified impact is only ever captured by registering a real
chain** whose members are the *other*, independently-tracked vulns that supply the
precondition. A scanner earns the chain's extra credit only by matching every member — i.e.
only by actually finding the precondition-supplying vuln too, never by flagging the
downstream vuln alone. The same review applied to TP-023 ("JWT Claim Forgery"): the
`AdminController` trusting a JWT's `is_admin` claim is inert on its own — it only matters
once something can forge/tamper that claim (TP-011 "none"-alg, TP-012 signature-not-verified)
or steal the real signing secret (TP-027 SSRF + CODE-001 hardcoded secret) — so it was
likewise downgraded standalone and re-expressed as three separate two-member chains (one per
independent path in), rather than one vuln carrying `critical`/`chained` for an outcome it
cannot produce by itself.

**Chain CRUD** (`app/services/chains.py`, `app/routers/api/chains.py`) — the only write path
for `chains`/`chain_members`:

| Method | Route | Notes |
|---|---|---|
| GET | `/api/apps/{id}/chains` | List chains with resolved, ordered `members` (`vuln_code`, `vuln_title`, `step_order`) |
| POST | `/api/apps/{id}/chains` | Create. Body: `chain_id` (auto-generated `CHAIN-NNN` if omitted), `title`, `description`, `impact_weight` (required, 1\|3\|9\|27), `member_vuln_ids` (≥2, must belong to this app). Opens a `new_prior_vuln` revision, same as adding a vuln |
| PUT | `/api/apps/{id}/chains/{pk}` | Full update — title/description/weight/members. A weight change opens a `weight_change` revision |
| DELETE | `/api/apps/{id}/chains/{pk}` | Hard delete |

All three require app write access + `full` API scope, and log to `audit_log`
(`entity_type='chain'`, actions `chain_created`/`chain_updated`/`chain_deleted`) exactly like
vuln CRUD.

**Chain credit requires explicit evidence that the chain itself was identified — matching
every member is necessary but never sufficient.** `compute_metrics()`'s original rule
(migration 028) inferred credit purely from "every member matched." On real scan data this
credited chains that were never actually demonstrated: two independent findings each
matched a different member with zero connection between them (confirmed by reading the
finding text — one matched finding's own description explicitly said *"independent of SQL
injection"* about the very chain it was credited for). A chain now earns credit one of two
ways:

1. **Direct match (automatic).** A finding is matched straight to the chain itself (a
   `finding_matches` row carrying `chain_id`). This is for the case where the scanner's own
   report contains ONE finding that itself narrates combining >=2 members into the bigger
   exploit — first-class evidence, same trust level as any vuln match, no separate review
   required. Available via `POST /api/scans/{id}/findings/{finding_id}/match` (put the chain
   in `chain_ids`), manually through the chip picker on the scan detail page, or
   automatically from `tools/import_scan.py`'s LLM mapping (see below). Since migration 040
   the SAME finding may additionally credit the member vulns it demonstrably walked through
   — the chain and the members are separate assertions, and crediting a member is never
   inferred from the chain match.
2. **Explicit human confirmation (manual fallback).** Migration 038's
   `scan_chain_credits(scan_id, chain_pk, credited_by, credited_at, notes)` — for when no
   single finding was tagged directly. Nothing is ever auto-populated into this table; a
   reviewer must read the scan's actual finding text and decide it narrates the pivot.

| Method | Route | Notes |
|---|---|---|
| POST | `/api/scans/{id}/chains/{chain_pk}/confirm` | Manual confirm. Body (optional): `{notes}`. **400** if every member isn't matched by this scan yet |
| DELETE | `/api/scans/{id}/chains/{chain_pk}/confirm` | Revoke a manual confirmation — reverts to 0 credit (does not affect a direct match; unmatch the finding for that) |

Both require scan write access + `vuln-mapper` scope, log to `audit_log`
(actions `chain_credit_confirmed`/`chain_credit_revoked`), same access rule as
match/mark-fp. UI: the scan detail page's **Chains** section lists each in-scope chain, its
members with per-member match status, and status `✓ Credited (direct match)` /
`✓ Confirmed` (+ Revoke) / a Confirm button (once eligible) / "members not all matched" —
this is also where a reviewer reads the finding text before manually confirming. The
Compare Scans page has a read-only **Chains** table showing every chain × every compared
scanner (`✓ confirmed` / `✗`) — a chain either scored its weight or it didn't, so there is no
third "matched, unconfirmed" glyph implying a scored in-between state. When every member
matched independently but the chain itself was never credited, the `✗` cell's tooltip says so
(and points to the scan detail page to review), but the visible glyph never implies a scored
outcome that didn't happen. The app detail page also lists
**Chains** (name, weight, linked members) alongside the Vulnerabilities table, so a chain
is never missing from the one place ground truth is browsed.

**LLM-assisted import** (`tools/import_scan.py`) is taught about registered chains: the
mapping prompt includes a "Known Exploit Chains" section (`format_chains_for_prompt`) and
an explicit rule to set `matched_chain_db_id` ONLY when a single finding's own text narrates
the pivot end to end — never merely because the report separately covers each member. The
rule quotes the real false-credit incident (SSRF finding + hardcoded-secret finding, no
cross-reference) as the negative example. `validate_llm_matches` hallucination-guards
`matched_chain_db_id` the same way it does `matched_vuln_db_id`, and rejects a finding that
set both (keeps the chain match, clears the vuln match). `print_mapping_table` shows a
separate "CHAIN MATCHED — review these carefully" section so a rare, high-stakes match is
never buried among ordinary ones before the operator submits.

That prompt-only rule was not enough on its own (real incident, 2026-09-21): a standalone
SSRF finding that only *stated* a further step's consequence ("with this secret one could
forge tokens...") without demonstrating it, and a deserialization finding that explicitly
said the RCE step was "not performed per rules of engagement", both got `matched_chain_db_id`
anyway; a password-reset-log finding that explicitly said the combined takeover is "scored
separately" was ALSO chain-credited despite disclaiming that itself; and conversely a
genuine chain write-up got split into one finding per mechanism, each matched to an
individual vuln, losing the chain credit the file was written to earn. `SYSTEM_PROMPT_MAP`
now spells out those three exact "claims/withholds/defers, doesn't demonstrate" phrasings as
things that must NOT justify chain credit — a directory-independent, content-based rule that
applies to every scan report regardless of how it's organized.

On top of that, when a scan's own report layout separates dedicated chain write-ups from
standalone findings into different directories (not guaranteed for every scan, but true of
this importer's usual source), `_discover_findings_dirs` already reads both, and each file's
containing directory name (`"chain" in dirname.lower()`) is passed through the whole
per-file pipeline as `is_chain_source` — a secondary, report-specific signal layered on top
of the content rule, not a replacement for it. It does two things: the prompt (in
`_build_user_message`) tells the model which of the two a file was *authored* as, including
telling a chain file not to split its narrative into per-mechanism findings; and
`_enforce_source_kind` mechanically force-clears whichever field that source type is never
allowed to populate — the PRIMARY `matched_vuln_db_id` on a chain file, `matched_chain_db_id`
on a standalone one — regardless of what the model returned. That backstop can only ever
downgrade a wrong credit to unmatched, never manufacture a wrong one, so it costs nothing
even for a scan whose directory layout turns out not to carry this meaning. It is no longer
symmetrical: a chain file may still credit the member vulns it walked through via
`additional_vuln_db_ids` (below), so only its primary vuln match is cleared.

**`additional_vuln_db_ids` — one finding crediting several vulns.** Alongside the primary
`matched_vuln_db_id` / `matched_chain_db_id`, a finding carries a list of everything ELSE its
own evidence demonstrates, which the importer submits as one match set (see
`finding_matches`, migration 040). Two shapes recur: a finding whose subject is one bug but
whose PoC also establishes another known vuln (the scan-330 directory listing that quotes the
hardcoded secret out of `jwt.php`), and a chain finding naming the members it walked through
(so the chain and its members are both credited from the one finding).

The bar is the same as for any other match — the finding's own text must demonstrate that
specific mechanism — with one carve-out learned from a live dry run. Given the rule above,
the model credited the hardcoded-secret vuln (right: the secret's *value* was quoted) and the
admin-trusts-the-claim vuln (right: the finding forged a token and got a live `200` from
`/admin/orders`), but ALSO the `alg:none` and signature-not-verified vulns purely because the
*disclosed source code contained* them. Unbounded, one file dump would sweep up most of the
catalogue. So the prompt now distinguishes by what kind of claim the vuln makes: if the vuln
IS the presence of something in source (a hardcoded secret, credential, key), quoting it
demonstrates it completely; if the vuln is a claim about how the running app BEHAVES
(`alg:none` is accepted, a signature mismatch is tolerated, an endpoint skips authorization),
only an actual request/response in that finding counts — reading code that contains the bug
is a strong argument it exists, but not evidence this scan exercised it.
`validate_llm_matches` additionally applies the hallucination guard to every id in the list,
dedupes, and drops any that repeat the primary.

### Ground-truth revisions

`ground_truth_revisions`, one sequence per app.
Reasons: `new_prior_vuln`, `weight_change`, `vuln_invalidated`, `corpus_change`.

Each vuln carries two revision fields, and they mean different things:
- `existed_since_revision` — when the flaw was present in the application. Drives scope.
- `known_since_revision` — when we learned about it. Audit only.

**Scope rule.** A vuln (or chain) is in scope for scoring scan *S* at revision *R* when:

```
existed_since_revision <= R                                    -- known ground truth at R
AND existed_since_revision <= S.corpus_revision                 -- existed when S ran
AND (invalidated_at_revision IS NULL OR invalidated_at_revision > R)
```

The second clause is not in the original design and is not optional: without it, a vuln
introduced by a code change (`existed_since = N`) would count as a miss for every older
scan the moment they were re-scored at revision N — a decline the scanner did not cause.
A vuln that "existed all along" (`existed_since = 1`) still reaches every scan, which is
exactly the retroactive re-scoring that is wanted. In the compare matrix, an out-of-scope
cell renders `n/a`, not `✗`.

**Promotion rule.** Promoting a discovery finding into a vuln always opens a revision
(`new_prior_vuln`) and the operator MUST state which case it is — the API rejects the
request otherwise, and the UI disables the submit button until a radio is chosen:
- *existed all along* → `existed_since_revision = 1`, `known_since_revision = N`. Every
  prior scan legitimately takes the miss once re-scored.
- *introduced by a code change* → `existed_since_revision = N`. Prior scans untouched.

**Weights are immutable within a revision.** Changing an `impact_weight` opens a
`weight_change` revision. Changing a `difficulty_tier` does not — it never moves the
weighted total.

**Revision churn control.** A corpus change on an app with NO scans stays on the current
revision: there is no history to preserve, so authoring 28 seed vulns does not create 28
revisions. From the first scan onward, every corpus change opens one.

**Invalidation replaces deletion.** A vuln that any finding matched cannot be deleted
(409) — that would rewrite history and orphan the finding. `POST /api/apps/{id}/vulns/{vid}/invalidate`
opens a `vuln_invalidated` revision and stamps `invalidated_at_revision`, so the vuln stays
in scope for earlier revisions while the current revision drops it.

Metrics are always computed live — there is no persisted scoring history — so a number can
shift over time as ground truth grows, including retroactively if a vuln is promoted as
"existed all along". This is correct: every chart and table is labelled with the revision
it was scored at, because an unlabelled downward shift reads as a regression when it may
just be a bigger corpus.

**Benchmark-corpus and weight-review flags.** Migration 024 derived weights from severity
for ~55k vulns across 217 apps — fine for apps nobody is curating. `apps.benchmark_verified`
marks an app whose vulns have actually been hand-reviewed (set via App edit → "Benchmark
corpus", or `PUT /api/apps/{id}`; never inferred from name/version, since this database has
duplicate app names). `vulnerabilities.weight_verified` marks one vuln's severity/tier as
hand-confirmed rather than still carrying the migration-024 backfill/placeholder; any write
path that states a tier explicitly sets it, including re-confirming `commodity`. Both are
informational badges on the App page today — no export/aggregation feature currently reads
them (see `tasks/scorings-table.md` and `tasks/config-fingerprinting.md` for the deferred
work that would).

### Scan list coverage row

The scan list has no summed "Total" row: it added TP and FN across scans, so a vuln found by
five scans counted five times and FN repeated the catalog once per scan. In its place, when
**every listed scan is for the same app** (a new version of an app is a new app id, so this
is exact), `list_scans` returns `coverage` and the list shows "Any of these N scans":
distinct catalog vulns found by at least one of them (`found / total`, with the C/H/M/L
split), and the ones missed by all, linked. Computed server-side in one query over the
listed scan ids (`_coverage`), against the current catalog -- the same scope as the rows'
own `tp_count`. With more than one app listed, `coverage` is null and there is no row.

### TP split by severity

`tp` alone is ambiguous — 45 true positives reads very differently as 8 criticals than as 8
lows. Both the scan list (`ScansList.jsx`, beside the TP cell and in the totals row) and the
comparison table (`ScanCompare.jsx`, under the TP row) show the split inline: `45  8C 19H 14M 4L`.

Normative rules:

- **Catalog severity, never the scanner's.** `tp` counts *distinct matched vulns*, so the
  vuln row carries the authoritative label — the same side `impact_weight` comes from. A
  scanner calling a medium bug critical must not move it between buckets; that gap is what
  `severity_accuracy` measures, and folding it in here would hide it.
- **The buckets must sum to the `tp` shown beside them.** All five severities are always
  present (zero-initialised), matching the `severity_counts` convention on the app detail
  payload. `info` is hidden in the UI when zero.
- Counted per distinct vuln, not per finding: two findings hitting one vuln is one TP.

The scan detail page's **Difficulty Tiers** table shows the same split in its Found
column, per tier: each bucket in `metrics.tiers` carries `found_by_severity`, summing to that
tier's `found`. Chains have no severity column, only `impact_weight`, so the Chained row maps
the weight back (27→critical, 9→high, 3→medium, 1→low). The Weighted-total row uses
`tp_by_severity`, so it sums to `tp` (vulns only) like the number beside it — not to the tier
rows, whose Chained row counts chains. All three surfaces render through
`components/SeverityBreakdown.jsx`.

Three producers, kept deliberately in agreement (`tests/test_tp_severity_and_ignore.py`
pins this):

1. `compute_metrics` returns `tp_by_severity`, built from `in_scope_matched` — the canonical one.
2. `list_scans` computes `tp_critical..tp_info` in SQL, mirroring `tp_subquery`'s scope
   exactly so the plain list view's breakdown matches its own `tp_count`. (The SQL `tp` and
   the scorer's `tp` can differ — the SQL one omits the `existed_since_revision` rule.) When
   `include_metrics=True` the service overwrites those columns with the scorer's split,
   because the frontend also swaps in the scorer's `tp_count` there. `tp_by_severity` itself
   is stripped from the `metrics` payload, which stays scalar-only: the grouped view averages
   every field in it.
3. `ScanCompare.jsx` derives its own from `filteredMatrix`/`tpRows`, so the split follows the
   page's severity filter instead of contradicting it.

### Reporting guards

`GET /api/apps/{id}/compare` returns a `guards` payload and the UI renders a warning
banner — advisory only, never blocking: hard-refusing an exploratory comparison would break
day-to-day use, including looking at an old scan next to a new one, which is how you notice
ground truth moved. Guards: mixed `corpus_revision` among the compared scans;
adjudication-incomplete scans, which suppresses the single precision value in the UI in
favor of the lower–upper range.

### Editable Scan Metadata

`PUT /api/scans/{id}` allows updating `scanner_name`, `scan_date`, `authenticated`, and `notes` on an existing scan. Requires scan write access and `vuln-mapper` API key scope.

### Rematch Endpoint

`POST /api/scans/{id}/rematch` — Re-runs automatic matching for all findings in a scan. Requires scan write access. Re-matches ALL findings including manually mapped and manually marked FP ones. Returns `{"ok": true, "updated": count}`.

Use case: After splitting a coarse-grained vuln into finer ones, re-match picks up the new vulns.

### Split/Refine Workflow

Users can create fine-grained vulns from any finding — including ones already matched to a coarse vuln. After creating new vulns, "Re-match All" re-runs matching so findings map to the more specific vulns.

---

## Scan Comparison

Comparison page at `/apps/:id/compare` (API: `GET /api/apps/{id}/compare?scans=1,2,3`).

**Features:**
- No scan limit for comparison (select any number of scans)
- Severity filter toggles that recalculate metrics dynamically
- Horizontal scroll with sticky columns for the detection matrix
- Cost/tokens shown in comparison when available (private, only shown to authorized users)
- Scans ordered by date in the selector

**Comparison data includes:**
- **Reporting guards banner** (top): warns on mixed corpus revisions among the
  compared scans, and on incomplete adjudication. Advisory only — never blocking.
- **Metrics Table**: Weighted Detection (headline, with `found/total pts`), TP,
  FP clusters, FN, Pending, Precision (a `lower–upper` range while unadjudicated),
  Recall, F1, Severity Accuracy (`correct/checked`, `-` when nothing was
  checkable), and a per-tier detection breakdown. Color-coded: green >=70%,
  yellow >=40%, red <40%. The 🏆 marks the highest **weighted** rate, not the
  highest F1.
- **Coverage & Quality Shape**: a radar/spider chart, one small-multiple panel
  per scanner (`TierRadar`/`RadarPanel` in `ScanCompare.jsx`), shown right after
  the Metrics Table. Axes, clockwise from the top: Commodity / Business logic /
  Chained rate (same gating as the table's tier rows — hidden under a severity
  filter, and a tier axis only appears if some compared scan's ground truth
  actually has vulns in it), then Severity Accuracy / Precision (`precision_upper`)
  / Weighted Detection (always shown). One polygon per panel rather than N
  overlaid on one chart — this page allows comparing an unbounded number of
  scans, and overlaid same-hue polygons stop being tellable-apart long before
  that; each panel's own title carries scanner identity instead. All panels
  share the app's single accent hue; the weighted-detection winner's panel gets
  an accent-colored border + 🏆 instead of a background wash — a background tint
  over the panel's own near-black surface flattened the grid-line contrast to
  the point the rings became illegible, so the winner is marked by a ring, not
  a fill. Hover a vertex for the exact rate + `found/total` (or `correct/checked`
  for Severity Accuracy).
  **Column alignment:** best-effort, not guaranteed — a `ResizeObserver` on the
  Metrics Table's header row measures each scanner `<th>`'s actual rendered
  width plus the sticky label column's width; when available, the radar panels
  render in a matching non-wrapping row (leading spacer + one fixed-width slot
  per scanner) so panel N sits under table column N, with its own
  `.compare-scroll` horizontal scroll for when the table itself needs one. Falls
  back to the plain responsive `card-grid` (auto-fill, wraps on narrow screens)
  whenever widths haven't been measured yet.
- **Detection Matrix**: Rows = known vulnerabilities (with weight and tier),
  Columns = scanners. Checkmark (found), X (missed), or `n/a` where the vuln
  postdates that run. Coverage summary per vuln counts only applicable scans.
- **False Positives Table**: FPs grouped by scanner with vuln_type, method, URL, parameter.
- **Trend chart**: an inline-SVG scatter shown at the **end** of the comparison
  (after the detection/FP matrices), via `TrendChart` in `ScanCompare.jsx`.
  X = scan date (multiple `YY-MM-DD` ticks), Y = the selected metric (fixed 0–100%
  axis) — Weighted Detection by default, F1 one click away. One accent point per
  scan, directly labeled with the scanner name (labels are vertically de-collided
  with leader lines when points crowd), plus a **least-squares trend line**
  (dashed, clipped to the plot) and a hover tooltip
  (`scanner · YY-MM-DD · metric%`). Values are read from the severity-filtered
  metrics, so the chart recomputes live with the filter. Single series → no
  legend; no charting dependency. The chart carries the `app@revN` label, because
  scores drift downward as ground truth grows and an unlabelled downward trend
  reads as a regression.
- Scanner names in comparison link to scan detail page

Under a severity filter the metrics are recomputed client-side from the matrix
(vulns only — chains are excluded and the heading says so). Unfiltered, the
server's live-computed numbers are used verbatim.

---

## Scan Labels

User-defined, color-coded tags for organizing scans.

- **Labels table**: `id`, `name` (unique), `color` (hex, default orange)
- **Junction table**: `scan_labels(scan_id, label_id)` — many-to-many
- **Badge display**: Color-coded badges in scans list and scan detail
- **Filtering**: Scans list supports `?label=` filter
- **Management**: Admin can CRUD labels globally via `/api/admin/labels`. Any user with scan write access can attach/remove *existing* labels on a scan. *Creating* a new label name (not just attaching one) additionally requires being a global admin or a team admin/contributor on the app's own team — a private app's own creator does not qualify on their own.
- **CLI support**: `--labels` flag on import_scan.py for auto-labeling (labels auto-created if they don't exist and the submitting user/key qualifies to create one, per the rule above; otherwise the label name is silently skipped, not an error)

---

## App Visibility

Apps have a `visibility` field: `public` (default), `team`, or `private`.

- **public**: visible to everyone (including unauthenticated users)
- **team**: visible only to members of the assigned team + creator + admin
- **private**: visible only to creator + admin

`app/visibility.py` provides `app_visibility_filter(user)` which returns a SQL WHERE clause and params for filtering. Applied in app list and app detail queries.

---

## Teams

Users can create teams and add members by email. Team creator becomes team admin.
Team admins (and app admins) can add/remove members and change member roles (admin/contributor/view).

---

## Scan Visibility

- `scans.is_public` defaults to `1` (visible to all)
- User can set to `0` (private) — only visible to the submitter, team members, and admins
- `app/visibility.py` provides `scan_visibility_filter(user)` which includes:
  - Unauthenticated: public scans on public apps only
  - Logged in: public scans + own scans + scans on team apps
  - Admin: all scans

---

## History Log

Append-only audit trail of operations on scan findings and on app
vulnerabilities (ground truth). Scoped to exactly two consumers: a "History
Log" section at the end of `ScanDetail.jsx` and one at the end of
`AppDetail.jsx` — no audit logging anywhere else in the app.

**Table** (`audit_log`, migration 036): `entity_type` (`scan_finding` |
`vulnerability`), `entity_id` (nullable — null for bulk/aggregate events),
`scan_id`/`app_id` (whichever applies, `ON DELETE CASCADE`), `action`,
`actor_id`, a **pre-rendered** human-readable `message`, an optional JSON
`details` blob, `created_at`. The message is rendered once, at write time
(`app/services/audit.py::record_audit_event`) — not templated from
structured fields by the frontend — because the actor's name, the matched
vuln's title, or its `vuln_id` slug can all change after the fact, and a log
entry must keep describing what happened at the time, not what's true now.

**Gating**: "visible only to contributors and admin" is implemented by
reusing each page's existing write-access check (`can_edit` on `get_scan`
in `ScanDetail`, on `get_app` in `AppDetail`) rather than a role check —
this app has no account-level `contributor`/`viewer` role today (migration
012 collapsed them into `user`; `contributor`/`viewer` only exist as *team*
roles, scoped to one team). Per-resource write access — global admin, or
the scan submitter/app creator, or a team member whose team role is
`admin`/`contributor` — is exactly that population. Enforced server-side on
`GET /api/scans/{id}/history` and `GET /api/apps/{id}/history` (403/404 for
anyone else); the frontend `HistoryLog` component additionally only renders
for a `canView`-true caller, but that's UI polish, not the access boundary.

**What's logged** (one row per human action; bulk/algorithmic operations get
one aggregate row, never one per affected item):
- Scan-scoped: `finding_matched`, `finding_unmatched` (`match_finding` — new
  match, changed match, or a match cleared entirely), `finding_marked_fp`,
  `finding_marked_ignored`/`finding_unignored`, `finding_promoted` (also
  writes an app-scoped `vuln_created` row from the same call), `scan_rematched`
  (one row for the whole "Re-match All" click, only if anything changed)
- App-scoped: `vuln_created`, `vuln_updated` (lists which fields changed —
  old → new for short scalar fields like severity/weight/tier, just the
  field name for long free-text ones; a no-op update logs nothing),
  `vuln_deleted`, `vuln_invalidated`, `vulns_imported` (one row per bulk
  import call), `revision_opened` (only the standalone "open a revision"
  endpoint — the four vuln-mutation call sites that also open one fold it
  into their own message instead of emitting a second row)

**Not touched by this feature**: the existing `ground_truth_revisions`
table and `AppDetail.jsx`'s `GroundTruth` panel — that stays exactly as it
was (ungated, revision-only, near the top of the page); the new gated
History Log is a separate section at the bottom.

---

## CSS Classes Reference

**Layout:** `.container`, `.page-header`, `.page-title`, `.card`, `.card-grid`, `.card-header`, `.card-title`
**Buttons:** `.btn`, `.btn-primary` (orange), `.btn-outline`, `.btn-danger`, `.btn-sm`
**Forms:** `.form-group`, `.form-label`, `.form-input`, `.form-select`, `.form-textarea`, `.form-row` (2-col grid), `.form-check`
**Tables:** `.table-wrap`, `table`, `th`, `td`
**Badges:** `.badge`, `.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-info`, `.badge-pending`, `.badge-user`, `.badge-admin`, `.badge-contributor`, `.badge-view`, `.badge-member` (legacy)
**Metrics:** `.metrics-grid`, `.metric-card`, `.metric-value`, `.metric-label`
**Text:** `.text-success`, `.text-error`, `.text-warning`, `.text-accent`, `.text-muted`, `.text-secondary`, `.text-sm`, `.text-xs`, `.font-mono`
**Alerts:** `.alert`, `.alert-error`, `.alert-success`
**Inline Edit:** `.cell-editable`, `.inline-input`, `.btn-icon`, `.btn-icon-danger`, `.btn-save`, `.vuln-row`
**Other:** `.detail-grid`, `.detail-label`, `.detail-value`, `.search-box`, `.empty-state`, `.hero`, `.hero-actions`, `.pagination`
**Spacing:** `.mt-1`/`.mt-2`/`.mt-3`, `.mb-1`/`.mb-2`, `.flex`, `.items-center`, `.gap-1`/`.gap-2`, `.justify-between`

---

## CLI Scan Importer (`tools/import_scan.py`)

LLM-assisted CLI tool to import scan results (.md files) into Vulnapps.

**Usage:**
```bash
python tools/import_scan.py --url https://vulnapps.example.com \
    --api-key va_... --app-id 1 --dir ./scan-results/
```

**Two phases, and why (normative, 2026-09-28).**
1. **Extract** — one call per report file with `SYSTEM_PROMPT_EXTRACT`, which **never contains
   the catalog**. One entry per finding the file reports: never merged, split, invented or
   dropped; the report's own title verbatim; severity as the report assigns it; the PoC's
   evidence (requests, responses, values, steps) kept rather than summarised. The file's
   folder is a soft hint here only (keep a chain write-up as one finding). Default model
   `claude-sonnet-5` (`--extract-model`).
2. **Map** — `SYSTEM_PROMPT_MAP` gets the catalog plus a **numbered** batch of extracted
   findings (`--map-batch-size`, default 20) and returns only `mappings[]` keyed by `index`.
   `merge_mappings` enforces the guarantee: the answer must cover exactly the numbers it was
   given (missing / extra / duplicated → `MappingMismatch`, one retry, then the import stops
   with extraction checkpointed), and only `MAPPING_FIELDS` (vuln / chain / additional ids,
   `is_chain`, `fp_group`, `reasoning`) are taken — nothing the mapper returns can rewrite a
   title, description, PoC or severity. `is_false_positive` is OR-ed: the mapper can flag,
   never un-flag, what the report called false. `_enforce_chain_flag` then runs on the merged
   result. Default model `claude-opus-5` (`--map-model`); `--model` sets both.

Why: ten TaintedPort scans arrived pre-mapped by a scanner's own publishing step, which wrote
one finding per catalog entry while looking at the catalog — duplicates vanished and bodies
were copied from the wrong source finding. The importer used to have the same shape (one call
per file extracting AND mapping with the catalog in view). Measured on the scan-330 report
(61 files) the split is also cheaper: ~481k input tokens vs ~1,064k, because the catalog and
rules (~11.5k tokens) go out once per mapping batch instead of once per file. Per-phase token
use is printed after every import ("LLM usage — this import, not the scan"). The mapping
prompt also dropped its dead "milestones" block (nothing read it since the scoring prune).

API calls to `claude-opus-5` / `claude-fable-5-1` on the first-party API opt into server-side
refusal fallbacks (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`): exploit
write-ups can trip safety classifiers, and a declined request is re-run on the recommended
model rather than failing the import. A final `stop_reason: "refusal"` raises instead of being
read as an empty result.

**KPIs in the CLI output.** Every import ends with the scan's headline numbers — weighted
detection (points found / total), TP with its C/H/M/L split, FP groups (and raw FP count when
they differ), FN, pending, precision (a lower–upper range while anything is pending, never the
flattering bound alone), recall, F1, severity accuracy, and the per-tier found / total with
weighted rate and severity split. After a real import they are **vulnapps' own** numbers for the
new scan (`GET /api/scans/{id}`); with `--dry-run`, where nothing is submitted, the importer
computes them locally with `app.scoring.compute_metrics` against the current catalog
(`local_metrics`) and labels them a preview. `tests/test_cli_kpis.py` submits the same mapped
findings through the real service and asserts every KPI, per-tier and per-severity split
included, is identical — the preview is only worth showing if it is the number the scan page
will show.

**`--format json` (a.k.a. `--output json`), with `--dry-run`.** Prints the whole import
grounding as one JSON object on stdout, so a sweep can be scripted: each finding carries its
display fields (title/severity/description/poc/...), its raw mapping decision
(`matched_vuln_db_id`, `additional_vuln_db_ids`, `matched_chain_db_id`, `is_chain`, fp) and
the resolved catalog identifiers (`catalog_ids`/`catalog_chain_ids` as codes like TP-014 /
CHAIN-011, `catalog_db_ids`/`catalog_chain_db_ids` as numbers), plus the `metrics` KPI block
from `local_metrics`. In this mode all human output is rerouted to stderr (sys.stdout is
pointed at stderr for the run), so stdout is clean JSON safe to pipe into jq; the metrics are
passed through `_json_safe` because `compute_metrics` returns some fields as sets. It requires
`--dry-run` today (a real import has interactive prompts that would block a piped run) and
errors otherwise.

**Provenance.** Every scan records who imported and mapped it (migration 042):
`imported_by` ("vulnapps import_scan", or "vulnapps web form" from the submit page),
`importer_version` (v`VERSION`.`commit count` of the importer's own checkout — the app's
version scheme), `importer_commit` (short sha, `-dirty` when the tree has uncommitted changes),
`extractor_version` / `matcher_version` (`llm-api:<model>`) and the sha256 of each phase's
prompt, plus the run details the importer always sent and the server used to drop
(model_version, reasoning_effort, harness_version, token_budget, seed, run_group,
trial_index). `clean_run_details` whitelists and types them. The scan page shows
"Imported By"; a null `imported_by` renders as **unknown**, which is exactly what the
pre-mapped scans would have shown. The scan's `tokens` never falls back to the importer's own
LLM usage (it used to): that is the cost of importing, not of the scan.

**Features:**
- Reads one or more `.md` scan result files (combines into single scan via `--dir`)
- `--dir` accepts the project/run root, not just the findings dir directly: `_discover_findings_dirs` finds the right subdirectory/subdirectories to read. If ANY immediate child directory contains `.md` files, ALL such children are used together (a standardized report layout splits findings across siblings like `vulnerabilities/` + `vulnerability_chains/`, and both matter — chunked, one LLM call per file). Only when no child has `.md` files does it fall back to `.md` files at the root itself, then to a child whose name/contents mention "report". A real incident: a root with both a big combined `report.md` AND per-finding subdirectories used to let the combined file win outright, forcing one giant non-chunked LLM call whose response came back too large to parse as valid JSON.
- Sends scan content + known vulns to Claude for mapping (streamed response — non-streaming calls stall on the 600s read timeout for detail-rich reports; cap is 16384 output tokens)
- Displays colored mapping table (matched, unmatched, FP)
- Submits scan and applies LLM match corrections
- Auto-captures LLM token count from response
- Supports `--labels` for auto-labeling scans
- If a metrics-stream file (see below) is found anywhere under `--dir`, reads authoritative cost/tokens/duration/start-time/model from it instead of relying on the LLM to read them out of report prose

**Key flags:**
| Flag | Description |
|------|-------------|
| `--url` | Vulnapps instance URL (required) |
| `--api-key` | API key (or `VULNAPPS_API_KEY` env var) |
| `--app-id` | Target app ID (required) |
| `--dir` | Directory with `.md` files (combined into one scan) |
| `--file` | Single `.md` file to import |
| `--scanner` | Override LLM-detected scanner name |
| `--scan-start` | Override LLM/stats-detected start time (`YYYY-MM-DD HH:MM`, plain `YYYY-MM-DD` also accepted) |
| `--scan-model` | Model that PERFORMED the scan (overrides the value read from the report/metrics-stream file); auto-added as a label |
| `--authenticated` | Mark scan as authenticated (overrides LLM detection) |
| `--unauthenticated` | Mark scan as unauthenticated (overrides LLM detection) |
| `--public` | Make scan public (default: private) |
| `--labels` | Comma-separated labels (auto-created if missing) |
| `--confirm` | Ask for confirmation before submitting (default: auto-submit) |
| `--cost` | Scan cost in USD (private field) |
| `--tokens` | Token count (auto-captured from LLM if not set) |
| `--duration` | Scan duration in minutes (private field) |
| `--notes` | Notes to attach to the scan |
| `--model` | Claude model (default: `claude-sonnet-4-6` mapping, `claude-haiku-4-5` extract-only) |
| `--provider` | `anthropic` or `vertex` (auto-detected from `CLAUDE_CODE_USE_VERTEX=1`) |
| `--vertex-region` | Vertex AI region (or `ANTHROPIC_VERTEX_LOCATION`) |
| `--vertex-project` | GCP project ID (or `ANTHROPIC_VERTEX_PROJECT_ID`) |
| `--extra-info-extract` | Extra operator instructions appended to the extraction prompt (used when the app has no known vulns yet to map against) |
| `--extra-info-mapping` | Extra operator instructions appended to the mapping prompt (used once the app has known vulns to map against) |
| `--dry-run` | Show mapping without submitting |
| `--skip-state` | Don't zip/upload `--dir` as scan state |
| `--upload-state-for <scan_id>` | Skip mapping entirely — just (re-)upload `--dir` as scan state for an already-submitted scan (retry after a state-upload failure) |

**LLM provider:** Supports both Anthropic direct API and Google Vertex AI. Auto-detects from `CLAUDE_CODE_USE_VERTEX=1` env var.

**Operator steering (`--extra-info-extract` / `--extra-info-mapping`):** free-text appended
to the prompt as a distinct "Additional Instructions From The Operator" section, right before
the scan report. Only one applies per call — `--extra-info-extract` when the app has no known
vulns yet (extraction-only mode), `--extra-info-mapping` once it does (mapping mode) — since
each run is already in exactly one of those two modes (`run_llm_mapping`/`run_llm_mapping_cli`
switch on whether `vulns` is empty). The section is explicitly scoped as informing judgment
calls, not overriding the mandatory JSON schema or rules above it. Both the streaming-API path
and the `--use-cli` subprocess path build this section through the same shared
`_build_user_message` helper, so the two never drift apart.

**Scan metadata from a metrics-stream file (`_find_stats_files`, `_read_scan_stats`,
`_scan_date_from_iso`):** the scanning tool that produces a report (e.g. `ai-pentest-agent`)
may separately emit an append-only JSONL metrics stream (schema:
`ai-pentest-agent/docs/contracts/stats.schema.json`, conventionally named `stats.jsonl`) that
is *not* part of the report's own JSON/markdown at all. Real incident (2026-09-21): before
this, cost/tokens/duration/model stayed empty on the submitted scan unless the operator
passed `--cost`/`--tokens`/`--duration`/`--scan-model` by hand every time, because the
importer had no way to see this data — the report text itself never states it. `stats.jsonl`
is a convention from the one tool we've seen emit this, not a contract every scanner has to
follow, so `_find_stats_files` locates the file by *content* (any `.jsonl` file under `--dir`,
searched recursively, skipping hidden/underscore directories, whose first record is a dict
with an `"event"` key) rather than by that exact filename or top-level placement — a
differently-named or nested file is still picked up. `_read_scan_stats` then reads the last
`run_snapshot` record marked `"final": true` across all matched files (falling back to the
last snapshot seen, with a warning, if the run was interrupted before one was written) and
extracts `cost_usd`, `tokens_used`, `duration_seconds`, `started_at`, and the set of every
agent's `model_name`. Precedence for each field is: explicit CLI flag (`--cost`/`--tokens`/
`--duration`/`--scan-start`/`--scan-model`) > metrics-stream file (deterministic, not an LLM
guess) > value the LLM extracted from the report text. Before submitting, the importer prints
this metadata for review — including which file(s) it actually read it from, since the name
is no longer guaranteed — and flags any model name found there that isn't already in
`--labels`, offering to add it. It then asks about cost/tokens/duration/start-date **one
field at a time** (`_stats_fields_to_confirm`), skipping a field entirely when the operator
already settled it via the matching CLI flag. Real incident (2026-09-21): an earlier version
asked one bundled yes/no for all four fields — an operator who'd already passed `--duration`
explicitly (the scanning tool recorded wall time until they manually exited, not real scan
time) still wanted cost/tokens accepted from the file, but declining the bundled question
discarded all four fields *and aborted the entire submission* after the LLM mapping pass had
already run. Per-field confirmation fixes both problems: declining one field only drops that
field back to the next item in its precedence chain, and only a real Ctrl-C/EOF aborts the
run — a plain "no" never does.

**Retrying a failed state upload (`--upload-state-for`):** the scan-state zip (of the whole
`--dir`) is uploaded as the last step of a normal import, after the scan itself is already
submitted — so a failure there (e.g. nginx's `client_max_body_size` rejecting a large bundle
with a 413, see the CLI Scan Importer's operational notes) doesn't lose any mapping work, but
previously had no retry path short of re-running the whole LLM pass. `--upload-state-for
<scan_id>` skips mapping/import entirely and just zips `--dir` and uploads it for an
already-submitted scan, sharing the same `_upload_scan_state` helper the normal flow uses.

---

## Running (Local Development)

### Backend
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend (development)
```bash
cd frontend
npm install
npm run dev
```
Vite dev server runs on port 5173 and proxies `/api` and `/static` to the backend on port 8000.

### Frontend (production build)
```bash
cd frontend
npm run build
```
Output goes to `frontend/dist/`, which FastAPI serves automatically.

First registered user becomes admin. Database auto-creates on startup.

---

## App Version (`app/version.py`, `VERSION` file, `/api/version`)

Displayed next to the "Vulnapps" heading on the home page (`frontend/src/pages/Home.jsx`)
as `v<major>.<minor>`. `major` is a hand-set number in the `VERSION` file at the repo root
(bump it manually for a deliberate release); `minor` is the number of commits to `main`, so it
advances automatically on every merge without anyone having to remember to touch anything.

`app/version.py`'s `get_app_version()` reads `VERSION` for the major number. For minor, the
deployed Docker image has no `.git` to compute a commit count from at runtime (`.git/` is
excluded from the build context by `.dockerignore`, and the Dockerfile never does a broad
`COPY . .` that would pull it in anyway) — so whichever build path builds the image computes
`git rev-list --count HEAD` (or `main`, the same commit for a push-to-main build) on the build
host (where `.git` *is* available) and passes it to `docker build` as `--build-arg
COMMIT_COUNT=...`, which the Dockerfile bakes into a `COMMIT_COUNT` file inside the image.
There are two such build paths, both must pass this build-arg or minor silently reads back as
`0`: `build.sh` (manual local build/push) and `.github/workflows/deploy.yml`'s "Build image and
check startup" step (the actual auto-deploy-on-push-to-main path — see **Automated
deployment** below), which also needs `fetch-depth: 0` on its checkout since a shallow clone
would make the commit count always come back as 1. `get_app_version()` reads that baked file
when present; local dev (running uvicorn
directly from a git checkout, no baked file) falls back to asking git directly. Either way
resolves to `"0"` if neither source is available, rather than crashing.

`GET /api/version` (in `app/main.py`, alongside the existing `/api` root endpoint; no auth
required, matching that same public-metadata pattern) returns `{"version": "v1.153"}`.
`Home.jsx` fetches it on mount and renders it as a muted `.hero-version` span next to the
`<h1>`, styled after `TaintedPort`'s own `v1.35` version tag next to its hero heading.

## Change Log (`app/changelog.py`, `tools/gen_changelog.py`, `/api/admin/changelog`)

Admin → **Change Log** (`/admin/changelog`, `frontend/src/pages/AdminChangelog.jsx`). Because
the version's minor number IS the commit count (see **App Version** above), every commit on
`main` is a release, and the change log is the commit log with the matching version attached.

**One line per release by default** — version, time, subject — expanding on click to at most
3 bullets plus SHA and author, with expand/collapse all. The first cut rendered every commit
body in full and 189 releases became a wall of text. The payload carries `bullets`, never the
raw `body` (129KB → 70KB); the commit itself stays the place for full prose.

`summarise()` takes the opening sentence of each paragraph, since commit bodies are written
a-point-per-paragraph and the blank lines are the only structure available. Hard-wrapped
lines are rejoined (git's 72-char breaks are not sentence breaks), a lead sentence under
`LEAD_FLOOR` absorbs the one after it (a transitional opener is not the point of its
paragraph), trailers like `Co-Authored-By:` are dropped, and bullets are capped at
`MAX_BULLETS` / `MAX_BULLET_CHARS` with word-boundary truncation. This is extraction, not
comprehension: a paragraph opening on a weak sentence still yields a weak bullet and nothing
in the heuristic can tell. It buys a scannable page, not a written summary.

The minor number for a given commit is that commit's own **ancestor count**, which is *not*
its position in `git log` — with merge commits the two diverge, and numbering the log top to
bottom would silently misnumber every entry below the first merge. `_ancestor_counts()` gets
the whole parent graph in one `git rev-list --parents` call and computes reachability with
integer bitmasks, so `v1.171` here is the same commit the running app reports as `v1.171`.
Merge commits are kept (they increment the version, so dropping them would break the
mapping) but flagged `is_merge` and collapsed behind a toggle in the UI.

Same no-`.git`-in-the-image problem as the version, solved the same way:
`tools/gen_changelog.py` writes `CHANGELOG.json` on the build host and both build paths run
it before `docker build` (`build.sh`, and the deploy workflow's "Build image and check
startup" step). The Dockerfile copies it with the optional-source form `COPY CHANGELOG.jso[n]
./` so a build without the generator still succeeds; `get_changelog()` then reads the baked
file if present, falls back to git for local dev, and returns `[]` rather than raising when
neither exists. `CHANGELOG.json` is gitignored — it is a build artifact, not source.
`build_entries()` falls back from `main` to `HEAD` because a CI checkout of a pull request is
detached and has no local `main`.

`GET /api/admin/changelog` returns `{"version", "entries"}` and is admin-only (`_require_admin`,
like the rest of `app/routers/api/admin.py`) — commit messages describe internals that the
app's own pages do not.

## Docker Deployment

### Dockerfile (Multi-Stage Build)

```dockerfile
# Stage 1: Build React frontend
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package*.json .
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Python backend + built frontend
FROM python:3.12-slim
WORKDIR /app

# Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY migrations/ migrations/
COPY VERSION .

# Commit count to main, computed on the build host (by build.sh) and passed
# in since .git isn't in the build context -- see "App Version" above.
ARG COMMIT_COUNT=0
RUN echo "$COMMIT_COUNT" > COMMIT_COUNT

# Copy built frontend from Stage 1
COPY --from=frontend /frontend/dist frontend/dist

# Data volume for SQLite persistence
VOLUME /data
ENV DATABASE_PATH=/data/vulnapps.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**`docker-compose.yml`**
```yaml
services:
  vulnapps:
    build: .
    container_name: vulnapps
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - vulnapps-data:/data
    env_file:
      - .env
    environment:
      - DATABASE_PATH=/data/vulnapps.db

volumes:
  vulnapps-data:
```

**`.env.example`** (copy to `.env` and customize)
```
SECRET_KEY=change-me-to-a-random-string
DATABASE_PATH=/data/vulnapps.db
TOKEN_EXPIRY_HOURS=24
```

**`.dockerignore`** — Excludes `__pycache__/`, `*.py[cod]`, `venv/`, `.venv/`, `.git/`, `*.db`, `*.sqlite3`, `.env`, `.env.local`, `.coverage`, `htmlcov/`, `.pytest_cache/`, `.DS_Store`, `*.pem`, `*.log`, `tasks/`, `tests/`, `CLAUDE.md`, `AppBuilder.md`, `LICENSE`, `README.md`

### Deploy to EC2

```bash
# First time setup
git clone <repo-url> vulnapps && cd vulnapps
cp .env.example .env
# Edit .env — set a strong SECRET_KEY
docker compose up -d --build
```

### Update Workflow

```bash
cd vulnapps
git pull
docker compose up -d --build
```

The named volume `vulnapps-data` persists the SQLite database across container rebuilds. Data survives `docker compose down` — only `docker volume rm vulnapps_vulnapps-data` would delete it.

### Production Deployment (EC2 alongside TaintedPort)

Same pattern as TaintedPort: build locally for linux/amd64, push to Docker Hub, pull on EC2.

- **Container port:** `8001` on host (TaintedPort uses `8080`)
- **Docker Hub image:** `nunoloureiro/vulnapps:latest`
- **Host nginx** proxies domain to `127.0.0.1:8001` (`docker/nginx-host-vulnapps.conf`)
- **Data persists** via named volume `vulnapps-data`

**`aws/setup-ec2.sh`** — Installs Docker (if needed), pulls the `VULNAPPS_IMAGE` image from Docker Hub, creates the data volume, and runs the container on `127.0.0.1:8001`. Accepts an optional Docker env-file for CI and manual updates; without it, uses the shell's SECRET_KEY or generates one. Snapshots an existing database before replacement and checks API startup.

**`docker/nginx-host-vulnapps.conf`** — Host nginx virtual host config. Server name set to `vulnapps.net`.

**`DeployInstructions.txt`** — Quick reference for local build/push and EC2 update commands.

#### Local Build & Push
```bash
docker build --platform linux/amd64 --build-arg COMMIT_COUNT="$(git rev-list --count main)" -t nunoloureiro/vulnapps:latest .
docker push nunoloureiro/vulnapps:latest
```
(`./build.sh` does this already — see **App Version** above for why the build-arg matters.)

#### EC2 Update
```bash
sudo docker pull nunoloureiro/vulnapps:latest
sudo docker stop vulnapps; sudo docker rm vulnapps
sudo docker run -d --name vulnapps --restart unless-stopped \
    -p 127.0.0.1:8001:8000 -v vulnapps-data:/data \
    -e SECRET_KEY="YOUR_SECRET_KEY" -e DATABASE_PATH=/data/vulnapps.db \
    vulnapps:latest
```

## Automated deployment

GitHub Actions must test and build pull requests and deploy successful `main`
pushes in `nunoloureiro/vulnapps`, with a manual trigger for `main`. Checkout uses
`fetch-depth: 0` (full history, not the default shallow clone) so the commit count
below is real. Run the
self-contained pytest suite (exclude the production-database-dependent
`test_api_endpoints.py`), build the existing Dockerfile for linux/amd64 — passing
`--build-arg COMMIT_COUNT="$(git rev-list --count HEAD)"` so the deployed app reports
the right version (see **App Version** above) — and
check API and frontend startup before publishing. Supply Docker Hub and SSH
credentials through repository secrets. Use SSH `accept-new` with a temporary
known-hosts file per deployment; no saved host-key secret is required. Store application
settings in individual `SECRET_KEY`, `TOKEN_EXPIRY_HOURS`, and `MAX_STATE_SIZE`
secrets, and assemble the Docker env-file in CI as documented in README.md.
Serialize runs and deploy the published
image by digest through the existing `aws/setup-ec2.sh`, preserving `vulnapps-data` and the
existing loopback port `8001`. Take a SQLite database snapshot before container
replacement, fail the run on startup failure, and update `latest` only after
successful deployment. Do not automatically reverse database migrations.
After successful startup, prune dangling Docker images on EC2 with
`docker image prune -f`. Leave volumes intact and warn without failing deployment
if image cleanup fails. No cleanup is needed on the ephemeral Actions runner.

### Scan list discovery and grouping

The scans page uses searchable, keyboard-accessible comboboxes for labels, scanners, apps,
and teams. Labels support multi-selection with removable chips and an explicit match-all
(default) or match-any control; other filters remain single-select. Typing narrows choices,
arrow keys navigate, Enter selects, and Escape dismisses. Show empty-options feedback and
clear controls. Preserve repeated `label` query parameters and `label_match=all|any` in the
URL, including backward compatibility for existing single-label links.

The `group_by` URL parameter selects scanner, app, label, or no grouping. Grouping shows an
aggregation table first: scan count and per-scan statistics for TP, FP, pending, and FN: mean, sample standard
deviation (denominator n−1), min–max range, and visible measured/total sample counts.
Exclude missing metrics; show an em dash for missing means or standard deviations with
fewer than two observations. Retain valid zero values. Groups sort alphabetically; expand a row to inspect and
sort its underlying scans. Label grouping includes each scan in every assigned label group,
with a No labels group for unlabeled scans. Group counts overlap; the overall count and bulk
selection count unique scans. Selecting a group's scans preserves selection in other groups.
Changing filters clears selection. Ignore stale network responses and offer retry on failure.

A separate `npm run dev:mock` frontend command previews these interactions with synthetic
scans and no backend dependency. The preview visibly identifies mock data, uses separate
auth storage, serves allowlisted local assets, and never forwards API requests to a backend.

The desktop scan-discovery UI separates filters from a two-option results view: Individual
scans (default) and Grouped summary. Reset filters preserves the results view. Grouped summaries
offer Quality and Counts: count-based precision, recall, and F1 are calculated for each scan
then macro-averaged, while Counts shows TP, FP, pending, and FN. Exclude undefined ratios.
Display mean ± sample standard deviation, min–max beneath, and measured/total counts when data
is incomplete. Explain formulas and caveats in an expandable methodology note. Scores exclude
pending findings and remain provisional while any are pending; these descriptive statistics
do not establish controlled comparisons across different app versions or benchmark corpora.

Additional grouping options separate scanner versions or the combination of app ID, scanner
name/version, and exact label-name set (independent of label order). Missing versions are
explicitly unknown. Show app and labels beneath each configuration group name. These are
recorded configurations, not proof that unrecorded settings match. Every metric displays
n=measured/total, including complete and singleton samples. Describe small samples as
descriptive variation rather than evidence of performance differences.

Quality summaries default to Weighted, with an explicit Unweighted toggle saved as
`weighting=unweighted` in the URL. Weighted shows canonical impact-weighted detection,
reviewed weighted F₀.₅ and weighted precision (see Reviewed weighted F₀.₅ below). Unweighted shows
count-based precision, recall, and F1 from the same current-revision scorer. Each scan
remains equally weighted when aggregating scores. Zero available points yields unavailable
detection, not zero percent. Reset filters preserves the scoring choice.

All scan list views request `include_metrics=true`. The service batches authorized scans' scoring
inputs, shares corpus/revision reads, and calls the canonical scoring implementation. Individual rows and grouped drill-downs show sortable Weighted Detection
(credited / available impact points, plus percentage) and Cost / point (USD scan cost divided
by credited points, four decimals). Include chain credit and use the current benchmark scorer.
Show an em dash for missing scores, hidden/missing costs, or zero credited points in the cost
ratio; preserve valid zero cost. Cost visibility follows the existing API permissions.
Leave the combined coverage footer's new metric cells empty: individual weighted scores must
not be summed across scans. Failed list requests clear stale results and
show the load error rather than a misleading successful empty state.

Scan result payloads are keyed by API query and authenticated user. Render results only after
the matching request succeeds, including when entering grouped mode to load canonical metrics;
keep filter controls mounted while loading. Ignore superseded responses and distinguish load
failures from successful empty lists. When canonical metrics are present, use their TP, grouped
FP, pending, and FN counts consistently for summary statistics, sorting, and drill-down rows.
Autocomplete search results never include the reset action; Enter with no matches preserves
current selections. Explicit clear controls remain available.

Grouped metrics show observed Best/Worst values per metric (higher is better for detection,
TP and points found; lower is better for FP/FN/pending). Available corpus points use neutral
Min/Max labels. These are within-group extremes, not rankings or necessarily the same scan
across metrics. Keep sample counts visible. Hide Team when an app is selected, ignore any
team restriction in app-scoped links, and remove stale team restrictions when changing or
clearing App. The team filter remains available in the cross-app list.

### Run performance chart
The scans page has an optional Performance chart view independent of grouping. Each point
represents one filtered scan; History still controls all runs versus latest per scanner/app.
Default axes are cost in USD and reviewed weighted F₀.₅. X can switch to wall-clock duration in
minutes. Y offers conservative F0.5, adjudicated precision, recall, F1, and impact-weighted
detection (including chain credit). Conservative F0.5 uses
1.25 TP / (1.25 TP + 0.25 FN + clustered FP + pending), prioritizes precision, and is undefined
without a benchmark corpus. This follows testbed's unresolved-item penalty with vulnapps'
canonical clustered FP units. Weighted F₀.₅ is the default chart score; FP penalties follow the policy below.
Use canonical current-revision metrics. Missing or unauthorized cost/duration and undefined
scores are excluded, counted visibly, never plotted as zero. Zero cost and zero scores remain
valid. Colors identify scanners. Hover/focus reveals a run; clicking/selecting opens its
metrics and a scan-detail link. Provide an accessible run selector for coincident points.
Keep quality on a fixed 0–100% axis, resource use on a zero-based linear axis, and explain
that the upper left is preferable. Filters and axis/view selections are shareable in the URL.
Mixed app/corpus comparisons are descriptive; pending quality is provisional. List endpoints
must redact cost, tokens, duration, and notes using scan-detail visibility rules.

The scatter chart includes a green dashed upper-left guide for higher quality and lower
cost/shorter duration. This is a directional visual cue, not a scoring threshold.


### Team app navigation
The team detail page (`/teams/:id`) includes a View Apps link in its header
for every team member and application admin. Use the existing outline small
button style and link to `/apps?filter=team%3A{id}` so the existing Apps page
shows that team's apps using its current cards and team filter.

## Reviewed weighted F₀.₅

The Individual scans tab retains the full diagnostic table: Scanner, App (when
unscoped), Date, TP, FP, Pending, FN, Weighted Detection (credited / available points
and percentage), Cost / point, Severity, and Labels. It has no Quality/Counts switch
or weighted F₀.₅ headline. Grouped summaries retain Quality/Counts controls and the
reviewed weighted F₀.₅ metrics described below. Expanded groups use the same full
scan table as Individual scans.

Let T be credited impact, A available corpus impact and E clustered FP penalties.
Use existing 1/3/9/27 ground-truth weights and confirmed-chain credit; each vulnerability
and each credited chain counts once. Chains remain separately weighted corpus items.

- Weighted recall/detection = T/A.
- Weighted precision = T/(T+E).
- Weighted F₀.₅ = 1.25T/(T + 0.25A + E).
- Reviewer FP penalties use 1/3/9/27, independently of scanner-reported severity.
  A cluster takes its maximum member penalty; ungrouped FPs cost individually.
- Headlines, sorting, chart points and group statistics require
  `weighted_score_provisional === false`. Incomplete or unknown review shows
  **Awaiting review**. Weighted detection remains available independently.
- Groups macro-average reviewed scores only, showing measured/total sample counts
  and awaiting-review counts. No reviewed samples shows Awaiting review.
- Detail exposes a closed Conservative estimate disclosure: missing FP reviews cost
  27 and each pending finding adds 27 (U). Estimated precision = T/(T+E+U); estimated
  F₀.₅ = 1.25T/(T+0.25A+E+U). These estimates never select a winner.
- Empty corpora yield null weighted precision/F₀.₅. No predictions yields undefined
  precision; a nonempty corpus with no detections yields F₀.₅ = 0.
- `weighted_f05_upper` / `weighted_precision_upper` omit pending penalties only,
  not forecasts of additional TP credit. These API fields are not displayed.

Migration 043 adds nullable `scan_findings.fp_impact_weight` constrained to 1/3/9/27.
Existing FPs remain unreviewed. The existing mark-fp endpoint accepts this field:
omission preserves the stored value, null resets review, and an integer sets the
penalty. Existing scan-write permissions and mapper scope apply; invalid input yields
400. Penalty changes enter the audit log. Matching, rematching, ignoring or promoting
a finding (to a vulnerability or chain) clears its FP penalty. Imports cannot assign
reviewer penalties. Existing count-based precision/recall/F1 remain unchanged.

Comparison shows canonical weighted F₀.₅ for the full corpus only. Severity filters
show Requires full corpus. The trophy selects the unique positive highest reviewed
weighted F₀.₅ only when all selected runs have scores; ties, one run, unreviewed or
missing scores, and severity filtering suppress the winner. Tooltips name its basis.
Scoring explanations are collapsed by default. Legacy cross-app dashboard/scanner
aggregates retain count metrics; weighted F₀.₅ is not inferred from pooled counts.

Weights express a review policy, not dollar costs. Compare runs within the same app
version and benchmark corpus. Mock previews use synthetic data and never modify
production.
