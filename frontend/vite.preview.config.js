import { defineConfig, mergeConfig } from 'vite';
import baseConfig from './vite.config.js';
import { readFileSync } from 'node:fs';

const logo = readFileSync(new URL('../app/static/logo.svg', import.meta.url));

const apps = [
  { id: 305, name: 'TaintedPort', version: '1.19', visibility: 'team', team_id: 1 },
  { id: 306, name: 'DemoBank', version: '2.0', visibility: 'team', team_id: 2 },
  { id: 307, name: 'DemoShop', version: '1.0', visibility: 'public', team_id: null },
];
const teams = [{ id: 1, name: 'Benchmark Lab' }, { id: 2, name: 'Research' }];
const scannerNames = ['AI PenTest Agent', 'ZAP', 'Burp Suite', 'Nuclei'];
const labelNames = [
  'blackbox', 'greybox', 'gpt-6-astra', 'claude-sonnet-4.6', 'gemini-pro',
  'thinking-high', 'thinking-medium', 'judge-verified', 'authenticated',
  'baseline', 'candidate', 'regression', 'nightly', 'manual-review',
  'used-browser', 'used-source', 'harness-v3', 'harness-v4',
  'long-label-to-check-filter-overflow-and-search',
];
const labels = labelNames.map((name, i) => ({
  id: i + 1, name, color: ['#f97316', '#3b82f6', '#8b5cf6', '#10b981'][i % 4],
}));
const scans = Array.from({ length: 18 }, (_, i) => {
  const app = apps[i < 12 ? 0 : i < 15 ? 1 : 2];
  const day = String(25 - Math.floor(i / 2)).padStart(2, '0');
  return {
    id: 9000 + i, app_id: app.id, app_name: app.name, app_version: app.version,
    scanner_name: scannerNames[i % 4], scanner_version: ['3.1', '2.16', '2026.9', '3.4'][i % 4],
    scan_date: `2026-09-${day} ${i % 2 ? '09:00' : '14:30'}`,
    created_at: `2026-09-${day}T${i % 2 ? '09:00' : '14:30'}:00Z`,
    submitted_by: 1, submitter_name: i % 2 ? 'Demo Reviewer' : 'Demo Researcher',
    tp_count: i === 11 ? null : 12 + i % 14, fp_count: i === 11 ? null : i % 4,
    fn_count: i === 11 ? null : 16 - i % 14, pending_count: i === 11 ? null : i % 3,
    sev_critical: i % 3, sev_high: 3 + i % 5, sev_medium: 5 + i % 4, sev_low: i % 4,
    cost: i === 11 ? null : 2.5 + i, tokens: i === 11 ? null : 100000 + i * 15000,
    duration: i === 11 ? null : 360 + i * 60, is_public: app.visibility === 'public',
  };
});
const scanLabels = Object.fromEntries(scans.map((scan, i) => [scan.id,
  i === 11 || i === 17 ? [] : [...new Set([
    i % 2, 2 + i % 3, 5 + i % 2, 7, 8 + i % 6, 14 + i % 5,
  ])].map(index => labels[index]).sort((a, b) => a.name.localeCompare(b.name)),
]));

function previewMetrics(scan) {
  const weighted_found = scan.tp_count === null ? null : scan.tp_count * (2 + scan.id % 3);
  const weighted_total = weighted_found === null ? null : 140;
  const unreviewed = scan.fp_count > 0 && scan.id % 3 === 0 ? 1 : 0;
  const penalty = weighted_found === null ? null : (scan.fp_count - unreviewed) * 3 + unreviewed * 27;
  const pending = weighted_found === null ? null : scan.pending_count * 27;
  const f05 = extra => weighted_found === null ? null : 1.25 * weighted_found / (weighted_found + .25 * weighted_total + penalty + extra);
  return {
    tp: scan.tp_count, fp_groups: scan.fp_count, fn: scan.fn_count, pending: scan.pending_count,
    weighted_found, weighted_total, weighted_fp_penalty: penalty, weighted_fp_unreviewed: unreviewed,
    weighted_f05: f05(pending), weighted_f05_upper: f05(0),
    weighted_precision: weighted_found === null ? null : weighted_found / (weighted_found + penalty + pending),
    weighted_precision_upper: weighted_found === null ? null : weighted_found / (weighted_found + penalty),
    weighted_score_provisional: scan.pending_count > 0 || unreviewed > 0,
  };
}

function scanResponse(params) {
  const appId = params.get('app_id');
  let rows = scans.filter(scan => {
    const app = apps.find(item => item.id === scan.app_id);
    const filter = params.get('filter');
    if (appId && String(scan.app_id) !== appId) return false;
    if (params.get('scanner') && scan.scanner_name !== params.get('scanner')) return false;
    const selectedLabels = [...new Set(params.getAll('label').filter(Boolean))];
    const hasLabel = name => scanLabels[scan.id].some(label => label.name === name);
    if (selectedLabels.length && !(params.get('label_match') === 'any'
      ? selectedLabels.some(hasLabel) : selectedLabels.every(hasLabel))) return false;
    if (['public', 'private', 'teams'].includes(filter) && app.visibility !== (filter === 'teams' ? 'team' : filter)) return false;
    if (filter?.startsWith('team:') && Number.isInteger(Number(filter.slice(5))) && app.team_id !== Number(filter.slice(5))) return false;
    const query = (params.get('q') || '').toLowerCase();
    return [scan.app_name, scan.scanner_name, scan.submitter_name].some(value => value.toLowerCase().includes(query));
  });
  if (params.get('latest')) {
    const seen = new Set();
    rows = [...rows].sort((a, b) => b.scan_date.localeCompare(a.scan_date) || b.created_at.localeCompare(a.created_at))
      .filter(scan => {
        const key = `${scan.scanner_name}:${scan.app_id}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }
  return {
    scans: rows.map((scan, i) => params.get('include_metrics') === 'true' ? {
      ...scan,
      metrics: previewMetrics(scan),
    } : scan).sort((a, b) => b.created_at.localeCompare(a.created_at)),
    scan_labels_map: Object.fromEntries(rows.map(scan => [scan.id, scanLabels[scan.id]])),
    scanners: [...new Set(scans.filter(scan => !appId || String(scan.app_id) === appId).map(scan => scan.scanner_name))].sort(),
    apps_list: [...apps].sort((a, b) => a.name.localeCompare(b.name)),
    all_labels: [...labelNames].sort(), user_teams: teams,
  };
}

const config = mergeConfig(baseConfig, defineConfig({
  plugins: [{
    name: 'synthetic-scan-preview',
    transform(code, id) {
      if (id.split('?')[0].endsWith('/src/api/client.js')) {
        return code.replaceAll("'token'", "'vulnapps.mock.token'");
      }
    },
    transformIndexHtml() {
      return [
        { tag: 'script', children: "localStorage.setItem('vulnapps.mock.token', 'synthetic-preview');", injectTo: 'head-prepend' },
        { tag: 'div', attrs: { role: 'status', style: 'padding:8px 16px;background:#7c2d12;color:#fff;text-align:center;font:13px system-ui;' }, children: 'LOCAL PREVIEW · Synthetic scan data · Read only · No backend connection', injectTo: 'body-prepend' },
      ];
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = new URL(req.url, 'http://localhost');
        if (url.pathname.startsWith('/static/')) {
          if (url.pathname === '/static/logo.svg' && ['GET', 'HEAD'].includes(req.method)) {
            res.setHeader('Content-Type', 'image/svg+xml');
            res.end(req.method === 'HEAD' ? undefined : logo);
          } else {
            res.statusCode = 404;
            res.end('Static asset not included in this preview.');
          }
          return;
        }
        if (url.pathname !== '/api' && !url.pathname.startsWith('/api/')) return next();
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        const send = (status, data) => { res.statusCode = status; res.end(JSON.stringify(data)); };
        if (req.method !== 'GET') return send(405, { detail: 'This synthetic preview is read only.' });
        if (url.pathname === '/api/auth/me') return send(200, { user: { id: 999, name: 'Demo Viewer', email: 'demo@example.invalid', role: 'viewer' } });
        if (url.pathname === '/api/teams') return send(200, { teams });
        if (url.pathname === '/api/scans') {
          if (url.searchParams.has('label_match') && !['all', 'any'].includes(url.searchParams.get('label_match'))) {
            return send(422, { detail: 'label_match must be all or any.' });
          }
          return send(200, scanResponse(url.searchParams));
        }
        return send(404, { detail: 'This endpoint is not part of the synthetic scan-list preview.' });
      });
    },
  }],
  server: { host: '127.0.0.1', port: 5174, strictPort: true },
}));
// This server never forwards requests to a real API or static backend.
config.server.proxy = {};
export default config;
