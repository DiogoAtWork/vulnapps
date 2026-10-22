import { useState, useEffect, useCallback, useRef } from 'react';
import { Badge } from '../components/Badge';
import { ChainForm } from '../components/ChainForm';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { HistoryLog } from '../components/HistoryLog';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export default function AppDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importMsg, setImportMsg] = useState(null);
  const [editingCell, setEditingCell] = useState(null);
  const fileInputRef = useRef(null);

  const fetchApp = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.get('/apps/' + id);
      setData(result);
    } catch (err) {
      setError(err.message || 'Failed to load app');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchApp(); }, [fetchApp]);

  async function handleDeleteVuln(vulnId) {
    if (!window.confirm('Delete this vulnerability?')) return;
    try {
      await api.del('/apps/' + id + '/vulns/' + vulnId);
      fetchApp();
    } catch (err) {
      setError(err.message || 'Failed to delete vulnerability');
    }
  }

  async function handleDeleteApp() {
    if (!data) return;
    const { app, vulns = [], scan_count = 0 } = data;
    const msg =
      `Delete app "${app.name}${app.version ? ' v' + app.version : ''}"?\n\n` +
      `This will permanently remove ${vulns.length} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} ` +
      `and ${scan_count} scan${scan_count === 1 ? '' : 's'} (with their findings).\n\n` +
      `This cannot be undone.`;
    if (!window.confirm(msg)) return;
    try {
      await api.del('/apps/' + id);
      navigate('/apps');
    } catch (err) {
      setError(err.message || 'Failed to delete app');
    }
  }

  async function handleImport(e) {
    e.preventDefault();
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    setImportMsg(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      // api.post attaches the JWT and handles FormData; result carries the
      // import audit fields {imported, skipped_over_cap, truncated_fields}.
      const result = await api.post('/apps/' + id + '/vulns/import', formData);
      const n = result.imported || 0;
      const base = `Imported ${n} vulnerabilit${n === 1 ? 'y' : 'ies'}`;

      // Surface the otherwise-silent caps loudly, as an error-level banner.
      const problems = [];
      if (result.skipped_over_cap > 0)
        problems.push(`${result.skipped_over_cap} row(s) were NOT imported — this app reached the per-app vulnerability limit`);
      if (result.truncated_fields > 0)
        problems.push(`${result.truncated_fields} field value(s) were truncated to the maximum length`);

      if (problems.length)
        setImportMsg({ level: 'error', text: `${base}. ⚠ ${problems.join('; ')}.` });
      else
        setImportMsg({ level: 'success', text: `${base}.` });

      fileInputRef.current.value = '';
      fetchApp();
    } catch (err) {
      setImportMsg({ level: 'error', text: 'Error: ' + (err.message || 'Import failed') });
    }
  }

  function startEdit(vulnId, field, currentValue) {
    setEditingCell({ vulnId, field, value: currentValue });
  }

  function cancelEdit() {
    setEditingCell(null);
  }

  async function saveEdit(vuln) {
    if (!editingCell) return;
    const { field, value } = editingCell;
    if (value === vuln[field]) {
      cancelEdit();
      return;
    }
    try {
      const body = {};
      // Send all required fields for full PUT update
      const fields = [
        'vuln_id', 'title', 'severity', 'vuln_type', 'http_method',
        'url', 'parameter', 'filename', 'line_number', 'description',
        'code_location', 'poc', 'remediation',
        // Scoring fields ride along so an inline title edit can't drop them.
        'impact_weight', 'difficulty_tier',
      ];
      for (const f of fields) {
        body[f] = vuln[f] || '';
      }
      body[field] = value;
      await api.put('/apps/' + id + '/vulns/' + vuln.id, body);
      cancelEdit();
      fetchApp();
    } catch (err) {
      setError(err.message || 'Failed to update');
      cancelEdit();
    }
  }

  if (loading) {
    return <div className="container"><div className="empty-state"><p>Loading...</p></div></div>;
  }

  if (error && !data) {
    return <div className="container"><div className="alert alert-error">{error}</div></div>;
  }

  if (!data) return null;

  const { app, vulns = [], chains = [], tech_stack = [], scan_count = 0, severity_counts = {}, can_edit, can_submit_scan } = data;
  const repositoryUrl = app.source_repository?.replace(/\/$/, '').replace(/\.git$/, '');
  const githubRepository = repositoryUrl && /^https?:\/\/github\.com\/[^/?#]+\/[^/?#]+$/i.test(repositoryUrl);
  const commitUrl = githubRepository && app.source_commit
    ? `${repositoryUrl}/commit/${app.source_commit}` : null;
  const directoryUrl = githubRepository && app.source_directory
    ? `${repositoryUrl}/tree/${app.source_commit || 'HEAD'}/${app.source_directory.split('/').map(encodeURIComponent).join('/')}` : null;
  // vuln_count is the true total from the server; vulns may be capped for very large apps.
  const vulnCount = data.vuln_count ?? vulns.length;

  function renderLocation(v) {
    if (v.url) return v.url;
    if (v.filename) return v.filename + (v.line_number ? ':' + v.line_number : '');
    return '';
  }

  function renderEditInput(vuln, field) {
    if (field === 'severity') {
      return (
        <select
          className="inline-input"
          value={editingCell.value}
          onChange={e => setEditingCell({ ...editingCell, value: e.target.value })}
          onBlur={() => saveEdit(vuln)}
          onKeyDown={e => { if (e.key === 'Escape') cancelEdit(); }}
          autoFocus
        >
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      );
    }
    return (
      <input
        className="inline-input"
        type="text"
        value={editingCell.value}
        onChange={e => setEditingCell({ ...editingCell, value: e.target.value })}
        onBlur={() => saveEdit(vuln)}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); saveEdit(vuln); }
          if (e.key === 'Escape') cancelEdit();
        }}
        autoFocus
      />
    );
  }

  function renderCell(vuln, field) {
    const isEditing = editingCell && editingCell.vulnId === vuln.id && editingCell.field === field;

    if (field === 'vuln_id') {
      return (
        <td
          data-label="ID"
          className={can_edit ? 'cell-editable font-mono text-sm' : 'font-mono text-sm'}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'vuln_id', vuln.vuln_id) : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : vuln.vuln_id}
        </td>
      );
    }
    if (field === 'title') {
      return (
        <td
          data-label="Title"
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? (e) => { if (e.target.tagName !== 'A') startEdit(vuln.id, 'title', vuln.title); } : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : <Link to={'/apps/' + id + '/vulns/' + vuln.id}>{vuln.title}</Link>}
        </td>
      );
    }
    if (field === 'severity') {
      return (
        <td
          data-label="Severity"
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'severity', vuln.severity) : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : <span className={'badge badge-' + vuln.severity}>{vuln.severity}</span>}
        </td>
      );
    }
    if (field === 'vuln_type') {
      return (
        <td
          data-label="Type"
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'vuln_type', vuln.vuln_type || '') : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : (vuln.vuln_type || '')}
        </td>
      );
    }
    return null;
  }

  return (
    <div className="container">
      {error && <div className="alert alert-error">{error}</div>}

      <div className="page-header">
        <h1 className="page-title">
          {app.name}
          {app.version && <span className="text-muted text-sm"> v{app.version}</span>}
        </h1>
        <div className="flex items-center gap-1">
          {can_edit && (
            <>
              <Link to={'/apps/' + id + '/edit'} className="btn btn-outline">Edit App</Link>
              <Link to={'/apps/' + id + '/vulns/new'} className="btn btn-primary">Add Vulnerability</Link>
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => setImportOpen(!importOpen)}
              >
                Import Vulns
              </button>
            </>
          )}
          {vulnCount > 0 && (
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => api.download('/apps/' + id + '/vulns/export', (app.name || 'app') + '-vulns.csv')}
            >
              Export CSV
            </button>
          )}
          {can_submit_scan && (
            <Link to={'/apps/' + id + '/scans/new'} className="btn btn-outline">Submit Scan</Link>
          )}
          {user && (
            <Link to={'/apps/new?clone_from=' + id} className="btn btn-outline">Clone</Link>
          )}
          {scan_count >= 2 && (
            <Link to={'/apps/' + id + '/compare'} className="btn btn-outline">Compare Scans</Link>
          )}
          {can_edit && (
            <button type="button" className="btn btn-danger" onClick={handleDeleteApp}>
              Delete App
            </button>
          )}
        </div>
      </div>

      <GroundTruth appId={id} app={app} vulns={vulns} canEdit={can_edit} />

      {can_edit && importOpen && (
        <div className="card mb-2">
          <h3 className="card-title mb-2">Import Vulnerabilities</h3>
          <p className="text-sm text-secondary mb-2">Upload a JSON or CSV file with vulnerabilities.</p>
          {importMsg && (
            <div className={'alert ' + (importMsg.level === 'success' ? 'alert-success' : 'alert-error')}>{importMsg.text}</div>
          )}
          <form onSubmit={handleImport}>
            <div className="flex items-center gap-1">
              <input type="file" ref={fileInputRef} accept=".json,.csv" className="form-input" style={{ maxWidth: '400px' }} required />
              <button type="submit" className="btn btn-primary">Upload</button>
            </div>
          </form>
        </div>
      )}

      <div className="card mb-2">
        <div className="detail-grid">
          <div className="detail-label">Description</div>
          <div className="detail-value">{app.description || 'No description provided.'}</div>

          <div className="detail-label">App URL</div>
          <div className="detail-value">
            {app.url ? <a href={app.url}>{app.url}</a> : <span className="text-muted">N/A</span>}
          </div>

          <div className="detail-label">Source repository</div>
          <div className="detail-value">
            {app.source_repository
              ? <a href={app.source_repository} target="_blank" rel="noopener noreferrer">{app.source_repository.replace(/^https?:\/\//, '').replace(/\.git\/?$/, '')}</a>
              : <span className="text-muted">Not recorded</span>}
          </div>

          {app.source_commit && (
            <>
              <div className="detail-label">Source commit</div>
              <div className="detail-value">
                {commitUrl
                  ? <a href={commitUrl} target="_blank" rel="noopener noreferrer" title={app.source_commit}><code>{app.source_commit.slice(0, 12)}</code></a>
                  : <code title={app.source_commit}>{app.source_commit.slice(0, 12)}</code>}
              </div>
            </>
          )}

          {app.source_directory && (
            <>
              <div className="detail-label">Source directory</div>
              <div className="detail-value">
                {directoryUrl
                  ? <a href={directoryUrl} target="_blank" rel="noopener noreferrer"><code>{app.source_directory}</code></a>
                  : <code>{app.source_directory}</code>}
              </div>
            </>
          )}

          <div className="detail-label">Tech Stack</div>
          <div className="detail-value">
            {tech_stack.length > 0
              ? tech_stack.map(t => <span className="badge badge-info" key={t} style={{ marginRight: '0.25rem' }}>{t}</span>)
              : <span className="text-muted">N/A</span>
            }
          </div>

          <div className="detail-label">Created by</div>
          <div className="detail-value">{app.creator_name || app.created_by}</div>

          <div className="detail-label">Visibility</div>
          <div className="detail-value">
            <span className={'badge badge-' + (app.visibility === 'public' ? 'info' : app.visibility === 'team' ? 'medium' : 'low')}>
              {app.visibility}
            </span>
          </div>

          <div className="detail-label">Scans</div>
          <div className="detail-value">
            <Link to={'/scans?app_id=' + id}>{scan_count} scan{scan_count === 1 ? '' : 's'}</Link>
          </div>
        </div>
      </div>

      <div className="page-header">
        <h2 className="page-title">Vulnerabilities <span className="text-muted text-sm">({vulnCount})</span></h2>
      </div>

      {vulns.length > 0 && (
        <div className="metrics-grid mb-2">
          {SEVERITIES.map(sev => {
            const count = severity_counts[sev] || 0;
            if (count === 0) return null;
            return (
              <div className="metric-card" key={sev}>
                <div className="metric-value">
                  <span className={'badge badge-' + sev} style={{ fontSize: '1.25rem', padding: '0.25rem 0.75rem' }}>{count}</span>
                </div>
                <div className="metric-label">{sev}</div>
              </div>
            );
          })}
        </div>
      )}

      {vulns.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table className="cards-on-mobile">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Location</th>
                  {can_edit && <th style={{ width: '70px' }}></th>}
                </tr>
              </thead>
              <tbody>
                {vulns.map(vuln => (
                  <tr className="vuln-row" key={vuln.id}>
                    {renderCell(vuln, 'vuln_id')}
                    {renderCell(vuln, 'title')}
                    {renderCell(vuln, 'severity')}
                    {renderCell(vuln, 'vuln_type')}
                    <td data-label="Location" className="font-mono text-sm">{renderLocation(vuln)}</td>
                    {can_edit && (
                      <td data-label="">
                        <div className="flex gap-1">
                          <Link to={'/apps/' + id + '/vulns/' + vuln.id + '/edit'} className="btn-icon" title="Edit all fields">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.85 2.85 0 114 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                          </Link>
                          <button
                            type="button"
                            className="btn-icon btn-icon-danger"
                            title="Delete"
                            onClick={() => handleDeleteVuln(vuln.id)}
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No vulnerabilities documented yet.</p>
          {scan_count > 0 && (
            <>
              <p className="text-muted text-sm">
                This app has {scan_count} scan{scan_count === 1 ? '' : 's'}. Open a scan to promote pending findings into documented vulnerabilities.
              </p>
              <Link to={'/scans?app_id=' + id} className="btn btn-outline">View scans</Link>
            </>
          )}
        </div>
      )}

      {(chains.length > 0 || can_edit) && (
        <Chains appId={id} chains={chains} vulns={vulns} canEdit={can_edit} onChange={fetchApp} />
      )}

      <HistoryLog appId={id} canView={can_edit} />
    </div>
  );
}

// Chains on the app page: the catalog view, where a chain's severity, title
// and steps are edited. Before this there was no way to edit a chain in the
// UI at all, and no severity to edit — every chain read as Critical.
function Chains({ appId, chains, vulns, canEdit, onChange }) {
  const [editing, setEditing] = useState(null); // chain id, 'new', or null

  const save = async (chain, data) => {
    if (chain) await api.put(`/apps/${appId}/chains/${chain.id}`, data);
    else await api.post(`/apps/${appId}/chains`, data);
    setEditing(null);
    onChange();
  };

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">Chains <span className="text-muted text-sm">({chains.length})</span></h2>
        {canEdit && editing !== 'new' && (
          <button type="button" className="btn btn-outline" onClick={() => setEditing('new')}>Add Chain</button>
        )}
      </div>
      <div className="card">
        <p className="text-muted text-sm mb-2">
          A chain is separate ground truth that links two or more of the vulnerabilities
          above into one bigger exploit, where each step hands the next what it needs — it earns
          its own points only when a scan demonstrates the whole thing, not just each step
          individually. Points follow the chain's severity. See a scan's own detail page to
          review and credit one.
        </p>
        {editing === 'new' && (
          <div className="card mb-2">
            <ChainForm vulns={vulns} submitLabel="Add chain"
              onSubmit={data => save(null, data)} onCancel={() => setEditing(null)} />
          </div>
        )}
        {chains.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Chain</th><th>Severity</th><th>Members</th>{canEdit && <th style={{ width: 60 }}></th>}</tr></thead>
              <tbody>
                {chains.map(chain => editing === chain.id ? (
                  <tr key={chain.id}>
                    <td colSpan={canEdit ? 4 : 3}>
                      <ChainForm vulns={vulns} submitLabel="Save chain"
                        intro={`Editing ${chain.chain_id}. Changing severity changes its points, which opens a new ground-truth revision.`}
                        initial={{
                          title: chain.title, severity: chain.severity, description: chain.description,
                          member_vuln_ids: chain.members.map(m => m.vuln_id),
                        }}
                        onSubmit={data => save(chain, data)} onCancel={() => setEditing(null)} />
                    </td>
                  </tr>
                ) : (
                  <tr key={chain.id}>
                    <td>
                      <strong>{chain.chain_id}</strong>
                      <div className="text-muted text-sm">{chain.title}</div>
                    </td>
                    <td>
                      <Badge severity={chain.severity}>{chain.severity}</Badge>
                      <div className="text-muted text-xs font-mono">{chain.impact_weight}p</div>
                    </td>
                    <td>
                      {chain.members.map(m => (
                        <div key={m.vuln_id}>
                          <Link to={'/apps/' + appId + '/vulns/' + m.vuln_id}>{m.vuln_code} — {m.vuln_title}</Link>
                        </div>
                      ))}
                    </td>
                    {canEdit && (
                      <td>
                        <button type="button" className="btn btn-outline btn-sm" onClick={() => setEditing(chain.id)}>Edit</button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

const REVISION_REASONS = {
  new_prior_vuln: 'vuln added',
  weight_change: 'weight changed',
  vuln_invalidated: 'vuln invalidated',
  corpus_change: 'corpus changed',
};

// Ground-truth revisions: the axis that makes a historical number reproducible.
// Recall legitimately drops when a vuln that existed all along is documented —
// what used to be wrong is that the change was invisible. Collapsed by default;
// an app with a single revision has nothing to explain.
function GroundTruth({ appId, app, vulns = [], canEdit = false }) {
  const [data, setData] = useState(null);
  const [open, setOpen] = useState(false);

  const load = useCallback(() => {
    api.get(`/apps/${appId}/revisions`)
      .then(setData)
      .catch(() => setData(null));
  }, [appId]);

  useEffect(() => { load(); }, [load]);

  if (!data) return null;
  const latest = data.latest_revision;
  const revisions = data.revisions || [];
  const isCorpus = !!app?.benchmark_verified;
  // Placeholder tiers from the migration-024 backfill. Only meaningful on a
  // curated corpus, and they block the benchmark export there: a corpus whose
  // tiers were never reviewed reports every flaw in it as commodity.
  const unreviewed = vulns.filter(v => !v.weight_verified).length;
  const corpusTitle = isCorpus
    ? 'Hand-curated corpus: eligible for benchmark export and configuration aggregation'
    : 'Not a benchmark corpus — weights and tiers come from the severity backfill, so this app is excluded from benchmark exports';

  return (
    <div className="card mb-2">
      <div className="flex items-center justify-between" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
        <h3 className="card-title" style={{ margin: 0 }}>
          Ground Truth
          <span className="text-muted text-sm font-mono" style={{ marginLeft: 8 }}>
            revision {latest}
          </span>
          {/* The flag this badge reports is set two regions away, on the app
              edit form. Anyone who can edit gets the badge itself as the link
              to that checkbox, so the status and the switch are one control
              rather than a state with no visible way to change it. `a:hover`
              recolors it, which is the affordance hint. */}
          {canEdit ? (
            <Link to={'/apps/' + appId + '/edit'}
              className={`badge badge-${isCorpus ? 'low' : 'ignored'}`} style={{ marginLeft: 8 }}
              title={`${corpusTitle} — click to change it on the app edit form`}>
              {isCorpus ? 'benchmark corpus' : 'not curated'}
            </Link>
          ) : (
            <span className={`badge badge-${isCorpus ? 'low' : 'ignored'}`} style={{ marginLeft: 8 }}
              title={corpusTitle}>
              {isCorpus ? 'benchmark corpus' : 'not curated'}
            </span>
          )}
          {isCorpus && unreviewed > 0 && (
            <span className="badge badge-medium" style={{ marginLeft: 6 }}
              title="These carry the placeholder difficulty_tier from the backfill. The benchmark export refuses until they are reviewed.">
              {unreviewed} tier{unreviewed === 1 ? '' : 's'} unreviewed
            </span>
          )}
          {revisions.length > 1 && (
            <button type="button" onClick={() => setOpen(!open)}
              className="btn btn-outline btn-sm" style={{ marginLeft: 8, height: 20, padding: '0 0.4rem', fontSize: '0.7rem' }}>
              {open ? 'Hide history' : `${revisions.length} revisions`}
            </button>
          )}
        </h3>
      </div>

      {open && (
        <div className="table-wrap mt-2">
          <table className="cards-on-mobile">
            <thead>
              <tr><th>Revision</th><th>Reason</th><th>Notes</th><th>By</th><th>When</th></tr>
            </thead>
            <tbody>
              {revisions.map(r => (
                <tr key={r.id}>
                  <td data-label="Revision" className="font-mono">rev{r.revision}</td>
                  <td data-label="Reason">{REVISION_REASONS[r.reason] || r.reason}</td>
                  <td data-label="Notes" className="text-sm text-secondary">{r.notes || '-'}</td>
                  <td data-label="By" className="text-sm text-secondary">{r.created_by_name || '-'}</td>
                  <td data-label="When" className="text-sm text-secondary">{r.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
