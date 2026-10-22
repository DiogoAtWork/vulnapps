import { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

export default function AppForm() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const cloneFrom = searchParams.get('clone_from');

  const isEdit = Boolean(id);

  const [form, setForm] = useState({
    name: '',
    version: '',
    description: '',
    url: '',
    source_repository: '',
    source_commit: '',
    source_directory: '',
    tech_stack: '',
    benchmark_verified: false,
    visibility: 'private',
    team_id: '',
  });
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [cloneSource, setCloneSource] = useState(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        // Fetch teams for dropdown
        try {
          const teamsData = await api.get('/teams');
          setTeams(teamsData.teams || []);
        } catch {
          // Teams may not be accessible if not logged in
        }

        if (isEdit) {
          const data = await api.get('/apps/' + id);
          const app = data.app;
          setForm({
            name: app.name || '',
            version: app.version || '',
            description: app.description || '',
            url: app.url || '',
            source_repository: app.source_repository || '',
            source_commit: app.source_commit || '',
            source_directory: app.source_directory || '',
            tech_stack: (data.tech_stack || []).join(', '),
            benchmark_verified: !!data.app?.benchmark_verified,
            visibility: app.visibility || 'private',
            team_id: app.team_id ? String(app.team_id) : '',
          });
        } else if (cloneFrom) {
          const data = await api.get('/apps/' + cloneFrom);
          const app = data.app;
          setCloneSource(app);
          setForm({
            name: app.name || '',
            version: app.version || '',
            description: app.description || '',
            url: app.url || '',
            source_repository: app.source_repository || '',
            source_commit: app.source_commit || '',
            source_directory: app.source_directory || '',
            tech_stack: (data.tech_stack || []).join(', '),
            // A clone starts uncurated — copied tiers are not reviewed tiers.
            benchmark_verified: false,
            visibility: 'private',
            team_id: '',
          });
        }
      } catch (err) {
        setError(err.message || 'Failed to load');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id, isEdit, cloneFrom]);

  function handleChange(e) {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    const body = {
      name: form.name,
      version: form.version,
      description: form.description || null,
      url: form.url || null,
      source_repository: form.source_repository || null,
      source_commit: form.source_commit || null,
      source_directory: form.source_directory || null,
      tech_stack: form.tech_stack,
      benchmark_verified: form.benchmark_verified,
      visibility: form.visibility,
      team_id: form.visibility === 'team' && form.team_id ? form.team_id : null,
    };

    if (!isEdit && cloneFrom) {
      body.clone_from = cloneFrom;
    }

    try {
      let result;
      if (isEdit) {
        result = await api.put('/apps/' + id, body);
      } else {
        result = await api.post('/apps', body);
      }
      const appId = result.app?.id || id;
      navigate('/apps/' + appId);
    } catch (err) {
      setError(err.message || 'Failed to save app');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <div className="container"><div className="empty-state"><p>Loading...</p></div></div>;
  }

  const title = isEdit ? 'Edit App' : (cloneFrom ? 'Clone App' : 'Create App');
  const submitLabel = isEdit ? 'Update App' : (cloneFrom ? 'Clone App' : 'Create App');

  return (
    <div className="container">
      <div style={{ maxWidth: '600px', margin: '2rem auto' }}>
        <div className="card">
          <h2 className="card-title mb-2">{title}</h2>

          {cloneSource && (
            <p className="text-sm text-secondary mb-2">
              Cloning from <strong>{cloneSource.name}</strong>. Vulnerabilities will be copied.
            </p>
          )}

          {error && <div className="alert alert-error">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="name">Name</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  className="form-input"
                  value={form.name}
                  onChange={handleChange}
                  required
                  autoFocus
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="version">Version</label>
                <input
                  type="text"
                  id="version"
                  name="version"
                  className="form-input"
                  value={form.version}
                  onChange={handleChange}
                  placeholder="e.g. 1.0"
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="description">Description</label>
              <textarea
                id="description"
                name="description"
                className="form-textarea"
                rows="4"
                value={form.description}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="url">App URL</label>
              <input
                type="url"
                id="url"
                name="url"
                className="form-input"
                value={form.url}
                onChange={handleChange}
                placeholder="https://app.example.com"
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="source_repository">Source repository</label>
              <input
                type="url"
                id="source_repository"
                name="source_repository"
                className="form-input"
                value={form.source_repository}
                onChange={handleChange}
                placeholder="https://github.com/owner/repository"
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="source_commit">Source commit</label>
              <input
                type="text"
                id="source_commit"
                name="source_commit"
                className="form-input"
                value={form.source_commit}
                onChange={handleChange}
                placeholder="Full commit SHA, when known"
                maxLength={64}
              />
              <small className="text-muted">The reviewed source revision. This does not confirm which revision is deployed.</small>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="source_directory">Source directory</label>
              <input
                type="text"
                id="source_directory"
                name="source_directory"
                className="form-input"
                value={form.source_directory}
                onChange={handleChange}
                placeholder="Optional path within the repository"
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="tech_stack">Tech Stack</label>
              <input
                type="text"
                id="tech_stack"
                name="tech_stack"
                className="form-input"
                value={form.tech_stack}
                onChange={handleChange}
                placeholder="e.g. PHP, Next.js, SQLite"
              />
              <span className="text-muted text-xs">Comma-separated list of technologies</span>
            </div>

            {/* Gate on benchmark exports and configuration aggregation. Migration
                024 derived weights from severity for every app; only a flagged
                corpus claims hand-curated ground truth, so a weighted comparison
                can never silently span curated and derived corpora.
                Edit-only: a new app has nothing reviewed yet, and POST /api/apps
                does not carry the flag — a checkbox that silently did nothing
                would be worse than no checkbox. */}
            {isEdit && (
            <div className="form-group">
              <label className="form-label" style={{ cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  name="benchmark_verified"
                  checked={form.benchmark_verified}
                  onChange={e => setForm(prev => ({ ...prev, benchmark_verified: e.target.checked }))}
                  style={{ accentColor: 'var(--accent)', marginRight: 6 }}
                />
                Benchmark corpus
              </label>
              <span className="text-muted text-xs">
                Hand-curated ground truth: severities and difficulty tiers have been
                reviewed. Only these apps can be exported as a benchmark or aggregated
                into configuration results.
              </span>
            </div>
            )}

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="visibility">Visibility</label>
                <select
                  id="visibility"
                  name="visibility"
                  className="form-select"
                  value={form.visibility}
                  onChange={handleChange}
                >
                  <option value="private">Private</option>
                  <option value="team">Team</option>
                  {user && user.role === 'admin' && (
                    <option value="public">Public</option>
                  )}
                </select>
              </div>
              {form.visibility === 'team' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="team_id">Team</label>
                  <select
                    id="team_id"
                    name="team_id"
                    className="form-select"
                    value={form.team_id}
                    onChange={handleChange}
                    required={form.visibility === 'team'}
                  >
                    <option value="">Select team</option>
                    {teams.map(t => (
                      <option key={t.id} value={t.id}>{t.name}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={submitting}>
              {submitting ? 'Saving...' : submitLabel}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
