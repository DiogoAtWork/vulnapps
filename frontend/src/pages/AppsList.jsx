import { useState, useEffect, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

export default function AppsList() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [teams, setTeams] = useState([]);

  const q = searchParams.get('q') || '';
  const filter = searchParams.get('filter') || '';

  const fetchApps = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (filter) params.set('filter', filter);
      const qs = params.toString();
      const data = await api.get('/apps' + (qs ? '?' + qs : ''));
      setApps(data.apps || []);
    } catch (err) {
      setError(err.message || 'Failed to load apps');
    } finally {
      setLoading(false);
    }
  }, [q, filter]);

  useEffect(() => { fetchApps(); }, [fetchApps]);

  useEffect(() => {
    if (user) api.get('/teams').then(d => setTeams(d.teams || [])).catch(() => {});
  }, [user]);

  function handleSearch(e) {
    const value = e.target.value;
    const next = new URLSearchParams(searchParams);
    if (value) next.set('q', value);
    else next.delete('q');
    setSearchParams(next, { replace: true });
  }

  function handleFilter(e) {
    const value = e.target.value;
    const next = new URLSearchParams(searchParams);
    if (value) next.set('filter', value);
    else next.delete('filter');
    setSearchParams(next, { replace: true });
  }

  return (
    <div className="container">
      <div className="page-header">
        <h1 className="page-title">Apps</h1>
        <div className="flex gap-1 items-center">
          <input
            type="text"
            className="search-box"
            placeholder="Search apps..."
            value={q}
            onChange={handleSearch}
          />
          {user && (
            <select
              className="form-select"
              style={{ width: 'auto', padding: '0.35rem 0.5rem', fontSize: '0.85rem' }}
              value={filter}
              onChange={handleFilter}
            >
              <option value="">All</option>
              <option value="public">Public</option>
              <option value="private">Private</option>
              {teams.length > 0 && <option value="teams" disabled style={{fontWeight:600}}>── Teams ──</option>}
              {teams.map(t => <option key={t.id} value={`team:${t.id}`}>{t.name}</option>)}
            </select>
          )}
          {user && (
            <Link to="/apps/new" className="btn btn-primary btn-sm" style={{ whiteSpace: 'nowrap' }}>Add App</Link>
          )}
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <div className="empty-state"><p>Loading...</p></div>
      ) : apps.length > 0 ? (
        <div className="card-grid">
          {apps.map(item => {
            const a = item.app;
            return (
              <Link to={'/apps/' + a.id} className="card" key={a.id}>
                <h3 className="card-title">
                  {a.name}{' '}
                  {a.version && <span className="text-muted text-sm">v{a.version}</span>}
                  {a.visibility !== 'public' && (
                    <span
                      className={'badge badge-' + (a.visibility === 'team' ? 'medium' : 'low')}
                      style={{ fontSize: '0.65rem', marginLeft: '0.5rem' }}
                    >
                      {a.visibility === 'team' ? (a.team_name || 'team') : a.visibility}
                    </span>
                  )}
                </h3>
                {item.tech && item.tech.length > 0 && (
                  <div className="mt-1">
                    {item.tech.map(t => (
                      <span className="badge badge-info" key={t} style={{ marginRight: '0.25rem' }}>{t}</span>
                    ))}
                  </div>
                )}
                {a.description && (
                  <p className="text-secondary text-sm mt-1">
                    {a.description.length > 120 ? a.description.slice(0, 120) + '...' : a.description}
                  </p>
                )}
                <div className="flex justify-between items-center mt-1">
                  <span className="text-muted text-xs">
                    {a.vuln_count} vulnerabilit{a.vuln_count === 1 ? 'y' : 'ies'} &middot; {a.scan_count} scan{a.scan_count === 1 ? '' : 's'}
                  </span>
                  {a.creator_name && (
                    <span className="text-muted text-xs">by {a.creator_name}</span>
                  )}
                </div>
              </Link>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <p>No apps found{q ? ' matching "' + q + '"' : ''}.</p>
        </div>
      )}
    </div>
  );
}
