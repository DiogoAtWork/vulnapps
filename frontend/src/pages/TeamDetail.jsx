import { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function TeamDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('view');
  const [error, setError] = useState('');
  const [editingName, setEditingName] = useState(false);
  const [draft, setDraft] = useState('');

  const load = () => api.get(`/teams/${id}`).then(setData);
  useEffect(() => { load(); }, [id]);

  const startEditName = () => { setDraft(data?.team?.name || ''); setEditingName(true); };
  const cancelEditName = () => { setEditingName(false); setDraft(''); };
  const saveEditName = async () => {
    const newName = draft.trim();
    if (!newName || newName === data?.team?.name) { cancelEditName(); return; }
    await api.put(`/teams/${id}`, { name: newName });
    cancelEditName();
    load();
  };

  const addMember = async (e) => {
    e.preventDefault();
    try {
      await api.post(`/teams/${id}/members`, { email, role });
      setEmail(''); load();
    } catch (err) { setError(err.message); }
  };

  const removeMember = async (uid) => {
    if (!confirm('Remove this member?')) return;
    await api.del(`/teams/${id}/members/${uid}`);
    load();
  };

  const changeRole = async (uid, newRole) => {
    await api.put(`/teams/${id}/members/${uid}`, { role: newRole });
    load();
  };

  const deleteTeam = async () => {
    if (!confirm('Delete this team? This cannot be undone.')) return;
    await api.del(`/teams/${id}`);
    navigate('/teams');
  };

  if (!data) return <p className="text-muted">Loading...</p>;
  const { team, members, is_team_admin } = data;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {editingName ? (
            <>
              <input
                className="form-input"
                value={draft}
                onChange={e => setDraft(e.target.value)}
                autoFocus
                onKeyDown={e => { if (e.key === 'Enter') saveEditName(); if (e.key === 'Escape') cancelEditName(); }}
                style={{ fontSize: '1.5rem', padding: '0.25rem 0.5rem', width: 'auto', minWidth: 240 }}
              />
              <button className="btn btn-primary btn-sm" onClick={saveEditName}>Save</button>
              <button className="btn btn-outline btn-sm" onClick={cancelEditName}>Cancel</button>
            </>
          ) : (
            <>
              {team.name}
              {is_team_admin && (
                <span className="editable-field" title="Click to rename" onClick={startEditName}>
                  <svg className="edit-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2"><path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>
                </span>
              )}
            </>
          )}
        </h1>
        <div className="flex gap-1 items-center">
          <Link to={`/apps?filter=team%3A${team.id}`} className="btn btn-outline btn-sm">View Apps</Link>
          {is_team_admin && <button className="btn btn-danger btn-sm" onClick={deleteTeam}>Delete Team</button>}
        </div>
      </div>

      {error && <div className="alert alert-error mb-2">{error}</div>}

      {is_team_admin && (
        <div className="card mb-2">
          <h3 className="card-title mb-2">Add Member</h3>
          <form onSubmit={addMember} className="flex gap-1 items-center">
            <input className="form-input" placeholder="Email address" value={email} onChange={e => setEmail(e.target.value)} required style={{ width: 250 }} />
            <select className="form-select" value={role} onChange={e => setRole(e.target.value)} style={{ width: 'auto' }}>
              <option value="view">Viewer</option>
              <option value="contributor">Contributor</option>
              <option value="admin">Admin</option>
            </select>
            <button type="submit" className="btn btn-primary btn-sm">Add</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3 className="card-title mb-2">Members</h3>
        <div className="table-wrap">
          <table className="cards-on-mobile">
            <thead><tr><th>Name</th><th>Email</th><th>Role</th>{is_team_admin && <th></th>}</tr></thead>
            <tbody>
              {members.map(m => (
                <tr key={m.id}>
                  <td data-label="Name">{m.name}</td>
                  <td data-label="Email" className="text-secondary">{m.email}</td>
                  <td data-label="Role">
                    {is_team_admin ? (
                      <select className="form-select" value={m.team_role} onChange={e => changeRole(m.id, e.target.value)} style={{ width: 'auto', padding: '2px 6px', fontSize: '0.85rem' }}>
                        <option value="view">view</option>
                        <option value="contributor">contributor</option>
                        <option value="admin">admin</option>
                      </select>
                    ) : (
                      <Badge severity={m.team_role === 'admin' ? 'critical' : m.team_role === 'contributor' ? 'high' : 'info'}>{m.team_role}</Badge>
                    )}
                  </td>
                  {is_team_admin && (
                    <td data-label=""><button className="btn btn-outline btn-sm" onClick={() => removeMember(m.id)}>Remove</button></td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
