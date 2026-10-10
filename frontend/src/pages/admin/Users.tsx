import { useCallback, useEffect, useMemo, useState } from "react";

import { del, fmtDate, get, patch, post, type ApiToken, type Role, type User } from "../../api";
import { Avatar, Card, CopyButton, Drawer, Empty, Icon, Modal, relTime } from "../../ui";
import { TokenManager } from "../Profile";
import { ROLES, ROLE_LABEL, msg, usersChanged } from "./common";

interface Detail {
  user: User;
  mfa: { totp: boolean; security_keys: number };
  groups: { source: string; group: string; synced_at: string }[];
  sessions: { ip: string | null; user_agent: string | null; created_at: string; last_seen_at: string }[];
  tokens: ApiToken[];
  projects: { owned: number; shared_with: number };
  audit: { ts: string; action: string; outcome: string; ip: string | null; actor: string | null; target: string | null }[];
}

const STATUS_TONE: Record<User["status"], string> = { active: "ok", pending: "warn", disabled: "" };

export default function Users({ currentUser }: { currentUser: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"" | User["status"]>("");
  const [role, setRole] = useState<"" | Role>("");
  const [source, setSource] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => get<User[]>("/api/admin/users").then(setUsers).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return users.filter(
      (u) =>
        (!q ||
          u.username.toLowerCase().includes(q) ||
          (u.display_name || "").toLowerCase().includes(q) ||
          (u.email || "").toLowerCase().includes(q)) &&
        (!status || u.status === status) &&
        (!role || u.role === role) &&
        (!source || u.auth_source === source),
    );
  }, [users, query, status, role, source]);

  const refresh = () => {
    load();
    usersChanged();
  };

  return (
    <>
      {error && <div className="alert error">{error}</div>}
      <Card>
        <div className="filters">
          <div className="toolbar-search">
            <Icon name="search" />
            <input placeholder="Search name, username, e-mail…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <select value={status} onChange={(e) => setStatus(e.target.value as User["status"] | "")} aria-label="Status">
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="pending">Pending</option>
            <option value="disabled">Disabled</option>
          </select>
          <select value={role} onChange={(e) => setRole(e.target.value as Role | "")} aria-label="Role">
            <option value="">All roles</option>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
            <option value="">All sources</option>
            <option value="local">Local</option>
            <option value="oidc">OIDC</option>
            <option value="ldap">LDAPS</option>
            <option value="service">Service account</option>
          </select>
          <span className="spacer" />
          <span className="muted small">
            {list.length} / {users.length}
          </span>
          <button className="primary" onClick={() => setCreating(true)}>
            <Icon name="plus" /> New account
          </button>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Source</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Last login</th>
              </tr>
            </thead>
            <tbody>
              {list.map((u) => (
                <tr key={u.id} className="clickable" onClick={() => setOpenId(u.id)}>
                  <td>
                    <div className="user-cell">
                      <Avatar name={u.display_name || u.username} />
                      <div className="who-text">
                        <strong>{u.display_name || u.username}</strong>
                        <span className="muted small">{u.username}</span>
                      </div>
                      {u.id === currentUser.id && <span className="badge info">you</span>}
                    </div>
                  </td>
                  <td>
                    <span className="badge">{u.auth_source}</span>
                  </td>
                  <td>{ROLE_LABEL[u.role]}</td>
                  <td>
                    <span className={`badge ${STATUS_TONE[u.status]}`}>{u.status}</span>
                    {u.locked && <span className="badge error">locked</span>}
                    {u.must_change_password && <span className="badge warn">password change due</span>}
                  </td>
                  <td>{u.totp_enabled ? <span className="badge ok">TOTP</span> : <span className="muted">—</span>}</td>
                  <td title={fmtDate(u.last_login_at)}>{relTime(u.last_login_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!list.length && <Empty icon="users">No account matches these filters.</Empty>}
        </div>
      </Card>
      {openId && (
        <UserDrawer userId={openId} currentUser={currentUser} onClose={() => setOpenId(null)} onChanged={refresh} />
      )}
      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onCreated={() => {
            refresh();
          }}
        />
      )}
    </>
  );
}

function UserDrawer({
  userId,
  currentUser,
  onClose,
  onChanged,
}: {
  userId: string;
  currentUser: User;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [secret, setSecret] = useState("");
  const load = useCallback(
    () => get<Detail>(`/api/admin/users/${userId}/detail`).then(setDetail).catch((e) => setError(msg(e))),
    [userId],
  );
  useEffect(() => {
    load();
  }, [load]);

  const act = async (fn: () => Promise<unknown>, confirmText?: string) => {
    if (confirmText && !confirm(confirmText)) return;
    setError("");
    try {
      await fn();
      await load();
      onChanged();
    } catch (e) {
      setError(msg(e));
    }
  };

  if (!detail) {
    return (
      <Drawer title={<strong>Account</strong>} onClose={onClose}>
        {error ? <div className="alert error">{error}</div> : <span className="spinner" />}
      </Drawer>
    );
  }
  const u = detail.user;
  const self = u.id === currentUser.id;

  return (
    <Drawer
      onClose={onClose}
      title={
        <div className="user-cell">
          <Avatar name={u.display_name || u.username} />
          <div className="who-text">
            <strong>{u.display_name || u.username}</strong>
            <span className="muted small">
              {u.username} · {u.auth_source}
            </span>
          </div>
        </div>
      }
    >
      {error && <div className="alert error">{error}</div>}
      {secret && (
        <div className="alert warn">
          Temporary password — send it through a secure channel; it will not be displayed again and must be changed
          at first login.
          <code className="secret">{secret}</code>
          <CopyButton text={secret} />
          <button className="small ghost" onClick={() => setSecret("")}>
            Done
          </button>
        </div>
      )}
      {u.status === "pending" && (
        <div className="alert warn">
          This account is waiting for approval.
          <span className="spacer" />
          <button className="small primary" onClick={() => act(() => post(`/api/admin/users/${u.id}/approve`, { role: u.role }))}>
            Approve as {ROLE_LABEL[u.role]}
          </button>
          <button className="small ghost danger" onClick={() => act(() => post(`/api/admin/users/${u.id}/reject`), `Reject ${u.username}?`)}>
            Reject
          </button>
        </div>
      )}
      <section>
        <div className="form-grid">
          <label>
            Role
            <select
              value={u.role}
              disabled={self}
              onChange={(e) => act(() => patch(`/api/admin/users/${u.id}`, { role: e.target.value }))}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Status
            <select
              value={u.status}
              disabled={self}
              onChange={(e) => act(() => patch(`/api/admin/users/${u.id}`, { status: e.target.value }))}
            >
              <option value="active">Active</option>
              <option value="pending">Pending</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
        </div>
        <div className="row">
          {u.auth_source === "local" && (
            <button
              className="small"
              onClick={() =>
                act(async () => {
                  const res = await post<{ temporary_password: string }>(`/api/admin/users/${u.id}/reset-password`);
                  setSecret(res.temporary_password);
                }, `Reset the password of ${u.username}?`)
              }
            >
              <Icon name="key" /> Reset password
            </button>
          )}
          {u.locked && (
            <button className="small" onClick={() => act(() => post(`/api/admin/users/${u.id}/unlock`))}>
              <Icon name="lock" /> Unlock
            </button>
          )}
          <button
            className="small"
            onClick={() => act(() => post(`/api/admin/users/${u.id}/reset-mfa`), `Reset MFA for ${u.username}?`)}
          >
            <Icon name="refresh" /> Reset MFA
          </button>
          <button
            className="small"
            disabled={!detail.sessions.length || self}
            onClick={() => act(() => post(`/api/admin/users/${u.id}/revoke-sessions`), `Sign ${u.username} out everywhere?`)}
          >
            <Icon name="logout" /> Sign out everywhere
          </button>
          {!self && (
            <button
              className="small danger"
              onClick={() =>
                act(async () => {
                  await del(`/api/admin/users/${u.id}`);
                  onClose();
                }, `Delete ${u.username} and their projects?`)
              }
            >
              <Icon name="trash" /> Delete
            </button>
          )}
        </div>
      </section>

      <section>
        <h3>Overview</h3>
        <dl className="kv">
          <dt>E-mail</dt>
          <dd>{u.email || "—"}</dd>
          <dt>Created</dt>
          <dd>{fmtDate(u.created_at)}</dd>
          <dt>Last login</dt>
          <dd>{fmtDate(u.last_login_at)}</dd>
          <dt>MFA</dt>
          <dd>
            {detail.mfa.totp ? <span className="badge ok">TOTP</span> : <span className="badge">no TOTP</span>}{" "}
            <span className="badge">{detail.mfa.security_keys} security key(s)</span>
          </dd>
          <dt>Projects</dt>
          <dd>
            {detail.projects.owned} owned · {detail.projects.shared_with} shared with them
          </dd>
        </dl>
      </section>

      {detail.groups.length > 0 && (
        <section>
          <h3>Directory groups</h3>
          <div className="field-chips">
            {detail.groups.map((g) => (
              <span key={`${g.source}|${g.group}`} className="badge" title={`${g.source} · ${fmtDate(g.synced_at)}`}>
                {g.group}
              </span>
            ))}
          </div>
        </section>
      )}

      <section>
        <h3>Active sessions ({detail.sessions.length})</h3>
        {detail.sessions.length ? (
          <ul className="list">
            {detail.sessions.map((s, i) => (
              <li key={i}>
                <span className="row" style={{ minWidth: 0 }}>
                  <Icon name="monitor" /> {s.ip || "?"}
                  <small className="muted ellipsis" style={{ maxWidth: 260 }}>
                    {s.user_agent}
                  </small>
                </span>
                <small>{relTime(s.last_seen_at)}</small>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">No active session.</p>
        )}
      </section>

      <section>
        <h3>API & MCP tokens</h3>
        {u.auth_source === "service" ? (
          <TokenManager base={`/api/admin/users/${u.id}/tokens`} title="Service account tokens" />
        ) : detail.tokens.length ? (
          <table className="table dense">
            <tbody>
              {detail.tokens.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>
                    <span className={`badge ${t.scope === "read" ? "" : "warn"}`}>{t.scope}</span>
                  </td>
                  <td className="muted">used {relTime(t.last_used_at)}</td>
                  <td className="actions">
                    <button
                      className="ghost small danger"
                      onClick={() => act(() => del(`/api/admin/tokens/${t.id}`), `Revoke "${t.name}"?`)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted small">No active token.</p>
        )}
      </section>

      <section>
        <h3>Recent activity</h3>
        {detail.audit.length ? (
          <table className="table dense">
            <tbody>
              {detail.audit.map((a, i) => (
                <tr key={i}>
                  <td className="nowrap" title={fmtDate(a.ts)}>
                    {relTime(a.ts)}
                  </td>
                  <td>
                    <code>{a.action}</code>
                  </td>
                  <td>
                    <span className={`badge ${a.outcome === "success" ? "ok" : "error"}`}>{a.outcome}</span>
                  </td>
                  <td className="muted">{a.actor !== u.username ? `by ${a.actor}` : a.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted small">No recorded activity.</p>
        )}
      </section>
    </Drawer>
  );
}

function CreateUser({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ username: "", display_name: "", role: "user" as Role, service_account: false });
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");

  const create = async () => {
    setError("");
    try {
      const res = await post<{ temporary_password: string | null }>("/api/admin/users", form);
      onCreated();
      if (res.temporary_password) setSecret(res.temporary_password);
      else onClose();
    } catch (e) {
      setError(msg(e));
    }
  };

  return (
    <Modal title="New account" onClose={onClose}>
      {secret ? (
        <div className="stack">
          <div className="alert warn">
            Temporary password for <strong>{form.username}</strong> — send it through a secure channel; it will not be
            displayed again and must be changed at first login.
            <code className="secret">{secret}</code>
            <CopyButton text={secret} />
          </div>
          <div className="row end">
            <button className="primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <div className="stack">
          <div className="form-grid" style={{ marginBottom: 0 }}>
            <label>
              Username
              <input autoFocus value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </label>
            <label>
              Display name
              <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
            </label>
            <label>
              Role
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABEL[r]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              checked={form.service_account}
              onChange={(e) => setForm({ ...form, service_account: e.target.checked })}
            />
            Service account (no password, API tokens only — for scripts, CI, shared MCP clients)
          </label>
          <p className="muted small" style={{ margin: 0 }}>
            SSO and LDAPS users do not need to be created: their account appears at their first login.
          </p>
          {error && <div className="alert error">{error}</div>}
          <div className="row end">
            <button className="ghost" onClick={onClose}>
              Cancel
            </button>
            <button className="primary" onClick={create} disabled={!form.username.trim()}>
              Create
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
