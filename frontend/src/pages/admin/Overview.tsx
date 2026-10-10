import { useCallback, useEffect, useState } from "react";

import { fmtDate, get, post, type Role, type User } from "../../api";
import { Avatar, Card, Empty, Icon, Stat, relTime } from "../../ui";
import type { Section } from "./Admin";
import { ROLES, ROLE_LABEL, msg, usersChanged } from "./common";

interface OverviewData {
  users: {
    by_status: Record<string, number>;
    by_role: Record<string, number>;
    locked: number;
    humans_active: number;
    humans_with_mfa: number;
    pending: (User & { groups: string[] })[];
  };
  activity_24h: { logins: number; failed_logins: number; agent_runs: number; mcp_calls: number };
  totals: { projects: number; active_sessions: number; active_tokens: number };
  integrations: {
    llm: { provider: string; model: string; host: string | null };
    oidc: { enabled: boolean; name: string | null };
    ldap: { enabled: boolean; host: string | null };
    syslog: { enabled: boolean; active: boolean; sent?: number; dropped?: number; last_error?: string | null };
    mcp: { enabled: boolean };
    backup: { file: string; size: number; count: number } | null;
    expiring_certificates: { file: string; subject: string; not_after: string }[];
  };
  recent_failures: { ts: string; actor: string | null; ip: string | null; action: string; target: string | null }[];
}

export default function Overview({ onNavigate }: { onNavigate: (s: Section) => void }) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => get<OverviewData>("/api/admin/overview").then(setData).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);

  if (!data) return error ? <div className="alert error">{error}</div> : <div className="muted">Loading…</div>;
  const { users, activity_24h: act, totals, integrations: integ } = data;
  const mfaPct = users.humans_active ? Math.round((users.humans_with_mfa / users.humans_active) * 100) : 0;

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="stats">
        <Stat icon="users" label="Active users" value={users.humans_active} sub={`${mfaPct}% with MFA`} />
        <Stat
          icon="clock"
          label="Pending approval"
          value={users.pending.length}
          tone={users.pending.length ? "warn" : undefined}
          sub={users.locked ? `${users.locked} locked account(s)` : "no locked account"}
        />
        <Stat
          icon="key"
          label="Logins (24 h)"
          value={act.logins}
          tone={act.failed_logins > 10 ? "error" : undefined}
          sub={`${act.failed_logins} failed`}
        />
        <Stat icon="sparkles" label="Agent runs (24 h)" value={act.agent_runs} sub={`${totals.projects} projects`} />
        <Stat icon="plug" label="MCP calls (24 h)" value={act.mcp_calls} sub={`${totals.active_tokens} active tokens`} />
        <Stat icon="monitor" label="Active sessions" value={totals.active_sessions} />
      </div>

      <div className="grid-2">
        <PendingQueue pending={users.pending} onChanged={load} />
        <Card title="Integrations">
          <div className="status-list">
            <StatusItem
              ok={!!integ.llm.host}
              name="AI agent (LLM)"
              value={`${integ.llm.provider} · ${integ.llm.model}${integ.llm.host ? ` · ${integ.llm.host}` : ""}`}
              onClick={() => onNavigate("ai")}
            />
            <StatusItem
              ok={integ.oidc.enabled}
              off={!integ.oidc.enabled}
              name="OIDC single sign-on"
              value={integ.oidc.enabled ? integ.oidc.name || "enabled" : "disabled"}
              onClick={() => onNavigate("directory")}
            />
            <StatusItem
              ok={integ.ldap.enabled}
              off={!integ.ldap.enabled}
              name="LDAPS directory"
              value={integ.ldap.enabled ? integ.ldap.host || "enabled" : "disabled"}
              onClick={() => onNavigate("directory")}
            />
            <StatusItem
              ok={integ.syslog.active && !integ.syslog.last_error}
              warn={!!integ.syslog.last_error || !!integ.syslog.dropped}
              off={!integ.syslog.enabled}
              name="Remote syslog"
              value={
                !integ.syslog.enabled
                  ? "disabled"
                  : integ.syslog.last_error
                    ? integ.syslog.last_error
                    : `${integ.syslog.sent ?? 0} sent, ${integ.syslog.dropped ?? 0} dropped`
              }
              onClick={() => onNavigate("logging")}
            />
            <StatusItem
              ok={integ.mcp.enabled}
              off={!integ.mcp.enabled}
              name="MCP server"
              value={integ.mcp.enabled ? "enabled" : "disabled"}
              onClick={() => onNavigate("mcp")}
            />
            <StatusItem
              ok={!!integ.backup}
              warn={!integ.backup}
              name="Encrypted backups"
              value={
                integ.backup
                  ? `${integ.backup.file} · ${(integ.backup.size / 1048576).toFixed(1)} MB · ${integ.backup.count} kept`
                  : "no backup yet (runs nightly)"
              }
            />
            <StatusItem
              ok={!integ.expiring_certificates.length}
              warn={!!integ.expiring_certificates.length}
              name="Internal CA certificates"
              value={
                integ.expiring_certificates.length
                  ? `${integ.expiring_certificates.length} expiring within 30 days`
                  : "none expiring soon"
              }
              onClick={() => onNavigate("pki")}
            />
          </div>
        </Card>
      </div>

      <Card
        title="Recent failures"
        description="Failed logins, rejected MCP calls, backup or configuration errors."
        actions={
          <button className="small ghost" onClick={() => onNavigate("audit")}>
            Full audit trail <Icon name="expand" />
          </button>
        }
      >
        {data.recent_failures.length ? (
          <div className="table-wrap">
            <table className="table dense">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>IP</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_failures.map((f, i) => (
                  <tr key={i}>
                    <td title={fmtDate(f.ts)}>{relTime(f.ts)}</td>
                    <td>
                      <code>{f.action}</code>
                    </td>
                    <td>{f.actor || "—"}</td>
                    <td>{f.ip || "—"}</td>
                    <td className="muted">{f.target || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty icon="check">Nothing to report.</Empty>
        )}
      </Card>
    </div>
  );
}

function StatusItem({
  name,
  value,
  ok,
  warn,
  off,
  onClick,
}: {
  name: string;
  value: string;
  ok?: boolean;
  warn?: boolean;
  off?: boolean;
  onClick?: () => void;
}) {
  const tone = off ? "" : warn ? "warn" : ok ? "ok" : "error";
  return (
    <div className="status-item">
      <span className={`dot ${tone}`} />
      <span className="name">{name}</span>
      <span className="value ellipsis" style={{ maxWidth: "55%" }} title={value}>
        {value}
      </span>
      {onClick && (
        <button className="ghost icon-only small" onClick={onClick} aria-label={`Configure ${name}`}>
          <Icon name="expand" />
        </button>
      )}
    </div>
  );
}

function PendingQueue({ pending, onChanged }: { pending: (User & { groups: string[] })[]; onChanged: () => void }) {
  const [roles, setRoles] = useState<Record<string, Role>>({});
  const [error, setError] = useState("");

  const act = async (u: User, action: "approve" | "reject") => {
    setError("");
    if (action === "reject" && !confirm(`Reject ${u.username}? The account is disabled.`)) return;
    try {
      await post(`/api/admin/users/${u.id}/${action}`, action === "approve" ? { role: roles[u.id] || "user" } : {});
      usersChanged();
      onChanged();
    } catch (e) {
      setError(msg(e));
    }
  };

  return (
    <Card
      title="Waiting for approval"
      description="SSO / LDAPS accounts created at their first login while auto-provisioning is off."
    >
      {pending.length ? (
        <ul className="list">
          {pending.map((u) => (
            <li key={u.id} style={{ alignItems: "flex-start" }}>
              <div className="user-cell" style={{ alignItems: "flex-start" }}>
                <Avatar name={u.display_name || u.username} />
                <div className="who-text">
                  <strong>{u.display_name || u.username}</strong>
                  <span className="muted small">
                    {u.username} · {u.auth_source.toUpperCase()} · {relTime(u.created_at)}
                  </span>
                  {u.groups.length > 0 && (
                    <span className="field-chips" style={{ marginTop: 4 }}>
                      {u.groups.slice(0, 4).map((g) => (
                        <span key={g} className="badge">
                          {g.length > 40 ? `${g.slice(0, 40)}…` : g}
                        </span>
                      ))}
                      {u.groups.length > 4 && <span className="badge">+{u.groups.length - 4}</span>}
                    </span>
                  )}
                </div>
              </div>
              <div className="row tight">
                <select
                  value={roles[u.id] || "user"}
                  onChange={(e) => setRoles({ ...roles, [u.id]: e.target.value as Role })}
                  aria-label="Role"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {ROLE_LABEL[r]}
                    </option>
                  ))}
                </select>
                <button className="primary small" onClick={() => act(u, "approve")}>
                  <Icon name="check" /> Approve
                </button>
                <button className="ghost small danger" onClick={() => act(u, "reject")}>
                  Reject
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <Empty icon="check">No account waiting.</Empty>
      )}
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}
