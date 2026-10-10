import { useCallback, useEffect, useMemo, useState } from "react";

import { del, fmtDate, get, put, type ApiToken } from "../../api";
import { Card, Empty, Icon, Stat, relTime } from "../../ui";
import { msg } from "./common";

interface AuditRow {
  id: number;
  ts: string;
  actor: string | null;
  ip: string | null;
  action: string;
  target: string | null;
  outcome: string;
  details: { token?: string; scope?: string; reason?: string };
}

export default function Mcp() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [calls, setCalls] = useState<AuditRow[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const settings = await get<{ mcp: { enabled: boolean } }>("/api/admin/settings");
      setEnabled(settings.mcp.enabled);
      setTokens(await get<ApiToken[]>("/api/admin/tokens"));
      setCalls(await get<AuditRow[]>("/api/admin/audit?limit=200&action=mcp."));
    } catch (e) {
      setError(msg(e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (next: boolean) => {
    if (!next && !confirm("Disable the MCP server for everyone? Connected clients will get an error.")) return;
    await put("/api/admin/settings/mcp", { enabled: next });
    load();
  };
  const revoke = async (t: ApiToken) => {
    if (!confirm(`Revoke "${t.name}" of ${t.username}?`)) return;
    await del(`/api/admin/tokens/${t.id}`);
    load();
  };

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return tokens.filter((t) => !q || t.name.toLowerCase().includes(q) || (t.username || "").toLowerCase().includes(q));
  }, [tokens, query]);
  const byTool = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const c of calls) counts[c.target || "?"] = (counts[c.target || "?"] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [calls]);
  const failures = calls.filter((c) => c.outcome !== "success").length;

  if (enabled === null) return error ? <div className="alert error">{error}</div> : <div className="muted">Loading…</div>;

  return (
    <div className="stack" style={{ gap: 16 }}>
      <Card
        title={
          <span className="row">
            <Icon name="plug" /> MCP server
          </span>
        }
        actions={enabled ? <span className="badge ok">Enabled</span> : <span className="badge error">Disabled</span>}
        description="MCP clients authenticate with a personal API token and act with their owner's rights. Read-only tokens only see read tools."
      >
        <div className="row">
          <label className="toggle">
            <input type="checkbox" checked={enabled} onChange={(e) => toggle(e.target.checked)} />
            Accept MCP connections
          </label>
          <span className="muted small">Endpoint: <code>/api/mcp</code> (Streamable HTTP)</span>
        </div>
      </Card>

      <div className="stats">
        <Stat icon="key" label="Active tokens" value={tokens.length} sub={`${tokens.filter((t) => t.scope === "read").length} read-only`} />
        <Stat icon="activity" label="Recent MCP calls" value={calls.length} sub="last 200 recorded" />
        <Stat icon="alert" label="Rejected calls" value={failures} tone={failures ? "warn" : undefined} />
        <Stat icon="users" label="Accounts using MCP" value={new Set(calls.map((c) => c.actor)).size} />
      </div>

      <div className="grid-2">
        <Card title="Active API tokens (all accounts)" description="Personal tokens, service accounts and MCP clients.">
          <div className="filters">
            <div className="toolbar-search">
              <Icon name="search" />
              <input placeholder="Filter by name or account" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
          </div>
          {list.length ? (
            <div className="table-wrap">
              <table className="table dense">
                <thead>
                  <tr>
                    <th>Account</th>
                    <th>Token</th>
                    <th>Access</th>
                    <th>Last used</th>
                    <th>Expires</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.map((t) => (
                    <tr key={t.id}>
                      <td>
                        {t.username} {t.auth_source === "service" && <span className="badge">service</span>}
                      </td>
                      <td>
                        {t.name} <code>lsx_{t.prefix}_…</code>
                      </td>
                      <td>
                        <span className={`badge ${t.scope === "read" ? "" : "warn"}`}>{t.scope}</span>
                      </td>
                      <td>{relTime(t.last_used_at)}</td>
                      <td>{fmtDate(t.expires_at)}</td>
                      <td className="actions">
                        <button className="ghost small danger" onClick={() => revoke(t)}>
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty icon="key">No active token.</Empty>
          )}
        </Card>
        <Card title="Tool usage">
          {byTool.length ? (
            <div className="status-list">
              {byTool.map(([tool, n]) => (
                <div key={tool} className="status-item">
                  <code>{tool}</code>
                  <span className="value">{n} call(s)</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty icon="plug">No MCP call recorded yet.</Empty>
          )}
        </Card>
      </div>

      <Card title="Recent MCP calls">
        {calls.length ? (
          <div className="table-wrap">
            <table className="table dense">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Account</th>
                  <th>Tool</th>
                  <th>Result</th>
                  <th>Token</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {calls.slice(0, 50).map((c) => (
                  <tr key={c.id}>
                    <td title={fmtDate(c.ts)}>{relTime(c.ts)}</td>
                    <td>{c.actor}</td>
                    <td>
                      <code>{c.target}</code>
                    </td>
                    <td>
                      <span className={`badge ${c.outcome === "success" ? "ok" : "error"}`}>{c.outcome}</span>
                      {c.details?.reason && <span className="muted small"> {c.details.reason}</span>}
                    </td>
                    <td>
                      {c.details?.token && <code>lsx_{c.details.token}_…</code>} {c.details?.scope}
                    </td>
                    <td>{c.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty icon="activity">No MCP call recorded yet.</Empty>
        )}
      </Card>
    </div>
  );
}
