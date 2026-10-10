import { useCallback, useEffect, useState } from "react";

import { fmtDate, get } from "../../api";
import { Card, Empty, Icon } from "../../ui";

interface AuditRow {
  id: number;
  ts: string;
  actor: string | null;
  ip: string | null;
  action: string;
  target: string | null;
  outcome: string;
  details: Record<string, unknown>;
}

const PRESETS: [string, string][] = [
  ["", "All"],
  ["auth.", "Sign-in"],
  ["user.", "Accounts"],
  ["token.", "Tokens"],
  ["mcp.", "MCP"],
  ["project.", "Projects"],
  ["settings.", "Settings"],
  ["agent.", "Agent"],
];

export default function Audit() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const query = new URLSearchParams({ ...(action && { action }), ...(actor && { actor }) }).toString();
  const load = useCallback(
    () => get<AuditRow[]>(`/api/admin/audit?limit=200&${query}`).then(setRows).catch(() => undefined),
    [query],
  );
  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [load]);

  return (
    <Card
      title="Audit trail"
      description="Every critical action, with actor, IP and outcome. Also forwarded to the remote syslog when enabled."
      actions={
        <a className="button small" href={`/api/admin/audit/export?${query}`}>
          <Icon name="download" /> Export CSV
        </a>
      }
    >
      <div className="filters">
        <div className="segmented">
          {PRESETS.map(([value, label]) => (
            <button key={value} className={action === value ? "active" : ""} onClick={() => setAction(value)}>
              {label}
            </button>
          ))}
        </div>
        <input placeholder="Action prefix (e.g. auth.)" value={action} onChange={(e) => setAction(e.target.value)} />
        <input placeholder="User" value={actor} onChange={(e) => setActor(e.target.value)} />
      </div>
      {rows.length ? (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Date</th>
                <th>User</th>
                <th>IP</th>
                <th>Action</th>
                <th>Target</th>
                <th>Outcome</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="nowrap">{fmtDate(r.ts)}</td>
                  <td>{r.actor}</td>
                  <td>{r.ip}</td>
                  <td>
                    <code>{r.action}</code>
                  </td>
                  <td className="ellipsis" style={{ maxWidth: 220 }} title={r.target || ""}>
                    {r.target}
                  </td>
                  <td>
                    <span className={`badge ${r.outcome === "success" ? "ok" : "error"}`}>{r.outcome}</span>
                  </td>
                  <td className="mono small ellipsis" style={{ maxWidth: 320 }} title={JSON.stringify(r.details)}>
                    {Object.keys(r.details || {}).length ? JSON.stringify(r.details) : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty icon="shield">No entry matches.</Empty>
      )}
    </Card>
  );
}
