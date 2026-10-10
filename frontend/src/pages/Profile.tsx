import QRCode from "qrcode";
import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, del, fmtDate, get, post, type ApiToken, type User } from "../api";
import { createCredential } from "../webauthn";
import { Avatar, Card, CopyButton, Empty, Icon, PageHeader, Snippet, relTime } from "../ui";
import { ChangePassword } from "./Auth";

interface Key {
  id: string;
  name: string;
  created_at: string;
}
interface SessionRow {
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  current: boolean;
}
interface McpInfo {
  enabled: boolean;
  url: string;
  tools: { name: string; description: string; read_only: boolean }[];
}

const msg = (e: unknown) => (e instanceof ApiError ? e.message : "Operation cancelled or not possible");

export default function Profile({ user, onChanged }: { user: User; onChanged: () => void }) {
  return (
    <div className="page">
      <PageHeader title="Profile & MCP" subtitle="Your account, its security, and access for MCP clients and scripts." />
      <div className="grid-2">
        <Card title="Account">
          <div className="row" style={{ marginBottom: 14 }}>
            <Avatar name={user.display_name || user.username} />
            <div className="who-text">
              <strong>{user.display_name || user.username}</strong>
              <span className="muted small">{user.email || user.username}</span>
            </div>
          </div>
          <dl className="kv">
            <dt>Username</dt>
            <dd>{user.username}</dd>
            <dt>Role</dt>
            <dd>
              <span className="badge accent">{user.role}</span>
            </dd>
            <dt>Sign-in</dt>
            <dd>{user.auth_source === "local" ? "Local account" : user.auth_source.toUpperCase()}</dd>
            <dt>Last login</dt>
            <dd>{fmtDate(user.last_login_at)}</dd>
          </dl>
        </Card>
        {user.auth_source === "local" ? (
          <Card title="Password" description="Changing it signs you out everywhere else.">
            <ChangePassword onDone={onChanged} />
          </Card>
        ) : (
          <DirectoryGroups />
        )}
        <Totp user={user} onChanged={onChanged} />
        <SecurityKeys />
      </div>
      <McpAccess />
      <TokenManager base="/api/me/tokens" title="Personal API tokens" />
      <Sessions />
    </div>
  );
}

// ---- MFA -------------------------------------------------------------------------------------
function Totp({ user, onChanged }: { user: User; onChanged: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (setup && canvas.current) QRCode.toCanvas(canvas.current, setup.otpauth_uri, { width: 180, margin: 1 });
  }, [setup]);

  const start = async () => {
    setError("");
    try {
      setSetup(await post("/api/me/totp/setup"));
    } catch (e) {
      setError(msg(e));
    }
  };
  const enable = async () => {
    try {
      await post("/api/me/totp/enable", { code });
      setSetup(null);
      setCode("");
      onChanged();
    } catch (e) {
      setError(msg(e));
    }
  };
  const disable = async () => {
    const c = prompt("Current TOTP code to confirm disabling");
    if (!c) return;
    try {
      await post("/api/me/totp/disable", { code: c });
      onChanged();
    } catch (e) {
      setError(msg(e));
    }
  };

  return (
    <Card
      title="Authenticator app (TOTP)"
      actions={user.totp_enabled ? <span className="badge ok">Enabled</span> : <span className="badge warn">Off</span>}
    >
      {user.totp_enabled ? (
        <button className="danger" onClick={disable}>
          Disable
        </button>
      ) : setup ? (
        <div className="stack">
          <canvas ref={canvas} className="qr" />
          <small className="muted">
            Scan the QR code or enter the key: <code>{setup.secret}</code>
          </small>
          <div className="row">
            <input
              placeholder="6-digit code"
              inputMode="numeric"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
            <button className="primary" onClick={enable} disabled={code.length < 6}>
              Enable
            </button>
          </div>
        </div>
      ) : (
        <>
          <p className="muted small">
            Adds a one-time code from an app such as FreeOTP, Aegis or Microsoft Authenticator.
          </p>
          <button onClick={start}>
            <Icon name="lock" /> Set up
          </button>
        </>
      )}
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}

function SecurityKeys() {
  const [keys, setKeys] = useState<Key[]>([]);
  const [error, setError] = useState("");
  const load = useCallback(() => get<Key[]>("/api/me/webauthn").then(setKeys).catch(() => undefined), []);
  useEffect(() => {
    load();
  }, [load]);

  const add = async () => {
    setError("");
    const name = prompt("Key name", "Security key");
    if (!name) return;
    try {
      const options = await post("/api/me/webauthn/register/options");
      const credential = await createCredential(options);
      await post("/api/me/webauthn/register/verify", { credential, name });
      load();
    } catch (e) {
      setError(msg(e));
    }
  };
  const remove = async (k: Key) => {
    if (!confirm(`Delete "${k.name}"?`)) return;
    await del(`/api/me/webauthn/${k.id}`);
    load();
  };

  return (
    <Card
      title="Security keys & passkeys"
      actions={
        <button className="small" onClick={add}>
          <Icon name="plus" /> Add
        </button>
      }
    >
      <ul className="list">
        {keys.map((k) => (
          <li key={k.id}>
            <span className="row">
              <Icon name="key" />
              {k.name} <small className="muted">{fmtDate(k.created_at)}</small>
            </span>
            <button className="ghost small danger" onClick={() => remove(k)}>
              Delete
            </button>
          </li>
        ))}
      </ul>
      {!keys.length && (
        <p className="muted small">No key registered. FIDO2 keys and passkeys (WebAuthn) are supported.</p>
      )}
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}

// ---- MCP access ------------------------------------------------------------------------------
type Client = "claude-code" | "claude-desktop" | "vscode" | "cursor" | "curl";
const CLIENTS: [Client, string][] = [
  ["claude-code", "Claude Code"],
  ["claude-desktop", "Claude Desktop"],
  ["vscode", "VS Code"],
  ["cursor", "Cursor"],
  ["curl", "Test (curl)"],
];

function snippet(client: Client, url: string, token: string): string {
  const auth = `Bearer ${token}`;
  switch (client) {
    case "claude-code":
      return `claude mcp add --transport http logstash-explorer ${url} \\\n  --header "Authorization: ${auth}"`;
    case "claude-desktop":
      return JSON.stringify(
        {
          mcpServers: {
            "logstash-explorer": {
              command: "npx",
              args: ["-y", "mcp-remote", url, "--header", "Authorization:${AUTH_HEADER}"],
              env: { AUTH_HEADER: auth },
            },
          },
        },
        null,
        2,
      );
    case "vscode":
      return JSON.stringify(
        { servers: { "logstash-explorer": { type: "http", url, headers: { Authorization: auth } } } },
        null,
        2,
      );
    case "cursor":
      return JSON.stringify({ mcpServers: { "logstash-explorer": { url, headers: { Authorization: auth } } } }, null, 2);
    case "curl":
      return `curl -s ${url} \\\n  -H "Authorization: ${auth}" -H "Content-Type: application/json" \\\n  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;
  }
}

const WHERE: Record<Client, string> = {
  "claude-code": "Run in a terminal (add --scope user to make it available in every project).",
  "claude-desktop":
    "Settings → Developer → Edit config (claude_desktop_config.json), then restart Claude Desktop. Requires Node.js.",
  vscode: "Save as .vscode/mcp.json in your workspace (or run “MCP: Add Server”).",
  cursor: "Save as ~/.cursor/mcp.json (or .cursor/mcp.json in a project).",
  curl: "Lists the tools available to this token.",
};

function McpAccess() {
  const [info, setInfo] = useState<McpInfo | null>(null);
  const [client, setClient] = useState<Client>("claude-code");
  const [scope, setScope] = useState<"read" | "write">("read");
  const [days, setDays] = useState(90);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    get<McpInfo>("/api/me/mcp").then(setInfo).catch(() => undefined);
  }, []);

  const create = async () => {
    setError("");
    try {
      const res = await post<{ token: string }>("/api/me/tokens", {
        name: `MCP · ${CLIENTS.find(([c]) => c === client)?.[1]}`,
        expires_in_days: days,
        scope,
      });
      setToken(res.token);
      window.dispatchEvent(new Event("lsx:tokens-changed"));
    } catch (e) {
      setError(msg(e));
    }
  };

  if (!info) return null;
  const tools = info.tools.filter((t) => scope === "write" || t.read_only);
  return (
    <Card
      title={
        <span className="row">
          <Icon name="plug" /> MCP server
        </span>
      }
      description="Connect an AI assistant (Claude Code, Claude Desktop, VS Code, Cursor…) to Logstash Explorer. It acts as you: it only sees your projects and those shared with you, with your role."
      actions={
        info.enabled ? (
          <span className="badge ok">Enabled</span>
        ) : (
          <span className="badge error">Disabled by an administrator</span>
        )
      }
    >
      <div className="stack">
        <div className="row">
          <span className="muted small">Server URL</span>
          <code>{info.url}</code>
          <CopyButton text={info.url} />
        </div>
        <div className="grid-2" style={{ gap: 20 }}>
          <div className="stack">
            <h3 style={{ margin: 0 }}>1. Create a dedicated token</h3>
            <div className="stack" style={{ gap: 10 }}>
              <label>
                Access
                <select value={scope} onChange={(e) => setScope(e.target.value as "read" | "write")}>
                  <option value="read">Read-only — list, read, test (recommended)</option>
                  <option value="write">Read & write — also save projects and run the agent</option>
                </select>
              </label>
              <label className="inline">
                Expires after
                <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={365}>1 year</option>
                </select>
              </label>
            </div>
            <div className="row">
              <button className="primary" onClick={create} disabled={!info.enabled}>
                <Icon name="key" /> Generate token
              </button>
              <span className="muted small">Revocable at any time below.</span>
            </div>
            {token && (
              <div className="alert warn">
                Copy this token now — it will never be displayed again. It is already inserted in the configuration.
                <code className="secret">{token}</code>
                <CopyButton text={token} label="Copy token" />
              </div>
            )}
            {error && <div className="alert error">{error}</div>}
            <h3 style={{ margin: "8px 0 0" }}>Tools available with this access</h3>
            <table className="table dense">
              <tbody>
                {tools.map((t) => (
                  <tr key={t.name}>
                    <td className="nowrap">
                      <code>{t.name}</code>
                    </td>
                    <td className="muted">{t.description}</td>
                    <td>
                      <span className={`badge ${t.read_only ? "" : "warn"}`}>{t.read_only ? "read" : "write"}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="stack">
            <h3 style={{ margin: 0 }}>2. Configure your client</h3>
            <div className="segmented" style={{ flexWrap: "wrap" }}>
              {CLIENTS.map(([c, label]) => (
                <button key={c} className={client === c ? "active" : ""} onClick={() => setClient(c)}>
                  {label}
                </button>
              ))}
            </div>
            <p className="muted small" style={{ margin: 0 }}>
              {WHERE[client]}
            </p>
            <Snippet code={snippet(client, info.url, token || "<YOUR_TOKEN>")} />
          </div>
        </div>
      </div>
    </Card>
  );
}

// ---- API tokens (also used by the admin for service accounts) --------------------------------
export function TokenManager({ base, title }: { base: string; title: string }) {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  const [scope, setScope] = useState<"read" | "write">("write");
  const [created, setCreated] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(() => get<ApiToken[]>(base).then(setTokens).catch(() => undefined), [base]);
  useEffect(() => {
    load();
    window.addEventListener("lsx:tokens-changed", load);
    return () => window.removeEventListener("lsx:tokens-changed", load);
  }, [load]);

  const create = async () => {
    setError("");
    try {
      const res = await post<{ token: string }>(base, { name, expires_in_days: days, scope });
      setCreated(res.token);
      setName("");
      load();
    } catch (e) {
      setError(msg(e));
    }
  };
  const revoke = async (t: ApiToken) => {
    if (!confirm(`Revoke token "${t.name}"?`)) return;
    await del(`${base}/${t.id}`);
    load();
  };
  const active = tokens.filter((t) => !t.revoked_at && new Date(t.expires_at) > new Date());

  return (
    <Card title={title} description="Used with the header Authorization: Bearer lsx_… (scripts, CI, MCP clients).">
      {created && (
        <div className="alert warn">
          Copy this token now, it will never be displayed again:
          <code className="secret">{created}</code>
          <CopyButton text={created} label="Copy token" />
          <button className="small ghost" onClick={() => setCreated("")}>
            Done
          </button>
        </div>
      )}
      {tokens.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Access</th>
                <th>Prefix</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                const dead = !!t.revoked_at || new Date(t.expires_at) <= new Date();
                return (
                  <tr key={t.id} className={dead ? "muted" : ""}>
                    <td>{t.name}</td>
                    <td>
                      <span className={`badge ${t.scope === "read" ? "" : "warn"}`}>
                        {t.scope === "read" ? "read-only" : "read & write"}
                      </span>
                    </td>
                    <td>
                      <code>lsx_{t.prefix}_…</code>
                    </td>
                    <td>{fmtDate(t.expires_at)}</td>
                    <td>{t.revoked_at ? "revoked" : relTime(t.last_used_at)}</td>
                    <td className="actions">
                      {!dead && (
                        <button className="ghost small danger" onClick={() => revoke(t)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty icon="key">No token yet.</Empty>
      )}
      <hr />
      <div className="row">
        <input placeholder="Token name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={scope} onChange={(e) => setScope(e.target.value as "read" | "write")} aria-label="Access">
          <option value="write">Read & write</option>
          <option value="read">Read-only</option>
        </select>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Expiry">
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={90}>90 days</option>
          <option value={365}>1 year</option>
        </select>
        <button onClick={create} disabled={!name.trim()}>
          <Icon name="plus" /> Create
        </button>
        <span className="muted small">{active.length} active</span>
      </div>
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}

function DirectoryGroups() {
  const [groups, setGroups] = useState<{ source: string; group: string; synced_at: string }[]>([]);
  useEffect(() => {
    get<typeof groups>("/api/groups/mine").then(setGroups).catch(() => undefined);
  }, []);
  return (
    <Card
      title="My directory groups"
      description="Seen at your last login; they determine your role and the projects shared with your teams."
    >
      <ul className="list">
        {groups.map((g) => (
          <li key={`${g.source}|${g.group}`}>
            <span className="row">
              <span className="badge">{g.source.toUpperCase()}</span> {g.group}
            </span>
            <small className="muted">{fmtDate(g.synced_at)}</small>
          </li>
        ))}
      </ul>
      {!groups.length && <p className="muted small">No group provided by the directory.</p>}
    </Card>
  );
}

function Sessions() {
  const [rows, setRows] = useState<SessionRow[]>([]);
  const load = useCallback(() => get<SessionRow[]>("/api/me/sessions").then(setRows).catch(() => undefined), []);
  useEffect(() => {
    load();
  }, [load]);
  const revokeOthers = async () => {
    await del("/api/me/sessions");
    load();
  };
  return (
    <Card
      title="Active sessions"
      actions={
        <button className="small" onClick={revokeOthers} disabled={rows.length < 2}>
          <Icon name="logout" /> Sign out other sessions
        </button>
      }
    >
      <ul className="list">
        {rows.map((s, i) => (
          <li key={i}>
            <span className="row" style={{ minWidth: 0 }}>
              <Icon name="monitor" />
              <span>{s.ip || "?"}</span>
              <small className="muted ellipsis" style={{ maxWidth: 420 }}>
                {s.user_agent || ""}
              </small>
            </span>
            {s.current ? <span className="badge ok">this session</span> : <small>{relTime(s.last_seen_at)}</small>}
          </li>
        ))}
      </ul>
    </Card>
  );
}
