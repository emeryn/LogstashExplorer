import { useCallback, useEffect, useState } from "react";

import { ApiError, del, fmtDate, get, patch, post, put, upload, type Role, type User } from "../api";
import { TokenManager } from "./Profile";

type Tab = "users" | "groups" | "ai" | "security" | "pki" | "audit";
const TABS: [Tab, string][] = [
  ["users", "Users"],
  ["groups", "Groups → roles"],
  ["ai", "AI agent"],
  ["security", "Security & logs"],
  ["pki", "PKI"],
  ["audit", "Audit"],
];
const ROLES: Role[] = ["user", "advanced", "admin"];
const ROLE_LABEL: Record<Role, string> = { user: "User", advanced: "Advanced user", admin: "Administrator" };
const msg = (e: unknown) => (e instanceof ApiError ? e.message : "Unexpected error");

export default function Admin({ currentUser }: { currentUser: User }) {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div className="page">
      <h1>Administration</h1>
      <div className="tabs big">
        {TABS.map(([id, label]) => (
          <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "users" && <Users currentUser={currentUser} />}
      {tab === "groups" && <Groups />}
      {tab === "ai" && <AiConfig />}
      {tab === "security" && <SecuritySettings />}
      {tab === "pki" && <Pki />}
      {tab === "audit" && <Audit />}
    </div>
  );
}

// ---- Users -------------------------------------------------------------------------------------
function Users({ currentUser }: { currentUser: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [secret, setSecret] = useState("");
  const [form, setForm] = useState({ username: "", display_name: "", role: "user" as Role, service_account: false });
  const [tokensFor, setTokensFor] = useState<User | null>(null);

  const load = useCallback(() => get<User[]>("/api/admin/users").then(setUsers).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setError("");
    try {
      await fn();
      load();
    } catch (e) {
      setError(msg(e));
    }
  };

  const create = () =>
    act(async () => {
      const res = await post<{ temporary_password: string | null }>("/api/admin/users", form);
      if (res.temporary_password) setSecret(`Temporary password for ${form.username}: ${res.temporary_password}`);
      setForm({ username: "", display_name: "", role: "user", service_account: false });
    });

  const resetPassword = (u: User) =>
    act(async () => {
      if (!confirm(`Reset the password of ${u.username}?`)) return;
      const res = await post<{ temporary_password: string }>(`/api/admin/users/${u.id}/reset-password`);
      setSecret(`New temporary password for ${u.username}: ${res.temporary_password}`);
    });

  return (
    <>
      {error && <div className="alert error">{error}</div>}
      {secret && (
        <div className="alert warn">
          <code className="secret">{secret}</code> Send it through a secure channel: it will not be displayed again. A
          change is enforced at first login.
          <button className="small" onClick={() => setSecret("")}>
            OK
          </button>
        </div>
      )}
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Source</th>
              <th>Role</th>
              <th>Status</th>
              <th>MFA</th>
              <th>Last login</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  {u.username}
                  {u.display_name && <small className="muted"> — {u.display_name}</small>}
                  {u.locked && <span className="badge error">locked</span>}
                  {u.must_change_password && <span className="badge warn">password change due</span>}
                </td>
                <td>{u.auth_source}</td>
                <td>
                  <select
                    value={u.role}
                    disabled={u.id === currentUser.id}
                    onChange={(e) => act(() => patch(`/api/admin/users/${u.id}`, { role: e.target.value }))}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <select
                    value={u.status}
                    disabled={u.id === currentUser.id}
                    onChange={(e) => act(() => patch(`/api/admin/users/${u.id}`, { status: e.target.value }))}
                  >
                    <option value="active">active</option>
                    <option value="pending">pending</option>
                    <option value="disabled">disabled</option>
                  </select>
                </td>
                <td>{u.totp_enabled ? "TOTP" : "—"}</td>
                <td>{fmtDate(u.last_login_at)}</td>
                <td className="actions">
                  {u.auth_source === "local" && (
                    <button className="small" onClick={() => resetPassword(u)}>
                      Reset password
                    </button>
                  )}
                  {u.locked && (
                    <button className="small" onClick={() => act(() => post(`/api/admin/users/${u.id}/unlock`))}>
                      Unlock
                    </button>
                  )}
                  {u.auth_source === "service" && (
                    <button className="small" onClick={() => setTokensFor(u)}>
                      Tokens
                    </button>
                  )}
                  <button
                    className="small"
                    onClick={() => confirm(`Reset MFA for ${u.username}?`) && act(() => post(`/api/admin/users/${u.id}/reset-mfa`))}
                  >
                    Reset MFA
                  </button>
                  {u.id !== currentUser.id && (
                    <button
                      className="small ghost danger"
                      onClick={() => confirm(`Delete ${u.username}?`) && act(() => del(`/api/admin/users/${u.id}`))}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {tokensFor && (
        <>
          <TokenManager base={`/api/admin/users/${tokensFor.id}/tokens`} title={`Tokens of service account ${tokensFor.username}`} />
          <button className="ghost" onClick={() => setTokensFor(null)}>
            Close
          </button>
        </>
      )}
      <div className="card">
        <h2>Create an account</h2>
        <div className="row">
          <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input
            placeholder="Display name"
            value={form.display_name}
            onChange={(e) => setForm({ ...form, display_name: e.target.value })}
          />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <label className="toggle">
            <input
              type="checkbox"
              checked={form.service_account}
              onChange={(e) => setForm({ ...form, service_account: e.target.checked })}
            />{" "}
            Service account (API tokens only)
          </label>
          <button className="primary" onClick={create} disabled={!form.username}>
            Create
          </button>
        </div>
      </div>
    </>
  );
}

// ---- Group mappings ------------------------------------------------------------------------------
interface Mapping {
  id: number;
  source: "oidc" | "ldap";
  group: string;
  role: Role;
}

function Groups() {
  const [rows, setRows] = useState<Mapping[]>([]);
  const [form, setForm] = useState({ source: "ldap", group: "", role: "user" as Role });
  const [prov, setProv] = useState<{ auto_provisioning: boolean; default_role: Role } | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setRows(await get<Mapping[]>("/api/admin/group-mappings"));
    setProv((await get<{ provisioning: { auto_provisioning: boolean; default_role: Role } }>("/api/admin/settings")).provisioning);
  }, []);
  useEffect(() => {
    load().catch((e) => setError(msg(e)));
  }, [load]);

  const add = async () => {
    try {
      await post("/api/admin/group-mappings", form);
      setForm({ ...form, group: "" });
      load();
    } catch (e) {
      setError(msg(e));
    }
  };
  const saveProv = async (next: { auto_provisioning: boolean; default_role: Role }) => {
    setProv(await put("/api/admin/settings/provisioning", next));
  };

  return (
    <>
      {error && <div className="alert error">{error}</div>}
      {prov && (
        <div className="card">
          <h2>Auto-provisioning (OIDC / LDAPS)</h2>
          <label className="toggle">
            <input
              type="checkbox"
              checked={prov.auto_provisioning}
              onChange={(e) => saveProv({ ...prov, auto_provisioning: e.target.checked })}
            />{" "}
            Automatically create and activate new SSO/LDAP accounts
          </label>
          <p className="muted small">
            Disabled: new accounts are created as "pending" and must be approved in the Users tab.
          </p>
          <label className="inline">
            Default role (when no group matches)
            <select value={prov.default_role} onChange={(e) => saveProv({ ...prov, default_role: e.target.value as Role })}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
      <div className="card">
        <h2>Directory group → role mapping</h2>
        <p className="muted small">
          At each login, the highest role among the matching groups is applied. For LDAP, enter the full DN or the CN of
          the group.
        </p>
        <table className="table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Group</th>
              <th>Role</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr key={m.id}>
                <td>{m.source}</td>
                <td>
                  <code>{m.group}</code>
                </td>
                <td>{ROLE_LABEL[m.role]}</td>
                <td>
                  <button className="small ghost danger" onClick={() => del(`/api/admin/group-mappings/${m.id}`).then(load)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="row">
          <select value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })}>
            <option value="ldap">LDAPS</option>
            <option value="oidc">OIDC</option>
          </select>
          <input placeholder="Group (e.g. CN=SOC-Analysts,OU=Groups,DC=corp)" value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })} />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <button onClick={add} disabled={!form.group}>
            Add
          </button>
        </div>
      </div>
    </>
  );
}

// ---- AI configuration ----------------------------------------------------------------------------
interface AiCfg {
  provider: "ollama" | "openai";
  base_url: string;
  model: string;
  temperature: number;
  timeout_s: number;
  max_iterations: number;
  ecs_compatibility: "disabled" | "v1" | "v8";
  api_key_set: boolean;
  extra_header_names: string[];
}

function AiConfig() {
  const [cfg, setCfg] = useState<AiCfg | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [headers, setHeaders] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [models, setModels] = useState<{ id: string; label: string }[]>([]);
  const [modelsState, setModelsState] = useState<"idle" | "loading" | "ok" | "error">("idle");
  const [modelsError, setModelsError] = useState("");
  const [manualModel, setManualModel] = useState(false);
  useEffect(() => {
    get<AiCfg>("/api/admin/ai").then(setCfg).catch((e) => setError(msg(e)));
  }, []);

  const provider = cfg?.provider;
  const baseUrl = cfg?.base_url;
  const fetchModels = useCallback(async () => {
    if (!provider || !baseUrl || !/^https?:\/\/.+/.test(baseUrl)) return;
    setModelsState("loading");
    try {
      const res = await post<{ ok: boolean; models: { id: string; label: string }[]; error?: string }>(
        "/api/admin/ai/models",
        { provider, base_url: baseUrl, api_key: apiKey || null },
      );
      setModels(res.models);
      setModelsError(res.error || "");
      setModelsState(res.ok ? "ok" : "error");
    } catch (e) {
      setModels([]);
      setModelsError(msg(e));
      setModelsState("error");
    }
  }, [provider, baseUrl, apiKey]);

  // Query the server's model list whenever the endpoint (or key) changes, debounced while typing.
  useEffect(() => {
    const t = setTimeout(fetchModels, 600);
    return () => clearTimeout(t);
  }, [fetchModels]);

  if (!cfg) return error ? <div className="alert error">{error}</div> : null;
  const modelKnown = models.some((m) => m.id === cfg.model);
  const useSelect = modelsState === "ok" && models.length > 0 && !manualModel;

  const save = async () => {
    setError("");
    setStatus("");
    let extra: Record<string, string> | null = null;
    if (headers.trim()) {
      try {
        extra = Object.fromEntries(
          headers
            .split("\n")
            .filter((l) => l.includes("="))
            .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]),
        );
      } catch {
        return setError("Expected format: NAME=value, one per line");
      }
    }
    try {
      const { api_key_set: _a, extra_header_names: _b, ...rest } = cfg;
      void _a;
      void _b;
      setCfg(await put<AiCfg>("/api/admin/ai", { ...rest, api_key: apiKey || null, extra_headers: extra }));
      setApiKey("");
      setHeaders("");
      setStatus("Configuration saved (secrets encrypted at rest).");
    } catch (e) {
      setError(msg(e));
    }
  };
  const test = async () => {
    setStatus("Testing…");
    const res = await post<{ ok: boolean; reply?: string; error?: string }>("/api/admin/ai/test");
    setStatus(res.ok ? `Connection OK — reply: ${res.reply}` : `Failed: ${res.error}`);
  };

  return (
    <div className="card">
      <h2>Autonomous agent LLM provider</h2>
      <div className="form-grid">
        <label>
          Provider
          <select
            value={cfg.provider}
            onChange={(e) => {
              const provider = e.target.value as AiCfg["provider"];
              setCfg({
                ...cfg,
                provider,
                base_url: provider === "openai" ? "https://api.openai.com/v1" : "http://host.docker.internal:11434",
              });
            }}
          >
            <option value="ollama">Ollama (local)</option>
            <option value="openai">OpenAI / OpenAI-compatible</option>
          </select>
        </label>
        <label>
          Endpoint URL
          <input value={cfg.base_url} onChange={(e) => setCfg({ ...cfg, base_url: e.target.value })} />
        </label>
        <label>
          <span className="row tight">
            Model
            <span className="spacer" />
            {modelsState === "loading" && <span className="spinner" />}
            {modelsState === "ok" && <small className="muted">{models.length} available</small>}
            <button type="button" className="small ghost" onClick={fetchModels} title="Query the server">
              ↻
            </button>
          </span>
          {useSelect ? (
            <select
              value={modelKnown ? cfg.model : ""}
              onChange={(e) =>
                e.target.value === "__manual__" ? setManualModel(true) : setCfg({ ...cfg, model: e.target.value })
              }
            >
              {!modelKnown && <option value="">{cfg.model ? `${cfg.model} (not on the server)` : "— Choose —"}</option>}
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
              <option value="__manual__">Manual entry…</option>
            </select>
          ) : (
            <input value={cfg.model} onChange={(e) => setCfg({ ...cfg, model: e.target.value })} />
          )}
          {modelsState === "error" && <small className="error-text">{modelsError} — manual entry possible.</small>}
          {modelsState === "ok" && !models.length && <small className="muted">No model on this server.</small>}
          {manualModel && models.length > 0 && (
            <button type="button" className="small ghost" onClick={() => setManualModel(false)}>
              Back to the list
            </button>
          )}
        </label>
        <label>
          Temperature
          <input type="number" step="0.1" min={0} max={2} value={cfg.temperature} onChange={(e) => setCfg({ ...cfg, temperature: Number(e.target.value) })} />
        </label>
        <label>
          Timeout (s)
          <input type="number" min={5} max={900} value={cfg.timeout_s} onChange={(e) => setCfg({ ...cfg, timeout_s: Number(e.target.value) })} />
        </label>
        <label>
          Default max iterations
          <input type="number" min={1} max={20} value={cfg.max_iterations} onChange={(e) => setCfg({ ...cfg, max_iterations: Number(e.target.value) })} />
        </label>
        <label>
          Pipeline ECS compatibility
          <select value={cfg.ecs_compatibility} onChange={(e) => setCfg({ ...cfg, ecs_compatibility: e.target.value as AiCfg["ecs_compatibility"] })}>
            <option value="disabled">disabled</option>
            <option value="v1">v1</option>
            <option value="v8">v8</option>
          </select>
        </label>
        <label>
          API key {cfg.api_key_set && <span className="badge ok">set</span>}
          <input
            type="password"
            autoComplete="off"
            placeholder={cfg.api_key_set ? "leave empty to keep" : "sk-…"}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
        </label>
      </div>
      <label>
        Extra variables / HTTP headers (NAME=value, one per line — encrypted, never displayed again)
        {cfg.extra_header_names.length > 0 && <small className="muted"> Current: {cfg.extra_header_names.join(", ")}</small>}
        <textarea rows={3} className="mono" value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="OpenAI-Organization=org-xxx" />
      </label>
      <div className="row">
        <button className="primary" onClick={save}>
          Save
        </button>
        <button onClick={test}>Test connection</button>
      </div>
      {status && <div className="alert ok">{status}</div>}
      {error && <div className="alert error">{error}</div>}
    </div>
  );
}

// ---- Security & logging ----------------------------------------------------------------------------
interface SettingsResp {
  logging: { masking_enabled: boolean; level: string };
  system: Record<string, string | number | boolean>;
}

function SecuritySettings() {
  const [s, setS] = useState<SettingsResp | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => get<SettingsResp>("/api/admin/settings").then(setS).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);
  if (!s) return error ? <div className="alert error">{error}</div> : null;

  const saveLogging = async (logging: SettingsResp["logging"]) => {
    await put("/api/admin/settings/logging", logging);
    load();
  };

  return (
    <div className="grid-2">
      <div className="card">
        <h2>Logging</h2>
        <label className="toggle">
          <input type="checkbox" checked={s.logging.masking_enabled} onChange={(e) => saveLogging({ ...s.logging, masking_enabled: e.target.checked })} />{" "}
          Mask personal data in logs (GDPR)
        </label>
        <p className="muted small">Emails, phone numbers, IBANs, card numbers and NIRs are replaced before writing (stdout and syslog).</p>
        <label className="inline">
          Log level
          <select value={s.logging.level} onChange={(e) => saveLogging({ ...s.logging, level: e.target.value })}>
            {["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"].map((l) => (
              <option key={l}>{l}</option>
            ))}
          </select>
        </label>
      </div>
      <RemoteSyslog />
      <div className="card">
        <h2>System settings (read-only)</h2>
        <dl className="kv">
          {Object.entries(s.system).map(([k, v]) => (
            <div key={k} className="kv-row">
              <dt>{k}</dt>
              <dd>{String(v)}</dd>
            </div>
          ))}
        </dl>
        <p className="muted small">Set through LSX_* environment variables (see README).</p>
      </div>
    </div>
  );
}

// ---- Remote syslog -----------------------------------------------------------------------------------
interface SyslogCfg {
  enabled: boolean;
  host: string;
  port: number;
  protocol: "udp" | "tcp" | "tls";
  framing: "octet_counting" | "lf";
  facility: string;
  client_cert_subject: string | null;
  client_cert_expires: string | null;
  status: { active: boolean; sent?: number; dropped?: number; last_error?: string | null };
}
const FACILITIES = ["local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "user", "daemon", "auth", "kern"];
const DEFAULT_PORT = { udp: 514, tcp: 514, tls: 6514 };

function RemoteSyslog() {
  const [cfg, setCfg] = useState<SyslogCfg | null>(null);
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(() => get<SyslogCfg>("/api/admin/syslog").then(setCfg).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);
  if (!cfg) return error ? <div className="alert error">{error}</div> : null;

  const save = async (clientCert: string | null = cert || null, clientKey: string | null = key || null) => {
    setError("");
    setStatus("");
    try {
      const { client_cert_subject: _s, client_cert_expires: _e, status: _st, ...rest } = cfg;
      void _s;
      void _e;
      void _st;
      setCfg(await put<SyslogCfg>("/api/admin/syslog", { ...rest, client_cert: clientCert, client_key: clientKey }));
      setCert("");
      setKey("");
      setStatus("Settings saved.");
    } catch (e) {
      setError(msg(e));
    }
  };
  const test = async () => {
    setError("");
    setStatus("Sending a test message…");
    const res = await post<{ ok: boolean; unconfirmed?: boolean; error?: string }>("/api/admin/syslog/test");
    if (!res.ok) {
      setStatus("");
      setError(`Test failed: ${res.error}`);
    } else {
      setStatus(res.unconfirmed ? "Test message sent (UDP: delivery cannot be confirmed)." : "Test message delivered.");
    }
  };

  const st = cfg.status;
  return (
    <div className="card">
      <h2>Remote syslog</h2>
      <p className="muted small">
        Application logs and the audit trail are sent in RFC 5424 format to this server, after PII masking. Sending never
        slows the application down: if the server is unreachable, messages are dropped and retried every 30 s.
      </p>
      <label className="toggle">
        <input type="checkbox" checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} /> Forward
        logs to this server
      </label>
      <div className="form-grid">
        <label>
          Host
          <input value={cfg.host} placeholder="siem.example.org" onChange={(e) => setCfg({ ...cfg, host: e.target.value.trim() })} />
        </label>
        <label>
          Protocol
          <select
            value={cfg.protocol}
            onChange={(e) => {
              const protocol = e.target.value as SyslogCfg["protocol"];
              setCfg({ ...cfg, protocol, port: cfg.port === DEFAULT_PORT[cfg.protocol] ? DEFAULT_PORT[protocol] : cfg.port });
            }}
          >
            <option value="tls">TLS (RFC 5425, recommended)</option>
            <option value="tcp">TCP (unencrypted)</option>
            <option value="udp">UDP (unencrypted, no delivery guarantee)</option>
          </select>
        </label>
        <label>
          Port
          <input type="number" min={1} max={65535} value={cfg.port} onChange={(e) => setCfg({ ...cfg, port: Number(e.target.value) })} />
        </label>
        {cfg.protocol !== "udp" && (
          <label>
            Framing
            <select value={cfg.framing} onChange={(e) => setCfg({ ...cfg, framing: e.target.value as SyslogCfg["framing"] })}>
              <option value="octet_counting">Octet counting (RFC 6587)</option>
              <option value="lf">Newline-delimited</option>
            </select>
          </label>
        )}
        <label>
          Facility
          <select value={cfg.facility} onChange={(e) => setCfg({ ...cfg, facility: e.target.value })}>
            {FACILITIES.map((f) => (
              <option key={f}>{f}</option>
            ))}
          </select>
        </label>
      </div>
      {cfg.protocol === "tls" && (
        <>
          <p className="muted small">
            The server certificate is verified against the system CAs and those imported in the PKI tab. A client
            certificate is only needed if the server requires mutual TLS.
          </p>
          {cfg.client_cert_subject ? (
            <div className="row">
              <span className="small">
                Client certificate: <code>{cfg.client_cert_subject}</code> — expires {fmtDate(cfg.client_cert_expires)}
              </span>
              <button className="small ghost danger" onClick={() => confirm("Remove the client certificate?") && save("", "")}>
                Remove
              </button>
            </div>
          ) : null}
          <label>
            {cfg.client_cert_subject ? "Replace client certificate (PEM)" : "Client certificate (PEM, optional)"}
            <textarea rows={3} className="mono" value={cert} onChange={(e) => setCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
          </label>
          <label>
            Client private key (unencrypted PEM — encrypted at rest, never displayed again)
            <textarea rows={3} className="mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
          </label>
        </>
      )}
      <div className="row">
        <button className="primary" onClick={() => save()} disabled={cfg.enabled && !cfg.host}>
          Save
        </button>
        <button onClick={test} disabled={!cfg.host}>
          Send a test message
        </button>
        <button className="ghost small" onClick={load} title="Refresh the counters">
          ↻
        </button>
      </div>
      {st.active ? (
        <p className={`small ${st.last_error ? "error-text" : "muted"}`}>
          Forwarding active — {st.sent} sent, {st.dropped} dropped
          {st.last_error ? ` — last error: ${st.last_error}` : ""}
        </p>
      ) : (
        <p className="muted small">Forwarding inactive.</p>
      )}
      {status && <div className="alert ok">{status}</div>}
      {error && <div className="alert error">{error}</div>}
    </div>
  );
}

// ---- PKI -----------------------------------------------------------------------------------------
interface PkiFile {
  name: string;
  certificates: { subject: string; not_after: string }[];
}

function Pki() {
  const [files, setFiles] = useState<PkiFile[]>([]);
  const [error, setError] = useState("");
  const load = useCallback(() => get<PkiFile[]>("/api/admin/pki").then(setFiles).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);

  const onFile = async (f: File) => {
    setError("");
    try {
      await upload("/api/admin/pki", f);
      load();
    } catch (e) {
      setError(msg(e));
    }
  };

  return (
    <div className="card">
      <h2>Internal certificate authorities</h2>
      <p className="muted small">
        PEM certificates added here are trusted for outbound connections (OIDC, LDAPS, AI endpoints, Vault). Private keys
        are rejected.
      </p>
      <ul className="list">
        {files.map((f) => (
          <li key={f.name}>
            <span>
              <strong>{f.name}</strong>
              {f.certificates.map((c) => (
                <small key={c.subject} className="muted block">
                  {c.subject} — expires {fmtDate(c.not_after)}
                </small>
              ))}
            </span>
            <button className="small ghost danger" onClick={() => del(`/api/admin/pki/${f.name}`).then(load)}>
              Delete
            </button>
          </li>
        ))}
        {!files.length && <li className="muted">No certificate imported.</li>}
      </ul>
      <label className="button">
        Import a PEM certificate…
        <input type="file" hidden accept=".pem,.crt,.cer" onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
      </label>
      {error && <div className="alert error">{error}</div>}
    </div>
  );
}

// ---- Audit ---------------------------------------------------------------------------------------
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

function Audit() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const query = new URLSearchParams({ ...(action && { action }), ...(actor && { actor }) }).toString();
  const load = useCallback(() => get<AuditRow[]>(`/api/admin/audit?limit=200&${query}`).then(setRows).catch(() => undefined), [query]);
  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="card">
      <div className="row">
        <input placeholder="Action (prefix, e.g. auth.)" value={action} onChange={(e) => setAction(e.target.value)} />
        <input placeholder="User" value={actor} onChange={(e) => setActor(e.target.value)} />
        <button onClick={load}>Filter</button>
        <a className="button" href={`/api/admin/audit/export?${query}`}>
          Export CSV
        </a>
      </div>
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
              <td>{fmtDate(r.ts)}</td>
              <td>{r.actor}</td>
              <td>{r.ip}</td>
              <td>
                <code>{r.action}</code>
              </td>
              <td>{r.target}</td>
              <td>
                <span className={`badge ${r.outcome === "success" ? "ok" : "error"}`}>{r.outcome}</span>
              </td>
              <td className="mono small">{JSON.stringify(r.details)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
