import { useCallback, useEffect, useState } from "react";

import { del, get, post, put, type Role } from "../../api";
import { Card, CopyButton, Empty, Icon } from "../../ui";
import { ROLES, ROLE_LABEL, msg } from "./common";

interface OidcCfg {
  enabled: boolean;
  issuer: string;
  client_id: string;
  scopes: string;
  groups_claim: string;
  display_name: string;
  client_secret_set: boolean;
  redirect_uri: string;
}
interface LdapCfg {
  enabled: boolean;
  url: string;
  bind_dn: string;
  user_base: string;
  user_filter: string;
  group_attribute: string;
  bind_password_set: boolean;
}
type TestResult = { ok: boolean; error?: string; [key: string]: unknown };

export default function Directory() {
  const [cfg, setCfg] = useState<{ oidc: OidcCfg; ldap: LdapCfg } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    get<{ oidc: OidcCfg; ldap: LdapCfg }>("/api/admin/directory").then(setCfg).catch((e) => setError(msg(e)));
  }, []);
  if (!cfg) return error ? <div className="alert error">{error}</div> : <div className="muted">Loading…</div>;
  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="grid-2">
        <OidcCard initial={cfg.oidc} />
        <LdapCard initial={cfg.ldap} />
      </div>
      <Provisioning />
    </div>
  );
}

function SecretInput({ isSet, value, onChange, label }: { isSet: boolean; value: string; onChange: (v: string) => void; label: string }) {
  return (
    <label>
      <span className="row tight">
        {label} {isSet && <span className="badge ok">set</span>}
      </span>
      <input
        type="password"
        autoComplete="new-password"
        placeholder={isSet ? "leave empty to keep" : ""}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <span className="hint">Encrypted at rest, never displayed again.</span>
    </label>
  );
}

function TestOutcome({ result }: { result: TestResult | null }) {
  if (!result) return null;
  if (!result.ok) return <div className="alert error">Connection failed: {result.error}</div>;
  return <div className="alert ok">{renderOk(result)}</div>;
}

function renderOk(result: TestResult) {
  if ("issuer" in result) {
    return (
      <span>
        Discovery OK — issuer <code>{String(result.issuer)}</code>
        {result.pkce_s256 ? ", PKCE S256 supported" : ", warning: PKCE S256 not advertised"}.
      </span>
    );
  }
  const user = result.user as { dn: string; display_name: string | null; groups: string[] } | null | undefined;
  return (
    <div className="stack" style={{ gap: 4 }}>
      <span>TLS and service account bind OK.</span>
      {user === null && <span>User not found with this filter.</span>}
      {user && (
        <>
          <span>
            User found: <code>{user.dn}</code> {user.display_name && `(${user.display_name})`}
          </span>
          <span className="field-chips">
            {user.groups.length ? user.groups.map((g) => <span key={g} className="badge">{g}</span>) : "no group"}
          </span>
        </>
      )}
    </div>
  );
}

function OidcCard({ initial }: { initial: OidcCfg }) {
  const [cfg, setCfg] = useState(initial);
  const [secret, setSecret] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [test, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);

  const save = async () => {
    setError("");
    setStatus("");
    try {
      const { client_secret_set: _s, redirect_uri: _r, ...rest } = cfg;
      void _s;
      void _r;
      setCfg(await put<OidcCfg>("/api/admin/directory/oidc", { ...rest, client_secret: secret || null }));
      setSecret("");
      setStatus("Saved.");
    } catch (e) {
      setError(msg(e));
    }
  };
  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      setTest(await post<TestResult>("/api/admin/directory/oidc/test"));
    } catch (e) {
      setTest({ ok: false, error: msg(e) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card
      title={
        <span className="row">
          <Icon name="key" /> OpenID Connect (SSO)
        </span>
      }
      actions={cfg.enabled ? <span className="badge ok">Enabled</span> : <span className="badge">Disabled</span>}
      description="Authorization code flow with PKCE (S256), state and nonce. Works with Entra ID, Keycloak, Okta, ADFS, Google Workspace…"
    >
      <div className="stack">
        <label className="toggle">
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} />
          Show the SSO button on the sign-in page
        </label>
        <div className="form-grid" style={{ marginBottom: 0 }}>
          <label className="span-2">
            Issuer URL
            <input
              placeholder="https://login.microsoftonline.com/<tenant>/v2.0"
              value={cfg.issuer}
              onChange={(e) => setCfg({ ...cfg, issuer: e.target.value.trim() })}
            />
          </label>
          <label>
            Client ID
            <input value={cfg.client_id} onChange={(e) => setCfg({ ...cfg, client_id: e.target.value.trim() })} />
          </label>
          <SecretInput label="Client secret" isSet={cfg.client_secret_set} value={secret} onChange={setSecret} />
          <label>
            Scopes
            <input value={cfg.scopes} onChange={(e) => setCfg({ ...cfg, scopes: e.target.value })} />
          </label>
          <label>
            Groups claim
            <input value={cfg.groups_claim} onChange={(e) => setCfg({ ...cfg, groups_claim: e.target.value.trim() })} />
          </label>
          <label>
            Button label
            <input value={cfg.display_name} onChange={(e) => setCfg({ ...cfg, display_name: e.target.value })} />
          </label>
        </div>
        <div className="alert info">
          <span>
            Redirect URI to register at the identity provider: <code>{cfg.redirect_uri}</code>
          </span>
          <CopyButton text={cfg.redirect_uri} />
        </div>
        <div className="row">
          <button className="primary" onClick={save}>
            <Icon name="save" /> Save
          </button>
          <button onClick={runTest} disabled={testing || !initial.issuer && !cfg.issuer}>
            {testing ? <span className="spinner" /> : <Icon name="activity" />} Test discovery
          </button>
          <span className="muted small">The test uses the saved settings.</span>
        </div>
        {status && <div className="alert ok">{status}</div>}
        {error && <div className="alert error">{error}</div>}
        <TestOutcome result={test} />
      </div>
    </Card>
  );
}

function LdapCard({ initial }: { initial: LdapCfg }) {
  const [cfg, setCfg] = useState(initial);
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [test, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);

  const save = async () => {
    setError("");
    setStatus("");
    try {
      const { bind_password_set: _p, ...rest } = cfg;
      void _p;
      setCfg(await put<LdapCfg>("/api/admin/directory/ldap", { ...rest, bind_password: password || null }));
      setPassword("");
      setStatus("Saved.");
    } catch (e) {
      setError(msg(e));
    }
  };
  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      setTest(await post<TestResult>("/api/admin/directory/ldap/test", { username: username || null }));
    } catch (e) {
      setTest({ ok: false, error: msg(e) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card
      title={
        <span className="row">
          <Icon name="network" /> LDAPS directory
        </span>
      }
      actions={cfg.enabled ? <span className="badge ok">Enabled</span> : <span className="badge">Disabled</span>}
      description="TLS is mandatory (ldaps://) and the server certificate is verified: import your internal CA in the PKI tab."
    >
      <div className="stack">
        <label className="toggle">
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} />
          Offer directory sign-in on the sign-in page
        </label>
        <div className="form-grid" style={{ marginBottom: 0 }}>
          <label className="span-2">
            Server URL
            <input placeholder="ldaps://dc01.corp.local:636" value={cfg.url} onChange={(e) => setCfg({ ...cfg, url: e.target.value.trim() })} />
          </label>
          <label className="span-2">
            Service account (bind DN)
            <input
              placeholder="CN=svc-logstash-explorer,OU=Service Accounts,DC=corp,DC=local"
              value={cfg.bind_dn}
              onChange={(e) => setCfg({ ...cfg, bind_dn: e.target.value })}
            />
          </label>
          <SecretInput label="Bind password" isSet={cfg.bind_password_set} value={password} onChange={setPassword} />
          <label>
            User search base
            <input placeholder="OU=Users,DC=corp,DC=local" value={cfg.user_base} onChange={(e) => setCfg({ ...cfg, user_base: e.target.value })} />
          </label>
          <label className="span-2">
            User filter
            <input className="mono" value={cfg.user_filter} onChange={(e) => setCfg({ ...cfg, user_filter: e.target.value })} />
            <span className="hint">
              Active Directory: <code>(&(objectClass=person)(sAMAccountName={"{username}"}))</code> — OpenLDAP:{" "}
              <code>(&(objectClass=inetOrgPerson)(uid={"{username}"}))</code>
            </span>
          </label>
          <label>
            Group attribute
            <input value={cfg.group_attribute} onChange={(e) => setCfg({ ...cfg, group_attribute: e.target.value.trim() })} />
          </label>
        </div>
        <div className="row">
          <button className="primary" onClick={save}>
            <Icon name="save" /> Save
          </button>
          <input placeholder="Username to look up (optional)" value={username} onChange={(e) => setUsername(e.target.value)} />
          <button onClick={runTest} disabled={testing || (!initial.url && !cfg.url)}>
            {testing ? <span className="spinner" /> : <Icon name="activity" />} Test connection
          </button>
        </div>
        <span className="muted small">The test uses the saved settings and never asks for the user's password.</span>
        {status && <div className="alert ok">{status}</div>}
        {error && <div className="alert error">{error}</div>}
        <TestOutcome result={test} />
      </div>
    </Card>
  );
}

interface Mapping {
  id: number;
  source: "oidc" | "ldap";
  group: string;
  role: Role;
}

function Provisioning() {
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
    <div className="grid-2">
      {prov && (
        <Card title="Provisioning of SSO / LDAPS accounts">
          <div className="stack">
            <label className="toggle">
              <input
                type="checkbox"
                checked={prov.auto_provisioning}
                onChange={(e) => saveProv({ ...prov, auto_provisioning: e.target.checked })}
              />
              Create and activate new accounts automatically
            </label>
            <p className="muted small" style={{ margin: 0 }}>
              When off, new accounts are created as <em>pending</em> and appear in the approval queue of the overview.
            </p>
            <label className="inline">
              Default role when no group matches
              <select value={prov.default_role} onChange={(e) => saveProv({ ...prov, default_role: e.target.value as Role })}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABEL[r]}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </Card>
      )}
      <Card
        title="Directory groups → roles"
        description="At each login, the highest role among the matching groups applies. For LDAP, use the full DN or the CN."
      >
        {rows.length ? (
          <table className="table dense">
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
                  <td>
                    <span className="badge">{m.source}</span>
                  </td>
                  <td>
                    <code>{m.group}</code>
                  </td>
                  <td>{ROLE_LABEL[m.role]}</td>
                  <td className="actions">
                    <button className="small ghost danger" onClick={() => del(`/api/admin/group-mappings/${m.id}`).then(load)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty icon="users">No mapping yet.</Empty>
        )}
        <div className="row" style={{ marginTop: 12 }}>
          <select value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} aria-label="Source">
            <option value="ldap">LDAPS</option>
            <option value="oidc">OIDC</option>
          </select>
          <input
            style={{ flex: 1, minWidth: 200 }}
            placeholder="CN=SOC-Analysts,OU=Groups,DC=corp"
            value={form.group}
            onChange={(e) => setForm({ ...form, group: e.target.value })}
          />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })} aria-label="Role">
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <button onClick={add} disabled={!form.group}>
            <Icon name="plus" /> Add
          </button>
        </div>
        {error && <div className="alert error">{error}</div>}
      </Card>
    </div>
  );
}
