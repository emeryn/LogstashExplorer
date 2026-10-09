import QRCode from "qrcode";
import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, del, fmtDate, get, post, type User } from "../api";
import { createCredential } from "../webauthn";
import { ChangePassword } from "./Auth";

interface Token {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}
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

const msg = (e: unknown) => (e instanceof ApiError ? e.message : "Operation cancelled or not possible");

export default function Profile({ user, onChanged }: { user: User; onChanged: () => void }) {
  return (
    <div className="page">
      <h1>My profile</h1>
      <div className="grid-2">
        <div className="card">
          <h2>Account</h2>
          <dl className="kv">
            <dt>Username</dt>
            <dd>{user.username}</dd>
            <dt>Name</dt>
            <dd>{user.display_name || "—"}</dd>
            <dt>Role</dt>
            <dd>{user.role}</dd>
            <dt>Source</dt>
            <dd>{user.auth_source}</dd>
            <dt>Last login</dt>
            <dd>{fmtDate(user.last_login_at)}</dd>
          </dl>
        </div>
        {user.auth_source === "local" && (
          <div className="card">
            <h2>Password</h2>
            <ChangePassword onDone={onChanged} />
          </div>
        )}
        <Totp user={user} onChanged={onChanged} />
        <SecurityKeys />
        {user.auth_source !== "local" && <DirectoryGroups />}
        <Tokens />
        <Sessions />
      </div>
    </div>
  );
}

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
    <div className="card">
      <h2>Authenticator app (TOTP)</h2>
      {user.totp_enabled ? (
        <>
          <p className="alert ok">TOTP enabled.</p>
          <button className="danger" onClick={disable}>
            Disable
          </button>
        </>
      ) : setup ? (
        <div className="stack">
          <canvas ref={canvas} className="qr" />
          <small className="muted">
            Scan the QR code or enter the key: <code>{setup.secret}</code>
          </small>
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
      ) : (
        <button onClick={start}>Set up</button>
      )}
      {error && <div className="alert error">{error}</div>}
    </div>
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
    <div className="card">
      <h2>Security keys / passkeys (WebAuthn)</h2>
      <ul className="list">
        {keys.map((k) => (
          <li key={k.id}>
            <span>
              {k.name} <small className="muted">{fmtDate(k.created_at)}</small>
            </span>
            <button className="ghost small danger" onClick={() => remove(k)}>
              Delete
            </button>
          </li>
        ))}
        {!keys.length && <li className="muted">No key registered.</li>}
      </ul>
      <button onClick={add}>Add a key</button>
      {error && <div className="alert error">{error}</div>}
    </div>
  );
}

export function TokenManager({ base, title }: { base: string; title: string }) {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [name, setName] = useState("");
  const [days, setDays] = useState(90);
  const [created, setCreated] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(() => get<Token[]>(base).then(setTokens).catch(() => undefined), [base]);
  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    setError("");
    try {
      const res = await post<{ token: string }>(base, { name, expires_in_days: days });
      setCreated(res.token);
      setName("");
      load();
    } catch (e) {
      setError(msg(e));
    }
  };
  const revoke = async (t: Token) => {
    if (!confirm(`Revoke token "${t.name}"?`)) return;
    await del(`${base}/${t.id}`);
    load();
  };

  return (
    <div className="card">
      <h2>{title}</h2>
      {created && (
        <div className="alert warn">
          Copy this token now, it will never be displayed again:
          <code className="secret">{created}</code>
          <button className="small" onClick={() => setCreated("")}>
            I have copied the token
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Prefix</th>
            <th>Expires</th>
            <th>Last used</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => (
            <tr key={t.id} className={t.revoked_at ? "muted" : ""}>
              <td>{t.name}</td>
              <td>
                <code>lsx_{t.prefix}_…</code>
              </td>
              <td>{fmtDate(t.expires_at)}</td>
              <td>{t.revoked_at ? "revoked" : fmtDate(t.last_used_at)}</td>
              <td>
                {!t.revoked_at && (
                  <button className="ghost small danger" onClick={() => revoke(t)}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row">
        <input placeholder="Token name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={90}>90 days</option>
          <option value={365}>1 year</option>
        </select>
        <button onClick={create} disabled={!name.trim()}>
          Create
        </button>
      </div>
      {error && <div className="alert error">{error}</div>}
    </div>
  );
}

function DirectoryGroups() {
  const [groups, setGroups] = useState<{ source: string; group: string; synced_at: string }[]>([]);
  useEffect(() => {
    get<typeof groups>("/api/groups/mine").then(setGroups).catch(() => undefined);
  }, []);
  return (
    <div className="card">
      <h2>My directory groups</h2>
      <p className="muted small">
        Seen at your last login; they determine your role and the projects shared with your teams.
      </p>
      <ul className="list">
        {groups.map((g) => (
          <li key={`${g.source}|${g.group}`}>
            <span>
              <span className="chip">{g.source.toUpperCase()}</span> {g.group}
            </span>
            <small className="muted">{fmtDate(g.synced_at)}</small>
          </li>
        ))}
        {!groups.length && <li className="muted">No group provided by the directory.</li>}
      </ul>
    </div>
  );
}

function Tokens() {
  return <TokenManager base="/api/me/tokens" title="Personal API tokens" />;
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
    <div className="card">
      <h2>Active sessions</h2>
      <ul className="list">
        {rows.map((s, i) => (
          <li key={i}>
            <span>
              {s.ip || "?"} — <small className="muted">{(s.user_agent || "").slice(0, 60)}</small>
            </span>
            <small>{s.current ? "this session" : fmtDate(s.last_seen_at)}</small>
          </li>
        ))}
      </ul>
      <button onClick={revokeOthers}>Sign out other sessions</button>
    </div>
  );
}
