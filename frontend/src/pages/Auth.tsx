import { useEffect, useState, type FormEvent } from "react";

import { ApiError, get, post } from "../api";
import { getAssertion } from "../webauthn";

interface Providers {
  local: boolean;
  ldap: boolean;
  oidc: boolean;
  oidc_name: string;
}

const SSO_ERRORS: Record<string, string> = {
  sso: "SSO login failed.",
  pending: "Your account has been created and is awaiting approval by an administrator.",
  disabled: "Your account is disabled.",
};

function errorText(e: unknown): string {
  return e instanceof ApiError ? e.message : "Unexpected error";
}

function AuthCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="brand big">
          <img src="/favicon.svg" alt="" width={32} height={32} />
          <span>Logstash Explorer</span>
        </div>
        <h1>{title}</h1>
        {children}
      </div>
    </div>
  );
}

export function Login({ onDone }: { onDone: () => void }) {
  const [providers, setProviders] = useState<Providers | null>(null);
  const [mode, setMode] = useState<"local" | "ldap">("local");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(() => SSO_ERRORS[new URLSearchParams(location.search).get("error") || ""] || "");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    get<Providers>("/api/auth/providers").then(setProviders).catch(() => undefined);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await post(mode === "ldap" ? "/api/auth/ldap/login" : "/api/auth/login", { username, password });
      if (location.pathname === "/login") history.replaceState(null, "", "/");
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
      setPassword("");
    }
  };

  return (
    <AuthCard title="Sign in">
      {providers?.ldap && (
        <div className="segmented">
          <button className={mode === "local" ? "active" : ""} onClick={() => setMode("local")} type="button">
            Local account
          </button>
          <button className={mode === "ldap" ? "active" : ""} onClick={() => setMode("ldap")} type="button">
            Directory (LDAPS)
          </button>
        </div>
      )}
      <form onSubmit={submit} className="stack">
        <label>
          Username
          <input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <div className="alert error">{error}</div>}
        <button className="primary" disabled={busy || !username || !password}>
          {busy ? "Checking…" : "Sign in"}
        </button>
      </form>
      {providers?.oidc && (
        <>
          <div className="divider">or</div>
          <a className="button block" href={`/api/auth/oidc/login?next=${encodeURIComponent("/")}`}>
            Continue with {providers.oidc_name}
          </a>
        </>
      )}
    </AuthCard>
  );
}

export function MfaChallenge({
  methods,
  onDone,
  onCancel,
}: {
  methods: string[];
  onDone: () => void;
  onCancel: () => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submitTotp = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await post("/api/auth/mfa/totp", { code });
      onDone();
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  const useKey = async () => {
    setBusy(true);
    setError("");
    try {
      const options = await post("/api/auth/mfa/webauthn/options");
      const credential = await getAssertion(options);
      await post("/api/auth/mfa/webauthn/verify", { credential });
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Security key rejected or operation cancelled.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title="Two-step verification">
      {methods.includes("totp") && (
        <form onSubmit={submitTotp} className="stack">
          <label>
            Authenticator app code
            <input
              autoFocus
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
          </label>
          <button className="primary" disabled={busy || code.length < 6}>
            Verify
          </button>
        </form>
      )}
      {methods.includes("webauthn") && (
        <button className="block" onClick={useKey} disabled={busy}>
          Use a security key / passkey
        </button>
      )}
      {error && <div className="alert error">{error}</div>}
      <button className="ghost block" onClick={onCancel}>
        Cancel
      </button>
    </AuthCard>
  );
}

export function ChangePassword({
  forced,
  onDone,
  onCancel,
}: {
  forced?: boolean;
  onDone: () => void;
  onCancel?: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return setError("The two passwords do not match.");
    setBusy(true);
    setError("");
    try {
      await post("/api/auth/change-password", { current_password: current, new_password: next });
      setOk(true);
      setCurrent("");
      setNext("");
      setConfirm("");
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <form onSubmit={submit} className="stack">
      {forced && (
        <div className="alert warn">
          For security reasons, you must set a new password before continuing.
        </div>
      )}
      <label>
        Current password
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </label>
      <label>
        New password
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        <small className="muted">At least 12 characters, using at least 3 of: lowercase, uppercase, digits, symbols.</small>
      </label>
      <label>
        Confirm
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </label>
      {error && <div className="alert error">{error}</div>}
      {ok && !forced && <div className="alert ok">Password changed. Your other sessions have been closed.</div>}
      <button className="primary" disabled={busy || !current || !next}>
        Change password
      </button>
      {onCancel && (
        <button type="button" className="ghost" onClick={onCancel}>
          Sign out
        </button>
      )}
    </form>
  );

  return forced ? <AuthCard title="New password required">{form}</AuthCard> : form;
}
