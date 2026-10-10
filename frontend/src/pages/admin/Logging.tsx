import { useCallback, useEffect, useState } from "react";

import { fmtDate, get, post, put } from "../../api";
import { Card, Icon } from "../../ui";
import { msg } from "./common";

interface SettingsResp {
  logging: { masking_enabled: boolean; level: string };
  system: Record<string, string | number | boolean>;
}

export default function Logging() {
  const [s, setS] = useState<SettingsResp | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => get<SettingsResp>("/api/admin/settings").then(setS).catch((e) => setError(msg(e))), []);
  useEffect(() => {
    load();
  }, [load]);
  if (!s) return error ? <div className="alert error">{error}</div> : <div className="muted">Loading…</div>;

  const saveLogging = async (logging: SettingsResp["logging"]) => {
    await put("/api/admin/settings/logging", logging);
    load();
  };

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="grid-2">
        <Card title="Application logs" description="JSON lines on the container output, plus the remote syslog below.">
          <div className="stack">
            <label className="toggle">
              <input
                type="checkbox"
                checked={s.logging.masking_enabled}
                onChange={(e) => saveLogging({ ...s.logging, masking_enabled: e.target.checked })}
              />
              Mask personal data in logs (GDPR)
            </label>
            <p className="muted small" style={{ margin: 0 }}>
              E-mails, phone numbers, IBANs, card numbers and NIRs are replaced before writing (stdout and syslog).
            </p>
            <label className="inline">
              Log level
              <select value={s.logging.level} onChange={(e) => saveLogging({ ...s.logging, level: e.target.value })}>
                {["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"].map((l) => (
                  <option key={l}>{l}</option>
                ))}
              </select>
            </label>
          </div>
        </Card>
        <Card title="System settings" description="Read-only — set through LSX_* environment variables (see README).">
          <dl className="kv">
            {Object.entries(s.system).map(([k, v]) => (
              <div key={k} className="kv-row">
                <dt>{k}</dt>
                <dd>
                  <code>{String(v)}</code>
                </dd>
              </div>
            ))}
          </dl>
        </Card>
      </div>
      <RemoteSyslog />
    </div>
  );
}

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
    <Card
      title={
        <span className="row">
          <Icon name="upload" /> Remote syslog
        </span>
      }
      actions={
        st.active ? (
          <span className={`badge ${st.last_error ? "error" : "ok"}`}>
            {st.last_error ? "Error" : "Forwarding"} · {st.sent} sent · {st.dropped} dropped
          </span>
        ) : (
          <span className="badge">Inactive</span>
        )
      }
      description="Application logs and the audit trail are sent in RFC 5424 format to this server (SIEM, rsyslog, syslog-ng, Graylog…), after PII masking. Sending never slows the application down: if the server is unreachable, messages are dropped and retried every 30 s."
    >
      <div className="stack">
        <label className="toggle">
          <input type="checkbox" checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.target.checked })} />
          Forward logs to this server
        </label>
        <div className="form-grid" style={{ marginBottom: 0 }}>
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
            <p className="muted small" style={{ margin: 0 }}>
              The server certificate is verified against the system CAs and those imported in the PKI tab. A client
              certificate is only needed if the server requires mutual TLS.
            </p>
            {cfg.client_cert_subject && (
              <div className="row">
                <span className="small">
                  Client certificate: <code>{cfg.client_cert_subject}</code> — expires {fmtDate(cfg.client_cert_expires)}
                </span>
                <button className="small ghost danger" onClick={() => confirm("Remove the client certificate?") && save("", "")}>
                  Remove
                </button>
              </div>
            )}
            <div className="grid-2" style={{ gap: 12 }}>
              <label>
                {cfg.client_cert_subject ? "Replace client certificate (PEM)" : "Client certificate (PEM, optional)"}
                <textarea rows={3} className="mono" value={cert} onChange={(e) => setCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
              </label>
              <label>
                Client private key (unencrypted PEM — encrypted at rest)
                <textarea rows={3} className="mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
              </label>
            </div>
          </>
        )}
        <div className="row">
          <button className="primary" onClick={() => save()} disabled={cfg.enabled && !cfg.host}>
            <Icon name="save" /> Save
          </button>
          <button onClick={test} disabled={!cfg.host}>
            <Icon name="activity" /> Send a test message
          </button>
          <button className="ghost icon-only" onClick={load} title="Refresh the counters" aria-label="Refresh">
            <Icon name="refresh" />
          </button>
        </div>
        {st.last_error && <div className="alert error">Last error: {st.last_error}</div>}
        {status && <div className="alert ok">{status}</div>}
        {error && <div className="alert error">{error}</div>}
      </div>
    </Card>
  );
}
