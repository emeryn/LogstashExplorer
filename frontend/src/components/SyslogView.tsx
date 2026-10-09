import { useState } from "react";

import type { SyslogFrame, SyslogResult } from "../api";

const FIELD_LABELS: [keyof SyslogFrame["fields"], string][] = [
  ["pri", "pri"],
  ["facility", "syslogfacility-text"],
  ["severity", "syslogseverity-text"],
  ["timereported", "timereported"],
  ["hostname", "hostname"],
  ["app_name", "app-name / programname"],
  ["procid", "procid"],
  ["msgid", "msgid"],
  ["structured_data", "structured-data"],
  ["msg", "msg"],
];

/** Make invisible characters visible in the raw wire frame. */
function visible(raw: string): string {
  return raw.replace(/\r/g, "␍").replace(/\n$/, "␊").replace(/\n/g, "␊\n").replace(/\t/g, "␉");
}

function fieldValue(v: unknown): string {
  if (v === undefined || v === null) return "—";
  if (Array.isArray(v))
    return v
      .map((e: { id: string; params: Record<string, string> }) =>
        `[${e.id}${Object.entries(e.params)
          .map(([k, val]) => ` ${k}="${val}"`)
          .join("")}]`,
      )
      .join("");
  return String(v);
}

export default function SyslogView({ syslog, configWarnings }: { syslog: SyslogResult; configWarnings: string[] }) {
  const [copied, setCopied] = useState(false);
  const frames = syslog.frames;
  const errorCount = frames.reduce((n, f) => n + f.errors.length, 0);
  const warnCount = frames.reduce((n, f) => n + f.warnings.length, 0);

  const copy = async () => {
    await navigator.clipboard.writeText(frames.map((f) => f.raw).join(""));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="scroll syslog">
      <div className="summary">
        <span className="chip">{frames.length} frame(s)</span>
        {syslog.outputs.map((o) => (
          <span key={o.line} className="chip" title={`syslog output line ${o.line}`}>
            l.{o.line} · {o.rfc} · {o.protocol}
          </span>
        ))}
        <span className={`chip ${errorCount ? "error" : "ok"}`}>{errorCount} error(s)</span>
        {warnCount > 0 && <span className="chip warn">{warnCount} warning(s)</span>}
        <span className="spacer" />
        <button className="small" onClick={copy} disabled={!frames.length}>
          {copied ? "Copied ✓" : "Copy raw frames"}
        </button>
      </div>
      <p className="muted small">
        Frames actually written by <code>logstash-output-syslog</code> (host, port and TLS redirected to a local capture;
        content identical to production). Decoded according to rsyslog properties.
      </p>
      {configWarnings.map((w, i) => (
        <div key={i} className="alert warn">
          {w}
        </div>
      ))}
      {!frames.length && <div className="alert warn">No frame emitted (no event reached the syslog output).</div>}
      {frames.map((f, i) => (
        <div key={i} className={`frame ${f.errors.length ? "has-error" : ""}`}>
          <div className="frame-head">
            <strong>#{i + 1}</strong>
            <span className="chip">{f.transport.toUpperCase()}</span>
            <span className={`chip ${f.format === "unknown" ? "error" : ""}`}>{f.format}</span>
            <span className="chip">{f.bytes} bytes</span>
            {f.fields.facility && (
              <span className="chip">
                {f.fields.facility}.{f.fields.severity} ({f.fields.facility_code}/{f.fields.severity_code})
              </span>
            )}
          </div>
          <pre className="raw mono">{visible(f.raw)}</pre>
          {f.errors.map((e, j) => (
            <div key={j} className="alert error">
              {e}
            </div>
          ))}
          {f.warnings.map((w, j) => (
            <div key={j} className="alert warn">
              {w}
            </div>
          ))}
          <details>
            <summary>Fields seen by rsyslog</summary>
            <table className="table dense">
              <tbody>
                {FIELD_LABELS.filter(([k]) => f.fields[k] !== undefined).map(([k, label]) => (
                  <tr key={k}>
                    <th>{label}</th>
                    <td className="mono">{fieldValue(f.fields[k])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </div>
      ))}
    </div>
  );
}
