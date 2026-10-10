import { useCallback, useEffect, useState } from "react";

import { del, fmtDate, get, upload } from "../../api";
import { Card, Empty, Icon } from "../../ui";
import { msg } from "./common";

interface PkiFile {
  name: string;
  certificates: { subject: string; not_after: string }[];
}

const DAY = 86400000;

export default function Pki() {
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
  const remove = async (f: PkiFile) => {
    if (!confirm(`Remove ${f.name}? Connections relying on it will fail.`)) return;
    await del(`/api/admin/pki/${f.name}`);
    load();
  };

  return (
    <Card
      title="Internal certificate authorities"
      description="PEM certificates added here are trusted for outbound TLS: OIDC, LDAPS, AI endpoints, remote syslog and Vault. Private keys are rejected."
      actions={
        <label className="button primary small">
          <Icon name="upload" /> Import PEM…
          <input type="file" hidden accept=".pem,.crt,.cer" onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
        </label>
      }
    >
      {files.length ? (
        <ul className="list">
          {files.map((f) => (
            <li key={f.name} style={{ alignItems: "flex-start" }}>
              <div className="stack" style={{ gap: 4 }}>
                <strong className="row">
                  <Icon name="lock" /> {f.name}
                </strong>
                {f.certificates.map((c) => {
                  const days = Math.round((new Date(c.not_after).getTime() - Date.now()) / DAY);
                  return (
                    <span key={c.subject} className="small row">
                      <span className="muted">{c.subject}</span>
                      <span className={`badge ${days < 0 ? "error" : days < 30 ? "warn" : ""}`}>
                        {days < 0 ? "expired" : `expires ${fmtDate(c.not_after)}`}
                      </span>
                    </span>
                  );
                })}
              </div>
              <button className="small ghost danger" onClick={() => remove(f)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <Empty icon="lock">No internal CA imported — the system trust store is used.</Empty>
      )}
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}
