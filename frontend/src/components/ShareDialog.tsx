import { useCallback, useEffect, useState } from "react";

import { ApiError, del, get, put } from "../api";

interface Share {
  user_id: string;
  username: string;
  display_name: string | null;
  permission: "read" | "write";
}
interface GroupShare {
  id: number;
  source: "ldap" | "oidc";
  group: string;
  permission: "read" | "write";
  members: number;
}
interface KnownGroup {
  source: "ldap" | "oidc";
  group: string;
  members: number;
}
interface DirectoryEntry {
  username: string;
  display_name: string | null;
}

export default function ShareDialog({
  projectId,
  projectName,
  onClose,
}: {
  projectId: string;
  projectName: string;
  onClose: () => void;
}) {
  const [shares, setShares] = useState<Share[]>([]);
  const [username, setUsername] = useState("");
  const [permission, setPermission] = useState<"read" | "write">("read");
  const [suggestions, setSuggestions] = useState<DirectoryEntry[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(
    () => get<Share[]>(`/api/pipelines/${projectId}/shares`).then(setShares).catch((e) => setError(String(e.message))),
    [projectId],
  );
  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (username.trim().length < 2) return setSuggestions([]);
    const t = setTimeout(
      () =>
        get<DirectoryEntry[]>(`/api/users/directory?q=${encodeURIComponent(username.trim())}`)
          .then(setSuggestions)
          .catch(() => setSuggestions([])),
      250,
    );
    return () => clearTimeout(t);
  }, [username]);

  const upsert = async (user: string, perm: "read" | "write") => {
    setError("");
    try {
      await put(`/api/pipelines/${projectId}/shares`, { username: user, permission: perm });
      setUsername("");
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Sharing failed");
    }
  };

  // ---- Directory groups ----
  const [groupShares, setGroupShares] = useState<GroupShare[]>([]);
  const [groups, setGroups] = useState<KnownGroup[]>([]);
  const [groupKey, setGroupKey] = useState("");
  const [groupPerm, setGroupPerm] = useState<"read" | "write">("read");

  const loadGroups = useCallback(() => {
    get<GroupShare[]>(`/api/pipelines/${projectId}/group-shares`).then(setGroupShares).catch(() => undefined);
    get<KnownGroup[]>("/api/groups/directory").then(setGroups).catch(() => undefined);
  }, [projectId]);
  useEffect(() => {
    loadGroups();
  }, [loadGroups]);

  const upsertGroup = async (source: string, group: string, perm: "read" | "write") => {
    setError("");
    try {
      await put(`/api/pipelines/${projectId}/group-shares`, { source, group, permission: perm });
      setGroupKey("");
      loadGroups();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Sharing failed");
    }
  };

  const addGroup = () => {
    const g = groups.find((x) => `${x.source}|${x.group}` === groupKey);
    if (g) upsertGroup(g.source, g.group, groupPerm);
  };

  const removeGroup = async (g: GroupShare) => {
    await del(`/api/pipelines/${projectId}/group-shares/${g.id}`);
    loadGroups();
  };

  const remove = async (s: Share) => {
    await del(`/api/pipelines/${projectId}/shares/${s.user_id}`);
    load();
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-label="Share project" onClick={(e) => e.stopPropagation()}>
        <h2>Share “{projectName}”</h2>
        <p className="muted small">
          <strong>Read</strong>: open, run and duplicate. <strong>Write</strong>: also save changes (concurrent editing
          conflicts are detected). Only the owner can share or delete.
        </p>
        <ul className="list">
          {shares.map((s) => (
            <li key={s.user_id}>
              <span>
                {s.username}
                {s.display_name && <small className="muted"> — {s.display_name}</small>}
              </span>
              <span className="row tight">
                <select value={s.permission} onChange={(e) => upsert(s.username, e.target.value as "read" | "write")}>
                  <option value="read">Read</option>
                  <option value="write">Write</option>
                </select>
                <button className="small ghost danger" onClick={() => remove(s)}>
                  Remove
                </button>
              </span>
            </li>
          ))}
          {!shares.length && <li className="muted">This project is not shared with anyone.</li>}
        </ul>
        <div className="row">
          <input
            list="lsx-directory"
            placeholder="Colleague username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
          <datalist id="lsx-directory">
            {suggestions.map((s) => (
              <option key={s.username} value={s.username}>
                {s.display_name || ""}
              </option>
            ))}
          </datalist>
          <select value={permission} onChange={(e) => setPermission(e.target.value as "read" | "write")}>
            <option value="read">Read</option>
            <option value="write">Write</option>
          </select>
          <button className="primary" onClick={() => upsert(username.trim(), permission)} disabled={!username.trim()}>
            Share
          </button>
        </div>
        <h3>Directory groups</h3>
        <p className="muted small">
          Every member of the group (LDAPS / SSO) gets access; membership is the one seen at their last login. The
          highest right between personal and group shares applies.
        </p>
        <ul className="list">
          {groupShares.map((g) => (
            <li key={g.id}>
              <span>
                <span className="chip">{g.source.toUpperCase()}</span> {g.group}{" "}
                <small className="muted">({g.members} known member(s))</small>
              </span>
              <span className="row tight">
                <select value={g.permission} onChange={(e) => upsertGroup(g.source, g.group, e.target.value as "read" | "write")}>
                  <option value="read">Read</option>
                  <option value="write">Write</option>
                </select>
                <button className="small ghost danger" onClick={() => removeGroup(g)}>
                  Remove
                </button>
              </span>
            </li>
          ))}
          {!groupShares.length && <li className="muted">No group.</li>}
        </ul>
        {groups.length ? (
          <div className="row">
            <select value={groupKey} onChange={(e) => setGroupKey(e.target.value)} aria-label="Group">
              <option value="">— Choose a group —</option>
              {groups.map((g) => (
                <option key={`${g.source}|${g.group}`} value={`${g.source}|${g.group}`}>
                  {g.source.toUpperCase()} · {g.group} ({g.members})
                </option>
              ))}
            </select>
            <select value={groupPerm} onChange={(e) => setGroupPerm(e.target.value as "read" | "write")}>
              <option value="read">Read</option>
              <option value="write">Write</option>
            </select>
            <button className="primary" onClick={addGroup} disabled={!groupKey}>
              Share with group
            </button>
          </div>
        ) : (
          <p className="muted small">
            No group available: only groups you are a member of (LDAPS/SSO login) are offered.
          </p>
        )}
        {error && <div className="alert error">{error}</div>}
        <div className="row end">
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
