import Editor, { type OnMount } from "@monaco-editor/react";
import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from "react";

import {
  ApiError,
  del,
  fmtDate,
  get,
  hasRole,
  post,
  put,
  stream,
  upload,
  type Parser,
  type ParserSummary,
  type Project,
  type ProjectMeta,
  type RunResult,
  type User,
} from "../api";
import InputFieldsEditor, { fieldError, toFields, toRows, type FieldRow } from "../components/InputFields";
import { ParserLibraryDialog } from "../components/ParserLibrary";
import ShareDialog from "../components/ShareDialog";
import SyslogView from "../components/SyslogView";
import { monaco } from "../monaco";
import { useEditorTheme } from "../theme";
import { Icon } from "../ui";

type InputFormat = "lines" | "json";
type AgentEvent = Record<string, unknown> & { type: string; n?: number };

const ACCESS_LABEL = { owner: "owner", write: "read/write", read: "read-only" };

const SYSLOG_TEMPLATE = `output {
  # Production output: host/port/protocol/TLS are redirected to a local capture during
  # the test; everything else (format, fields) is executed as is by Logstash.
  syslog {
    host => "rsyslog.example.org"
    port => 514
    protocol => "tcp"            # tcp | udp | ssl-tcp
    rfc => "rfc5424"             # rfc5424 | rfc3164
    facility => "daemon"
    severity => "informational"
    sourcehost => "%{host}"      # ECS v8: "%{[host][hostname]}"
    appname => "logstash"
    procid => "-"
    msgid => "-"
  }
}
`;

const SAMPLE_LOGS = `192.168.1.10 - - [07/Oct/2026:10:15:32 +0200] "GET /index.html HTTP/1.1" 200 5320 "-" "Mozilla/5.0"
10.0.0.5 - admin [07/Oct/2026:10:15:40 +0200] "POST /api/login HTTP/1.1" 401 112 "-" "curl/8.5.0"
203.0.113.42 - - [07/Oct/2026:10:16:01 +0200] "GET /images/logo.png HTTP/1.1" 304 0 "https://example.org/" "Mozilla/5.0"`;

const SAMPLE_CONFIG = `filter {
  grok {
    match => { "message" => "%{COMBINEDAPACHELOG}" }
  }
  date {
    match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    target => "@timestamp"
  }
  mutate {
    convert => { "response" => "integer" "bytes" => "integer" }
  }
}
`;

const EDITOR_OPTIONS = {
  minimap: { enabled: false },
  fontSize: 13,
  scrollBeyondLastLine: false,
  automaticLayout: true,
  tabSize: 2,
  renderWhitespace: "selection" as const,
};
const MAX_TEXT = 5 * 1024 * 1024;
const DETECT_SAMPLE = 64 * 1024;

function failureTags(events: Record<string, unknown>[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of events) {
    const tags = Array.isArray(e.tags) ? e.tags : [];
    for (const t of tags) if (typeof t === "string" && /^_.*(failure|error)/i.test(t)) counts[t] = (counts[t] || 0) + 1;
  }
  return counts;
}

/** Map "line N" mentions from the runner / Logstash to editor markers. */
function markersFor(result: RunResult | null): monaco.editor.IMarkerData[] {
  if (!result) return [];
  const lines = [...result.config_errors, ...result.errors];
  const markers: monaco.editor.IMarkerData[] = [];
  for (const msg of lines) {
    const m = /line (\d+)(?:, column (\d+))?/.exec(msg);
    if (!m) continue;
    const line = Number(m[1]);
    const col = m[2] ? Number(m[2]) : 1;
    markers.push({
      severity: monaco.MarkerSeverity.Error,
      message: msg.replace(/^\[[^\]]*\]\[[^\]]*\]\[[^\]]*\]\s*/, "").slice(0, 600),
      startLineNumber: line,
      startColumn: col,
      endLineNumber: line,
      endColumn: col + 200,
    });
  }
  return markers;
}

export default function Workspace({
  user,
  pendingParser,
  onParserConsumed,
}: {
  user: User;
  pendingParser: { parser: Parser; withSample: boolean } | null;
  onParserConsumed: () => void;
}) {
  const canAgent = hasRole(user, "advanced");
  const editorTheme = useEditorTheme();

  // Shared workspace state (the three panels are views of it)
  const [input, setInput] = useState(SAMPLE_LOGS);
  const [inputFormat, setInputFormat] = useState<InputFormat>("lines");
  const [fieldRows, setFieldRows] = useState<FieldRow[]>([]);
  const [config, setConfig] = useState(SAMPLE_CONFIG);
  const [result, setResult] = useState<RunResult | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState("");
  const [autoRun, setAutoRun] = useState(false);
  const [leftTab, setLeftTab] = useState<"input" | "fields" | "agent">("input");
  const [rightTab, setRightTab] = useState<"output" | "logs" | "syslog" | "agent">("output");
  const [dragging, setDragging] = useState(false);
  const [importInfo, setImportInfo] = useState("");
  const [ecs, setEcs] = useState("disabled");

  // Parser library & format detection
  const [libraryOpen, setLibraryOpen] = useState(false);
  const [suggestions, setSuggestions] = useState<ParserSummary[]>([]);
  const [appliedParser, setAppliedParser] = useState<string | null>(null);
  const [dismissedSuggestion, setDismissedSuggestion] = useState<string | null>(null);

  // Projects
  const [projects, setProjects] = useState<ProjectMeta[]>([]);
  const [current, setCurrent] = useState<ProjectMeta | null>(null);
  const [remoteChange, setRemoteChange] = useState<ProjectMeta | null>(null);
  const [conflict, setConflict] = useState("");
  const [sharing, setSharing] = useState(false);

  // Agent
  const [instructions, setInstructions] = useState(
    "Extract the client IP into client.ip, parse the Apache timestamp into @timestamp, convert the HTTP status code to an integer and ignore requests coming from the internal 10.0.0.0/8 network.",
  );
  const [expected, setExpected] = useState("");
  const [maxIter, setMaxIter] = useState(5);
  const [agentEvents, setAgentEvents] = useState<AgentEvent[]>([]);
  const [agentRunning, setAgentRunning] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const configEditorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const runRef = useRef<() => void>(() => undefined);

  const inputFields = useMemo(() => toFields(fieldRows), [fieldRows]);
  const fieldsInvalid = fieldRows.some((r) => (r.name || r.value) && fieldError(r.name, r.value));

  const loadProjects = useCallback(() => {
    get<ProjectMeta[]>("/api/pipelines").then(setProjects).catch(() => undefined);
  }, []);
  useEffect(() => {
    loadProjects();
    get<{ ecs_compatibility: string }>("/api/workspace/settings")
      .then((s) => setEcs(s.ecs_compatibility))
      .catch(() => undefined);
  }, [loadProjects]);

  const run = useCallback(async () => {
    setRunning(true);
    setRunError("");
    try {
      const res = await post<RunResult>("/api/pipeline/run", {
        config,
        input,
        input_format: inputFormat,
        input_fields: Object.keys(inputFields).length ? inputFields : null,
      });
      setResult(res);
      if (rightTab === "agent") setRightTab("output");
    } catch (e) {
      setRunError(e instanceof ApiError ? e.message : "Run failed");
    } finally {
      setRunning(false);
    }
  }, [config, input, inputFormat, inputFields, rightTab]);
  runRef.current = run;

  // Optional live mode: re-run automatically after edits (debounced; Logstash start-up takes seconds).
  useEffect(() => {
    if (!autoRun || agentRunning) return;
    const t = setTimeout(() => runRef.current(), 2500);
    return () => clearTimeout(t);
  }, [config, input, inputFormat, inputFields, autoRun, agentRunning]);

  // Error markers in the configuration editor
  useEffect(() => {
    const model = configEditorRef.current?.getModel();
    if (model) monaco.editor.setModelMarkers(model, "logstash", markersFor(result));
  }, [result]);

  // Format detection on the source logs (debounced): suggests a library parser.
  useEffect(() => {
    if (!input.trim()) return setSuggestions([]);
    const t = setTimeout(() => {
      post<{ matches: ParserSummary[] }>("/api/parsers/detect", {
        sample: input.slice(0, DETECT_SAMPLE),
        input_format: inputFormat,
      })
        .then((r) => setSuggestions(r.matches))
        .catch(() => setSuggestions([]));
    }, 700);
    return () => clearTimeout(t);
  }, [input, inputFormat]);

  const onConfigMount: OnMount = (editor) => {
    configEditorRef.current = editor;
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => runRef.current());
  };

  // ---- Parser library ------------------------------------------------------------------------
  const applyParser = useCallback((parser: Parser, withSample: boolean) => {
    setConfig(parser.filter);
    setAppliedParser(parser.id);
    setInputFormat(parser.input_format);
    if (withSample) {
      setInput(parser.sample);
      setImportInfo(`Loaded the "${parser.name}" filter and its sample.`);
    } else {
      setImportInfo(`Loaded the "${parser.name}" filter (Ctrl+Z in the editor to undo).`);
    }
    setResult(null);
    setLibraryOpen(false);
  }, []);

  useEffect(() => {
    if (!pendingParser) return;
    applyParser(pendingParser.parser, pendingParser.withSample);
    onParserConsumed();
  }, [pendingParser, applyParser, onParserConsumed]);

  const applySuggestion = async (s: ParserSummary) => {
    try {
      applyParser(await get<Parser>(`/api/parsers/${s.id}`), false);
    } catch {
      setRunError("The parser could not be loaded");
    }
  };

  // ---- Input ingestion (drag & drop, upload, manual) --------------------------------------
  const ingestFile = async (file: File) => {
    setImportInfo("");
    const head = new Uint8Array(await file.slice(0, 8).arrayBuffer());
    const isEvtx = file.name.toLowerCase().endsWith(".evtx") || String.fromCharCode(...head) === "ElfFile\0";
    try {
      if (isEvtx) {
        setImportInfo(`Converting EVTX ${file.name}…`);
        const res = await upload<{ input: string; records: number; truncated: boolean }>("/api/pipeline/evtx", file);
        setInput(res.input);
        setInputFormat("json");
        setImportInfo(`${file.name}: ${res.records} Windows events converted to JSON${res.truncated ? " (truncated)" : ""}.`);
        return;
      }
      if (file.size > MAX_TEXT) throw new Error("File too large (5 MB max).");
      let text = await file.text();
      let format: InputFormat = "lines";
      const lower = file.name.toLowerCase();
      if (lower.endsWith(".jsonl") || lower.endsWith(".ndjson")) format = "json";
      else if (lower.endsWith(".json")) {
        const parsed = JSON.parse(text);
        text = (Array.isArray(parsed) ? parsed : [parsed]).map((o) => JSON.stringify(o)).join("\n");
        format = "json";
      }
      setInput(text);
      setInputFormat(format);
      setImportInfo(`${file.name} loaded (${text.split("\n").length} lines).`);
    } catch (e) {
      setImportInfo(e instanceof Error ? `Import failed: ${e.message}` : "Import failed");
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) ingestFile(file);
  };

  // ---- Projects (save / duplicate / share, optimistic locking) --------------------------------
  const contentBody = () => ({
    config,
    sample: input,
    input_format: inputFormat,
    instructions,
    expected_output: expected || null,
    input_fields: Object.keys(inputFields).length ? inputFields : null,
  });

  const applyProject = (p: Project) => {
    setCurrent(p);
    setRemoteChange(null);
    setConflict("");
    const url = new URL(location.href);
    url.searchParams.set("project", p.id);
    history.replaceState(null, "", url);
  };

  const open = async (id: string) => {
    if (!id) {
      setCurrent(null);
      const url = new URL(location.href);
      url.searchParams.delete("project");
      history.replaceState(null, "", url);
      return;
    }
    try {
      const p = await get<Project>(`/api/pipelines/${id}`);
      applyProject(p);
      setConfig(p.config);
      setInput(p.sample || "");
      setInputFormat(p.input_format);
      setFieldRows(toRows(p.input_fields));
      setInstructions(p.instructions || "");
      setExpected(p.expected_output || "");
      setResult(null);
      setAppliedParser(null);
    } catch (e) {
      setRunError(e instanceof ApiError ? e.message : "Project unavailable");
    }
  };

  // Deep link: /?project=<id> (several tabs can work on different projects concurrently).
  useEffect(() => {
    const id = new URLSearchParams(location.search).get("project");
    if (id) open(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveAs = async () => {
    const name = prompt("Project name", current ? `${current.name} (copy)` : "New project")?.trim();
    if (!name) return;
    try {
      applyProject(await post<Project>("/api/pipelines", { name, ...contentBody() }));
      loadProjects();
    } catch (e) {
      setRunError(e instanceof ApiError ? e.message : "Save failed");
    }
  };

  const save = async (force = false) => {
    if (!current || current.access === "read") return saveAs();
    try {
      const saved = await put<Project>(`/api/pipelines/${current.id}`, {
        name: current.name,
        version: current.version,
        force,
        ...contentBody(),
      });
      applyProject(saved);
      loadProjects();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(e.message);
      else setRunError(e instanceof ApiError ? e.message : "Save failed");
    }
  };

  const duplicate = async () => {
    if (!current) return saveAs();
    const name = prompt("Copy name", `${current.name} (copy)`)?.trim();
    if (!name) return;
    // The copy is taken from the saved version; unsaved edits are carried over by saving the copy.
    const copy = await post<Project>(`/api/pipelines/${current.id}/duplicate`, { name });
    applyProject(await put<Project>(`/api/pipelines/${copy.id}`, { name, version: copy.version, ...contentBody() }));
    loadProjects();
  };

  const rename = async () => {
    if (!current || current.access !== "owner") return;
    const name = prompt("New name", current.name)?.trim();
    if (!name || name === current.name) return;
    setCurrent({ ...current, name });
  };

  const remove = async () => {
    if (!current || !confirm(`Permanently delete "${current.name}" (for colleagues too)?`)) return;
    await del(`/api/pipelines/${current.id}`);
    open("");
    loadProjects();
  };

  // Concurrent editing: poll the open project and warn when a colleague saved a newer version.
  useEffect(() => {
    if (!current) return;
    const t = setInterval(async () => {
      try {
        const meta = await get<ProjectMeta>(`/api/pipelines/${current.id}/meta`);
        if (meta.version > current.version) setRemoteChange(meta);
      } catch {
        /* project unshared/deleted: surfaced on next save */
      }
    }, 20000);
    return () => clearInterval(t);
  }, [current]);

  const insertSyslogOutput = () => {
    setConfig((c) => `${c.trimEnd()}\n\n${SYSLOG_TEMPLATE}`);
  };

  // ---- Autonomous agent ----------------------------------------------------------------------
  const startAgent = async () => {
    const controller = new AbortController();
    abortRef.current = controller;
    setAgentEvents([]);
    setAgentRunning(true);
    setRightTab("agent");
    try {
      await stream(
        "/api/agent/run",
        {
          input,
          input_format: inputFormat,
          instructions,
          expected_output: expected.trim() || null,
          initial_config: config.trim() && config !== SAMPLE_CONFIG ? config : null,
          max_iterations: maxIter,
          input_fields: Object.keys(inputFields).length ? inputFields : null,
        },
        (ev) => {
          const event = ev as AgentEvent;
          setAgentEvents((prev) => [...prev, event]);
          if (event.type === "config" && typeof event.config === "string") setConfig(event.config);
          if (event.type === "result") setResult(event as unknown as RunResult);
        },
        controller.signal,
      );
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "AbortError")) {
        setAgentEvents((prev) => [...prev, { type: "error", message: e instanceof Error ? e.message : String(e) }]);
      }
    } finally {
      setAgentRunning(false);
      abortRef.current = null;
    }
  };

  const stopAgent = () => abortRef.current?.abort();

  const events = result?.events ?? [];
  const tags = useMemo(() => failureTags(events), [events]);
  const outputJson = useMemo(() => JSON.stringify(events, null, 2), [events]);
  const syslogErrors = result?.syslog?.frames.reduce((n, f) => n + f.errors.length, 0) ?? 0;
  const top = suggestions[0];
  const showSuggestion =
    top && top.score !== undefined && top.score >= 0.6 && top.id !== appliedParser && top.id !== dismissedSuggestion;

  return (
    <div className="workspace">
      <div className="toolbar">
        <div className="group">
          <select
            className="project-select"
            value={current?.id ?? ""}
            onChange={(e) => open(e.target.value)}
            aria-label="Projects"
          >
            <option value="">— New project (unsaved) —</option>
            <optgroup label="My projects">
              {projects
                .filter((p) => p.access === "owner")
                .map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                    {p.shares ? ` · shared (${p.shares})` : ""}
                  </option>
                ))}
            </optgroup>
            <optgroup label="Shared with me">
              {projects
                .filter((p) => p.access !== "owner")
                .map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} — {p.owner} ({ACCESS_LABEL[p.access]}
                    {p.via_groups?.length ? `, via ${p.via_groups.join(", ")}` : ""})
                  </option>
                ))}
            </optgroup>
          </select>
          {current && (
            <span className="project-meta muted small" title={`Modified on ${fmtDate(current.updated_at)}`}>
              <span className="badge">v{current.version}</span>
              <span className={`badge ${current.access === "read" ? "warn" : ""}`}>{ACCESS_LABEL[current.access]}</span>
              {current.access !== "owner" && <span>by {current.owner}</span>}
            </span>
          )}
        </div>
        <span className="sep" />
        <div className="group">
          <button
            onClick={() => save()}
            disabled={fieldsInvalid}
            title={current?.access === "read" ? "Read-only: saves a copy" : "Save"}
          >
            <Icon name="save" />
            {current && current.access !== "read" ? "Save" : "Save as…"}
          </button>
          <button className="ghost" onClick={duplicate} title="Create a personal copy">
            <Icon name="copy" /> Duplicate
          </button>
          {current?.access === "owner" && (
            <>
              <button className="ghost" onClick={() => setSharing(true)}>
                <Icon name="share" /> Share
              </button>
              <button className="ghost icon-only" onClick={rename} title="Rename" aria-label="Rename">
                <Icon name="edit" />
              </button>
              <button className="ghost icon-only danger" onClick={remove} title="Delete" aria-label="Delete">
                <Icon name="trash" />
              </button>
            </>
          )}
        </div>
        <span className="spacer" />
        <div className="group">
          <button onClick={() => setLibraryOpen(true)} title="Ready-made filters for common log formats">
            <Icon name="library" /> Library
            {suggestions.length > 0 && <span className="badge accent">{suggestions.length}</span>}
          </button>
          <label className="toggle small" title="Automatically re-runs Logstash after each change">
            <input type="checkbox" checked={autoRun} onChange={(e) => setAutoRun(e.target.checked)} /> Auto-run
          </label>
          <button
            className="primary"
            onClick={run}
            disabled={running || agentRunning || fieldsInvalid}
            title="Ctrl+Enter"
          >
            {running ? <span className="spinner" /> : <Icon name="play" />}
            {running ? "Running…" : "Run"}
          </button>
        </div>
      </div>

      {remoteChange && (
        <div className="banner warn">
          <Icon name="alert" />
          {remoteChange.updated_by || "A colleague"} saved version {remoteChange.version} of this project (
          {fmtDate(remoteChange.updated_at)}).
          <button className="small" onClick={() => current && open(current.id)}>
            Reload (discards my changes)
          </button>
          <button className="small" onClick={saveAs}>
            Keep mine in a copy
          </button>
          <button className="small ghost" onClick={() => setRemoteChange(null)}>
            Dismiss
          </button>
        </div>
      )}
      {conflict && (
        <div className="banner error">
          <Icon name="alert" />
          {conflict}
          <button className="small" onClick={() => current && open(current.id)}>
            Reload the remote version
          </button>
          <button className="small" onClick={saveAs}>
            Save as a copy
          </button>
          <button className="small danger" onClick={() => confirm("Overwrite the colleague's version?") && save(true)}>
            Overwrite
          </button>
          <button className="small ghost" onClick={() => setConflict("")}>
            Cancel
          </button>
        </div>
      )}
      {sharing && current && (
        <ShareDialog
          projectId={current.id}
          projectName={current.name}
          onClose={() => {
            setSharing(false);
            loadProjects();
          }}
        />
      )}
      {libraryOpen && (
        <ParserLibraryDialog suggested={suggestions} onUse={applyParser} onClose={() => setLibraryOpen(false)} />
      )}

      <div className="panels">
        {/* ---- Left panel: input ---- */}
        <section
          className={`panel ${dragging ? "dragging" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <div className="panel-head">
            <div className="tabs">
              <button className={leftTab === "input" ? "active" : ""} onClick={() => setLeftTab("input")}>
                Source logs
              </button>
              <button className={leftTab === "fields" ? "active" : ""} onClick={() => setLeftTab("fields")}>
                Input fields
                {fieldRows.length > 0 && (
                  <span className={`badge ${fieldsInvalid ? "error" : ""}`}>{fieldRows.length}</span>
                )}
              </button>
              {canAgent && (
                <button className={leftTab === "agent" ? "active" : ""} onClick={() => setLeftTab("agent")}>
                  AI agent
                </button>
              )}
            </div>
          </div>
          {leftTab === "input" && (
            <>
              <div className="input-bar">
                <select
                  value={inputFormat}
                  onChange={(e) => setInputFormat(e.target.value as InputFormat)}
                  aria-label="Input format"
                >
                  <option value="lines">Text lines (1 line = 1 event)</option>
                  <option value="json">JSON lines</option>
                </select>
                <label className="button small" title="Load a file (.log, .json, .jsonl, .evtx…)">
                  <Icon name="upload" /> File…
                  <input
                    type="file"
                    hidden
                    accept=".log,.txt,.json,.jsonl,.ndjson,.evtx,.csv"
                    onChange={(e) => e.target.files?.[0] && ingestFile(e.target.files[0])}
                  />
                </label>
                <span className="spacer" />
                <span className="muted small">{input ? input.split("\n").length : 0} lines</span>
              </div>
              {importInfo && <div className="info-line">{importInfo}</div>}
              {showSuggestion && (
                <div className="suggestion">
                  <Icon name="wand" />
                  <span>
                    Looks like <strong>{top.name}</strong> ({Math.round((top.score ?? 0) * 100)}% of lines)
                  </span>
                  <span className="spacer" />
                  <button className="small primary" onClick={() => applySuggestion(top)}>
                    Use parser
                  </button>
                  <button className="small ghost" onClick={() => setLibraryOpen(true)}>
                    Compare
                  </button>
                  <button
                    className="small ghost icon-only"
                    aria-label="Dismiss"
                    onClick={() => setDismissedSuggestion(top.id)}
                  >
                    <Icon name="x" />
                  </button>
                </div>
              )}
              <div className="editor">
                <Editor
                  language={inputFormat === "json" ? "json" : "plaintext"}
                  theme={editorTheme}
                  value={input}
                  onChange={(v) => setInput(v ?? "")}
                  options={{ ...EDITOR_OPTIONS, wordWrap: "on", lineNumbers: "on" }}
                />
              </div>
              <div className="drop-hint">
                <Icon name="upload" /> Drop a file here — .log, .json, .jsonl, Windows .evtx (converted automatically)
              </div>
            </>
          )}
          {leftTab === "fields" && <InputFieldsEditor rows={fieldRows} onChange={setFieldRows} ecs={ecs} />}
          {leftTab === "agent" && (
            <div className="agent-form stack">
              <label>
                Business instructions
                <textarea rows={7} value={instructions} onChange={(e) => setInstructions(e.target.value)} />
              </label>
              <label>
                Expected output (optional) — JSON or JSON lines, "*" = any value
                <textarea
                  rows={6}
                  className="mono"
                  placeholder='{"client": {"ip": "192.168.1.10"}, "response": 200}'
                  value={expected}
                  onChange={(e) => setExpected(e.target.value)}
                />
              </label>
              <label className="inline">
                Max iterations
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={maxIter}
                  onChange={(e) => setMaxIter(Number(e.target.value))}
                  style={{ width: 80 }}
                />
              </label>
              <small className="muted">
                The agent starts from the current configuration if you modified it (or from a matching library parser),
                runs it with your input fields, analyzes the output and the Logstash errors, then fixes it until it
                validates.
              </small>
              {agentRunning ? (
                <button className="danger" onClick={stopAgent}>
                  <Icon name="stop" /> Stop the agent
                </button>
              ) : (
                <button
                  className="primary"
                  onClick={startAgent}
                  disabled={!instructions.trim() || !input.trim() || fieldsInvalid}
                >
                  <Icon name="sparkles" /> Start the autonomous agent
                </button>
              )}
            </div>
          )}
        </section>

        {/* ---- Center panel: configuration ---- */}
        <section className="panel">
          <div className="panel-head">
            <div className="title">
              <Icon name="file" />
              logstash.conf <span className="muted ellipsis">— {current?.name ?? "Untitled"}</span>
            </div>
            <div className="panel-actions">
              <button
                className="small"
                onClick={insertSyslogOutput}
                disabled={/\boutput\s*\{[\s\S]*\bsyslog\s*\{/.test(config)}
                title="Adds an output { syslog { … } } block to complete with your production settings"
              >
                <Icon name="plus" /> Syslog output
              </button>
            </div>
          </div>
          <div className="editor">
            <Editor
              language="logstash"
              theme={editorTheme}
              value={config}
              onChange={(v) => setConfig(v ?? "")}
              onMount={onConfigMount}
              options={EDITOR_OPTIONS}
            />
          </div>
        </section>

        {/* ---- Right panel: output ---- */}
        <section className="panel">
          <div className="panel-head">
            <div className="tabs">
              <button className={rightTab === "output" ? "active" : ""} onClick={() => setRightTab("output")}>
                Output {result ? <span className="badge">{events.length}</span> : null}
              </button>
              <button className={rightTab === "logs" ? "active" : ""} onClick={() => setRightTab("logs")}>
                Logstash logs
                {result && result.errors.length + result.config_errors.length > 0 && (
                  <span className="badge error">{result.errors.length + result.config_errors.length}</span>
                )}
              </button>
              {result?.syslog && (
                <button className={rightTab === "syslog" ? "active" : ""} onClick={() => setRightTab("syslog")}>
                  Syslog <span className="badge">{result.syslog.frames.length}</span>
                  {syslogErrors > 0 && <span className="badge error">{syslogErrors}</span>}
                </button>
              )}
              {canAgent && (
                <button className={rightTab === "agent" ? "active" : ""} onClick={() => setRightTab("agent")}>
                  Agent {agentRunning && <span className="spinner" />}
                </button>
              )}
            </div>
          </div>
          {runError && (
            <div className="alert error" style={{ margin: 8 }}>
              {runError}
            </div>
          )}
          {rightTab === "output" && (
            <>
              {result && (
                <div className="summary">
                  <span className={`chip ${result.ok ? "ok" : "error"}`}>
                    <Icon name={result.ok ? "check" : "alert"} />
                    {result.ok ? "Success" : "Failure"}
                  </span>
                  <span className="chip">{events.length} event(s)</span>
                  <span className="chip">
                    <Icon name="clock" />
                    {(result.duration_ms / 1000).toFixed(1)} s
                  </span>
                  {Object.entries(tags).map(([t, c]) => (
                    <span key={t} className="chip warn">
                      {t} × {c}
                    </span>
                  ))}
                </div>
              )}
              {result?.config_errors.map((e) => (
                <div key={e} className="alert error" style={{ margin: 8 }}>
                  {e}
                </div>
              ))}
              <div className="editor">
                {result ? (
                  <Editor
                    language="json"
                    theme={editorTheme}
                    value={outputJson}
                    options={{ ...EDITOR_OPTIONS, readOnly: true, folding: true }}
                  />
                ) : (
                  <div className="placeholder">
                    {running ? (
                      <span className="row">
                        <span className="spinner" /> Logstash is starting…
                      </span>
                    ) : (
                      <div className="stack" style={{ alignItems: "center" }}>
                        <Icon name="play" />
                        <span>
                          Run the configuration (<kbd>Ctrl</kbd>+<kbd>Enter</kbd>) to see the actual output.
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
          {rightTab === "logs" && (
            <div className="scroll">
              {result?.errors.map((e, i) => (
                <div key={i} className="alert error mono">
                  {e}
                </div>
              ))}
              {result?.warnings?.map((w, i) => (
                <div key={i} className="alert warn mono">
                  {w}
                </div>
              ))}
              <pre className="logs">{result?.logs || "No logs."}</pre>
            </div>
          )}
          {rightTab === "syslog" && result?.syslog && (
            <SyslogView
              syslog={result.syslog}
              configWarnings={(result.warnings || []).filter((w) => /^line \d+: /.test(w) && !/ignored/.test(w))}
            />
          )}
          {rightTab === "syslog" && !result?.syslog && (
            <div className="placeholder">Add a syslog output, then run to see the frames.</div>
          )}
          {rightTab === "agent" && <AgentTimeline events={agentEvents} running={agentRunning} onApply={setConfig} />}
        </section>
      </div>
    </div>
  );
}

function AgentTimeline({
  events,
  running,
  onApply,
}: {
  events: AgentEvent[];
  running: boolean;
  onApply: (config: string) => void;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  // Block body on purpose: scrollIntoView() returns a Promise in recent browsers, and an effect must
  // return nothing or a cleanup function (React would call the Promise and crash).
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  if (!events.length && !running) {
    return <div className="placeholder">Start the agent from the "AI agent" tab of the left panel.</div>;
  }
  return (
    <div className="scroll timeline">
      {events.map((ev, i) => {
        switch (ev.type) {
          case "iteration":
            return (
              <h3 key={i} className="iter">
                Iteration {ev.n}
              </h3>
            );
          case "status":
            return (
              <div key={i} className="muted small">
                {String(ev.message)}
              </div>
            );
          case "config":
            return (
              <details key={i} className="config-block">
                <summary>
                  Proposed configuration{" "}
                  <button className="small" onClick={() => onApply(String(ev.config))}>
                    Apply
                  </button>
                </summary>
                <pre className="mono">{String(ev.config)}</pre>
              </details>
            );
          case "result":
            return (
              <div key={i} className={`chip ${ev.ok ? "ok" : "error"}`}>
                Logstash: {String(ev.event_count ?? 0)} event(s), {((ev.errors as string[]) || []).length} error(s)
              </div>
            );
          case "evaluation": {
            const issues = (ev.issues as string[]) || [];
            return issues.length ? (
              <ul key={i} className="issues">
                {issues.map((x, j) => (
                  <li key={j}>{x}</li>
                ))}
              </ul>
            ) : (
              <div key={i} className="alert ok">
                Validation succeeded.
              </div>
            );
          }
          case "error":
            return (
              <div key={i} className="alert error">
                {String(ev.message)}
              </div>
            );
          case "done":
            return (
              <div key={i} className={`alert ${ev.success ? "ok" : "warn"}`}>
                {ev.success
                  ? `Done: configuration validated in ${ev.iterations} iteration(s). It is loaded in the editor.`
                  : `Stopped after ${ev.iterations} iteration(s) without full validation. The last proposal is in the editor.`}
              </div>
            );
          default:
            return null;
        }
      })}
      {running && (
        <div className="muted small row">
          <span className="spinner" /> The agent is working…
        </div>
      )}
      <div ref={endRef} />
    </div>
  );
}
