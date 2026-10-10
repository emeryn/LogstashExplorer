import { useCallback, useEffect, useState } from "react";

import { get, post, put } from "../../api";
import { Card, Icon } from "../../ui";
import { msg } from "./common";

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

export default function AiConfig() {
  const [cfg, setCfg] = useState<AiCfg | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [headers, setHeaders] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [models, setModels] = useState<{ id: string; label: string }[]>([]);
  const [modelsState, setModelsState] = useState<"idle" | "loading" | "ok" | "error">("idle");
  const [modelsError, setModelsError] = useState("");
  const [manualModel, setManualModel] = useState(false);
  const [testing, setTesting] = useState(false);
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

  if (!cfg) return error ? <div className="alert error">{error}</div> : <div className="muted">Loading…</div>;
  const modelKnown = models.some((m) => m.id === cfg.model);
  const useSelect = modelsState === "ok" && models.length > 0 && !manualModel;

  const save = async () => {
    setError("");
    setStatus("");
    let extra: Record<string, string> | null = null;
    if (headers.trim()) {
      extra = Object.fromEntries(
        headers
          .split("\n")
          .filter((l) => l.includes("="))
          .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]),
      );
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
    setTesting(true);
    setStatus("");
    setError("");
    try {
      const res = await post<{ ok: boolean; reply?: string; error?: string }>("/api/admin/ai/test");
      if (res.ok) setStatus(`Connection OK — reply: ${res.reply}`);
      else setError(`Failed: ${res.error}`);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card
      title="LLM provider of the autonomous agent"
      description="Local Ollama or any OpenAI-compatible endpoint. The logs sent to the agent go to this provider."
    >
      <div className="form-grid">
        <label>
          Provider
          <select
            value={cfg.provider}
            onChange={(e) => {
              const next = e.target.value as AiCfg["provider"];
              setCfg({
                ...cfg,
                provider: next,
                base_url: next === "openai" ? "https://api.openai.com/v1" : "http://host.docker.internal:11434",
              });
            }}
          >
            <option value="ollama">Ollama (local)</option>
            <option value="openai">OpenAI / OpenAI-compatible</option>
          </select>
        </label>
        <label className="span-2">
          Endpoint URL
          <input value={cfg.base_url} onChange={(e) => setCfg({ ...cfg, base_url: e.target.value })} />
        </label>
        <label>
          <span className="row tight">
            Model
            <span className="spacer" />
            {modelsState === "loading" && <span className="spinner" />}
            {modelsState === "ok" && <span className="badge">{models.length} available</span>}
            <button type="button" className="ghost icon-only small" onClick={fetchModels} title="Query the server">
              <Icon name="refresh" />
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
          {modelsState === "error" && <span className="error-text small">{modelsError} — manual entry possible.</span>}
          {modelsState === "ok" && !models.length && <span className="hint">No model on this server.</span>}
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
          <span className="hint">Applies to every run in the workspace, not only the agent.</span>
        </label>
        <label>
          <span className="row tight">API key {cfg.api_key_set && <span className="badge ok">set</span>}</span>
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
        {cfg.extra_header_names.length > 0 && <span className="hint">Current: {cfg.extra_header_names.join(", ")}</span>}
        <textarea rows={3} className="mono" value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="OpenAI-Organization=org-xxx" />
      </label>
      <div className="row" style={{ marginTop: 14 }}>
        <button className="primary" onClick={save}>
          <Icon name="save" /> Save
        </button>
        <button onClick={test} disabled={testing}>
          {testing ? <span className="spinner" /> : <Icon name="activity" />} Test connection
        </button>
      </div>
      {status && <div className="alert ok">{status}</div>}
      {error && <div className="alert error">{error}</div>}
    </Card>
  );
}
