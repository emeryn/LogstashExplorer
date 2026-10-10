// Same-origin API client. Every request carries X-Requested-With (CSRF guard enforced by the backend).

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function detail(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
  }
  return fallback;
}

export async function api<T = unknown>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("X-Requested-With", "XMLHttpRequest");
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const res = await fetch(path, { ...init, body, headers, credentials: "same-origin" });
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const data = isJson ? await res.json() : await res.text();
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/api/auth/")) window.dispatchEvent(new Event("lsx:unauthorized"));
    throw new ApiError(res.status, detail(data, res.statusText));
  }
  return data as T;
}

export const get = <T,>(path: string) => api<T>(path);
export const post = <T,>(path: string, json?: unknown) => api<T>(path, { method: "POST", json: json ?? {} });
export const put = <T,>(path: string, json: unknown) => api<T>(path, { method: "PUT", json });
export const patch = <T,>(path: string, json: unknown) => api<T>(path, { method: "PATCH", json });
export const del = <T,>(path: string) => api<T>(path, { method: "DELETE" });

export async function upload<T>(path: string, file: File): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  return api<T>(path, { method: "POST", body: form });
}

/** POST and consume an NDJSON stream, calling `onEvent` for each line. */
export async function stream(
  path: string,
  json: unknown,
  onEvent: (event: Record<string, unknown>) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    signal,
    headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
    body: JSON.stringify(json),
  });
  if (!res.ok || !res.body) {
    const data = await res.json().catch(() => ({}));
    throw new ApiError(res.status, detail(data, res.statusText));
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
}

// ---- Shared types --------------------------------------------------------------------------
export type Role = "user" | "advanced" | "admin";

export interface User {
  id: string;
  username: string;
  display_name: string | null;
  email: string | null;
  role: Role;
  status: "active" | "pending" | "disabled";
  auth_source: "local" | "oidc" | "ldap" | "service";
  must_change_password: boolean;
  totp_enabled: boolean;
  locked: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface MeResponse {
  mfa_pending: boolean;
  mfa_methods: string[];
  user: User;
}

export interface SyslogFrame {
  transport: "tcp" | "udp";
  format: "rfc5424" | "rfc3164" | "unknown";
  raw: string;
  bytes: number;
  fields: {
    pri?: number;
    facility?: string;
    facility_code?: number;
    severity?: string;
    severity_code?: number;
    timereported?: string;
    hostname?: string;
    app_name?: string;
    procid?: string;
    msgid?: string;
    structured_data?: string | { id: string; params: Record<string, string> }[];
    msg?: string;
  };
  errors: string[];
  warnings: string[];
}

export interface SyslogResult {
  outputs: { line: number; protocol: string; rfc: string }[];
  frames: SyslogFrame[];
}

export interface RunResult {
  ok: boolean;
  exit_code?: number;
  events: Record<string, unknown>[];
  errors: string[];
  warnings?: string[];
  config_errors: string[];
  logs: string;
  duration_ms: number;
  event_count?: number;
  syslog?: SyslogResult | null;
}

export type ProjectAccess = "owner" | "write" | "read";

export interface ProjectMeta {
  id: string;
  name: string;
  input_format: "lines" | "json";
  version: number;
  updated_at: string;
  updated_by: string | null;
  owner: string;
  access: ProjectAccess;
  shares: number | null;
  via_groups?: string[];
}

export type InputFields = Record<string, string>;

export interface Project extends ProjectMeta {
  config: string;
  sample: string | null;
  instructions: string | null;
  expected_output: string | null;
  input_fields: InputFields;
}

export type ParserCategory = "windows" | "cloud" | "web" | "network" | "system" | "apps" | "industrial";

export interface ParserSummary {
  id: string;
  name: string;
  category: ParserCategory;
  category_label: string;
  vendor: string;
  description: string;
  input_format: "lines" | "json";
  fields: string[];
  score?: number;
}

export interface Parser extends ParserSummary {
  filter: string;
  sample: string;
  notes: string;
  input_fields: InputFields;
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  scope: "read" | "write";
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  username?: string;
  auth_source?: string;
}

export const ROLE_RANK: Record<Role, number> = { user: 1, advanced: 2, admin: 3 };
export const hasRole = (u: User | null, r: Role) => !!u && ROLE_RANK[u.role] >= ROLE_RANK[r];

export function fmtDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}
