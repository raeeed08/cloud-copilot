import type {
  ChatAnswer,
  CloudAccount,
  Finding,
  Framework,
  Info,
  LLMSettings,
  Plan,
  Scan,
  TrendPoint,
} from "./types";

const KEY_STORAGE = "cloud-copilot.api-key";

export function getApiKey(): string {
  try {
    return sessionStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) sessionStorage.setItem(KEY_STORAGE, key);
    else sessionStorage.removeItem(KEY_STORAGE);
  } catch {
    /* storage unavailable: key lives for this page only */
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const key = getApiKey();
  if (key) headers.set("X-API-Key", key);
  if (init.body) headers.set("Content-Type", "application/json");
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  info: () => request<Info>("/api/v1/info"),
  latestScan: () => request<Scan>("/api/v1/scans/latest"),
  scan: (id: string) => request<Scan>(`/api/v1/scans/${id}`),
  scans: () => request<Scan[]>("/api/v1/scans?limit=20"),
  trend: () => request<TrendPoint[]>("/api/v1/trend"),
  findings: (scanId?: string) => request<Finding[]>(`/api/v1/findings?limit=5000${scanId ? `&scan_id=${scanId}` : ""}`),
  compliance: () => request<{ frameworks: Framework[] }>("/api/v1/compliance"),
  startScan: (target: { account_ids?: string[]; demo?: boolean } = {}) =>
    request<{ id: string }>("/api/v1/scans", { method: "POST", body: JSON.stringify({ ...target, explain: true }) }),
  plan: () => request<Plan>("/api/v1/plan"),
  accounts: () => request<CloudAccount[]>("/api/v1/accounts"),
  addAccount: (body: {
    name: string;
    provider: string;
    auth_method: string;
    config: Record<string, unknown>;
    secret: Record<string, string>;
  }) => request<CloudAccount>("/api/v1/accounts", { method: "POST", body: JSON.stringify(body) }),
  verifyAccount: (id: string) => request<CloudAccount>(`/api/v1/accounts/${id}/verify`, { method: "POST" }),
  updateAccount: (id: string, body: { enabled?: boolean; name?: string }) =>
    request<CloudAccount>(`/api/v1/accounts/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteAccount: (id: string) => request(`/api/v1/accounts/${id}`, { method: "DELETE" }),
  llm: () => request<LLMSettings>("/api/v1/settings/llm"),
  saveLlm: (body: { provider: string; base_url?: string; models?: string[]; api_key?: string; language?: string }) =>
    request<LLMSettings>("/api/v1/settings/llm", { method: "PUT", body: JSON.stringify(body) }),
  resetLlm: () => request<LLMSettings>("/api/v1/settings/llm", { method: "DELETE" }),
  testLlm: () =>
    request<{ ok: boolean; model?: string; latency_ms?: number; error?: string }>("/api/v1/settings/llm/test", {
      method: "POST",
    }),
  chat: (message: string, history: { role: "user" | "assistant"; content: string }[]) =>
    request<ChatAnswer>("/api/v1/chat", { method: "POST", body: JSON.stringify({ message, history }) }),
  suppress: (id: string, reason: string) =>
    request(`/api/v1/findings/${id}/suppression`, { method: "PUT", body: JSON.stringify({ reason }) }),
  unsuppress: (id: string) => request(`/api/v1/findings/${id}/suppression`, { method: "DELETE" }),
  exportUrl: (fmt: "csv" | "md") => `/api/v1/findings/export?fmt=${fmt}`,
};
