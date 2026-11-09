import type { ChatAnswer, Finding, Framework, Info, Scan, TrendPoint } from "./types";

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
  startScan: (providers?: string[]) =>
    request<{ id: string }>("/api/v1/scans", { method: "POST", body: JSON.stringify({ providers, explain: true }) }),
  chat: (message: string, history: { role: "user" | "assistant"; content: string }[]) =>
    request<ChatAnswer>("/api/v1/chat", { method: "POST", body: JSON.stringify({ message, history }) }),
  suppress: (id: string, reason: string) =>
    request(`/api/v1/findings/${id}/suppression`, { method: "PUT", body: JSON.stringify({ reason }) }),
  unsuppress: (id: string) => request(`/api/v1/findings/${id}/suppression`, { method: "DELETE" }),
  exportUrl: (fmt: "csv" | "md") => `/api/v1/findings/export?fmt=${fmt}`,
};
