export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ProviderId = "aws" | "azure";

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  provider: ProviderId;
  service: string;
  severity: Severity;
  category: "security" | "cost" | "reliability";
  resource_id: string;
  resource_name: string;
  region: string | null;
  account: string | null;
  message: string;
  remediation: string;
  terraform: string | null;
  compliance: Record<string, string[]>;
  estimated_monthly_savings: number | null;
  suppressed: boolean;
}

export interface ServiceResult {
  provider: ProviderId;
  service: string;
  status: "ok" | "partial" | "skipped" | "error";
  resources: number;
  duration_ms: number;
  rules_evaluated: number;
  error: string | null;
  warnings: string[];
}

export interface CostSummary {
  provider: ProviderId;
  currency: string;
  period_start: string;
  period_end: string;
  total: number;
  forecast_month_end: number | null;
  by_service: { service: string; amount: number }[];
}

export interface Summary {
  total: number;
  suppressed: number;
  by_severity: Record<Severity, number>;
  by_provider: Record<string, number>;
  by_service: Record<string, number>;
  by_category: Record<string, number>;
  estimated_monthly_savings: number;
}

export interface Scan {
  id: string;
  status: "queued" | "running" | "succeeded" | "partial" | "failed";
  trigger: string;
  demo: boolean;
  started_at: string;
  finished_at: string | null;
  score: number | null;
  controls_passed: number;
  controls_failed: number;
  summary: Summary;
  accounts: Record<string, string>;
  error: string | null;
  services?: ServiceResult[];
  inventory?: Record<string, number>;
  costs?: CostSummary[];
  explanation?: string | null;
}

export interface TrendPoint {
  scan_id: string;
  at: string;
  score: number | null;
  findings: number;
  critical: number;
  high: number;
}

export interface Control {
  control: string;
  rules: string[];
  status: "pass" | "fail";
}

export interface Framework {
  framework: string;
  passed: number;
  total: number;
  percent: number;
  controls: Control[];
}

export interface ChatAnswer {
  answer: string;
  mode: "llm" | "offline";
  model: string | null;
  citations: { id: string; title: string; source: string }[];
  findings: string[];
  latency_ms: number;
}

export interface Info {
  version: string;
  demo_mode: boolean;
  auth: boolean;
  llm: boolean;
  providers: string[];
  rag_mode: string;
}
