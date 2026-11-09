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
  console_url: string | null;
}

export interface ServiceResult {
  provider: ProviderId;
  service: string;
  account: string | null;
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
  targets?: string[];
  scenario_count?: number;
  scenarios?: Scenario[];
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
  llm_provider: string;
  llm_health: { ok: boolean; detail: string; at: string } | null;
  accounts: number;
  providers: string[];
  rag_mode: string;
}

export interface ScenarioStep {
  title: string;
  detail: string;
  technique: string | null;
  rule_id: string | null;
}

export interface Scenario {
  id: string;
  title: string;
  severity: Severity;
  provider: ProviderId;
  account: string | null;
  resource: string;
  summary: string;
  impact: string;
  steps: ScenarioStep[];
  break_first: string;
  break_rule: string | null;
  finding_ids: string[];
}

export interface PlanResource {
  finding_id: string;
  name: string;
  region: string | null;
  account: string | null;
  message: string;
  console_url: string | null;
}

export interface PlanAction {
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  provider: ProviderId;
  service: string;
  effort: "S" | "M" | "L";
  score_gain: number;
  monthly_savings: number | null;
  breaks: string[];
  why: string;
  steps: string;
  terraform: string | null;
  verify: string;
  compliance: Record<string, string[]>;
  resources: PlanResource[];
}

export interface PlanPhase {
  id: string;
  title: string;
  horizon: string;
  goal: string;
  actions: PlanAction[];
  findings: number;
  score_gain: number;
  monthly_savings: number;
}

export interface Guardrail {
  title: string;
  rules: string[];
  why: string;
  how: string;
  kind: string;
}

export interface ScanDiff {
  previous_scan_id: string | null;
  new: string[];
  resolved: { id: string; rule_id: string; severity: Severity; resource_name: string; title: string }[];
  persisting: string[];
}

export interface Plan {
  scan_id: string;
  current_score: number | null;
  target_score: number | null;
  actions: number;
  findings: number;
  monthly_savings: number;
  scenarios_open: number;
  resolved_since_last_scan: number;
  phases: PlanPhase[];
  guardrails: Guardrail[];
  scenarios: Scenario[];
  diff: ScanDiff;
}

export interface CloudAccount {
  id: string;
  name: string;
  provider: ProviderId;
  auth_method: string;
  config: Record<string, unknown>;
  secret_hints: Record<string, string>;
  enabled: boolean;
  status: "unverified" | "connected" | "error";
  status_detail: string | null;
  identity: { account_id?: string; arn?: string; alias?: string; tenant_id?: string; console_url?: string;
    subscriptions?: { id: string; name: string }[] };
  created_at: string;
  verified_at: string | null;
}

export interface LLMPreset {
  label: string;
  base_url: string;
  models: string[];
  key_url: string;
  needs_key: boolean;
}

export interface LLMSettings {
  provider: string;
  base_url: string;
  models: string[];
  language: string;
  source: "env" | "ui" | "none";
  has_key: boolean;
  key_hint: string | null;
  configured: boolean;
  health: { ok: boolean; detail: string; at: string } | null;
  presets: Record<string, LLMPreset>;
}
