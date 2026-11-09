import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { HBars, ScoreRing, SeverityStack, TrendChart, scoreTone } from "../components/charts";
import { Card, ProviderTag, SeverityBadge, Stat, money } from "../components/ui";
import type { Finding, Plan, Scan, TrendPoint } from "../types";

export function Overview({ scan, findings, trend, plan, onOpen, onStrategy }: {
  scan: Scan;
  findings: Finding[];
  trend: TrendPoint[];
  plan: Plan | null;
  onOpen: (f: Finding) => void;
  onStrategy: () => void;
}) {
  const s = scan.summary;
  const top = findings.filter((f) => !f.suppressed && (f.severity === "CRITICAL" || f.severity === "HIGH")).slice(0, 8);
  const services = Object.entries(s.by_service)
    .slice(0, 8)
    .map(([label, value]) => ({ label, value }));
  const spend = (scan.costs ?? []).reduce((a, c) => a + c.total, 0);
  const tone = scoreTone(scan.score);

  return (
    <div className="grid">
      <Card className="span-4 score-card" title="Posture score">
        <div className="row gap-l center">
          <ScoreRing score={scan.score} />
          <div className="stack gap-s">
            <span className={`pill pill-${tone}`}>
              {tone === "good" ? "Healthy" : tone === "warn" ? "Needs attention" : "At risk"}
            </span>
            <span className="small muted">
              {scan.controls_passed} of {scan.controls_passed + scan.controls_failed} controls passing
            </span>
            <SeverityStack counts={s.by_severity} />
            <div className="row gap-s wrap">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((k) => (
                <span key={k} className="small">
                  <span className={`dot sev-${k.toLowerCase()}`} /> {s.by_severity[k] ?? 0} {k.toLowerCase()}
                </span>
              ))}
            </div>
          </div>
        </div>
      </Card>

      <div className="span-8 stats">
        <Stat label="Open findings" value={s.total} hint={`${s.suppressed} suppressed`} />
        <Stat label="Critical" value={s.by_severity.CRITICAL ?? 0} tone="bad" hint="fix today" />
        <Stat label="Potential savings" value={`${money(s.estimated_monthly_savings)}/mo`} tone="good" hint="from cost rules" />
        <Stat label="30-day spend" value={spend ? money(spend) : "—"} hint={(scan.costs ?? []).map((c) => c.provider.toUpperCase()).join(" + ")} />
      </div>

      {plan && plan.scenarios.length > 0 && (
        <Card className="span-12" title={`Attack paths (${plan.scenarios.length})`} action={<button className="btn btn-s" onClick={onStrategy}>Open strategy →</button>}>
          <ul className="paths">
            {plan.scenarios.slice(0, 4).map((s) => (
              <li key={s.id}>
                <SeverityBadge severity={s.severity} />
                <span><strong>{s.title}</strong> <span className="small muted">→ {s.break_first}</span></span>
              </li>
            ))}
          </ul>
          {plan.resolved_since_last_scan > 0 && <p className="small good">✓ {plan.resolved_since_last_scan} finding(s) resolved since the previous scan.</p>}
        </Card>
      )}

      <Card className="span-7" title="AI strategy briefing" action={<span className="muted small">grounded on this scan</span>}>
        <div className="prose">
          <Markdown remarkPlugins={[remarkGfm]}>{scan.explanation || "_No briefing for this scan._"}</Markdown>
        </div>
      </Card>

      <div className="span-5 stack gap-m">
        <Card title="Posture trend">
          <TrendChart points={trend} />
        </Card>
        <Card title="Findings by service">
          <HBars items={services} />
        </Card>
      </div>

      <Card className="span-12" title="Fix first" action={<span className="muted small">critical & high</span>}>
        <table className="table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Cloud</th>
              <th>Rule</th>
              <th>Resource</th>
              <th className="hide-s">Issue</th>
            </tr>
          </thead>
          <tbody>
            {top.map((f) => (
              <tr key={f.id} onClick={() => onOpen(f)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onOpen(f)}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><ProviderTag provider={f.provider} /></td>
                <td className="mono">{f.rule_id}</td>
                <td className="mono truncate">{f.resource_name}</td>
                <td className="hide-s truncate">{f.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
