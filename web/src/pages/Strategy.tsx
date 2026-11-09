import { useState } from "react";
import { Card, Empty, ProviderTag, SeverityBadge, Stat, money } from "../components/ui";
import type { Plan, PlanAction, Scenario } from "../types";

const MITRE = "https://attack.mitre.org/techniques/";
const EFFORT = { S: "Small (minutes)", M: "Medium (hours)", L: "Large (days, plan a change)" };

function ScenarioCard({ s, onAsk }: { s: Scenario; onAsk: (q: string) => void }) {
  return (
    <article className={`scenario sev-border-${s.severity.toLowerCase()}`}>
      <header className="row between gap-s wrap">
        <div className="row gap-s">
          <SeverityBadge severity={s.severity} />
          <ProviderTag provider={s.provider} />
        </div>
        <button className="btn btn-ghost btn-s" onClick={() => onAsk(`Walk me through fixing the attack path "${s.title}" step by step.`)}>
          Ask Copilot
        </button>
      </header>
      <h3 className="scenario-title">{s.title}</h3>
      <p className="small">{s.summary}</p>
      <ol className="chain">
        {s.steps.map((st, i) => (
          <li key={i}>
            <strong>{st.title}</strong>
            <span className="small muted"> {st.detail}</span>
            <span className="chain-tags">
              {st.technique && (
                <a className="chip" href={`${MITRE}${st.technique.replace(".", "/")}/`} target="_blank" rel="noreferrer" title="MITRE ATT&CK technique">
                  {st.technique}
                </a>
              )}
              {st.rule_id && <code className="chip">{st.rule_id}</code>}
            </span>
          </li>
        ))}
      </ol>
      <p className="small"><strong>Impact:</strong> {s.impact}</p>
      <div className="break-first">
        <span className="small">Break the chain first</span>
        <strong>{s.break_first}</strong>
      </div>
    </article>
  );
}

function ActionRow({ a, done }: { a: PlanAction; done: number }) {
  const [open, setOpen] = useState(false);
  return (
    <li className={`action ${open ? "open" : ""}`}>
      <button className="action-head" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <SeverityBadge severity={a.severity} />
        <span className="action-title">
          <code>{a.rule_id}</code> {a.title}
          {a.breaks.length > 0 && <span className="pill pill-bad">breaks {a.breaks.length} attack path{a.breaks.length > 1 ? "s" : ""}</span>}
        </span>
        <span className="action-meta small muted">
          {a.resources.length} resource{a.resources.length > 1 ? "s" : ""} · effort {a.effort}
          {a.score_gain > 0 && <> · <span className="good">+{a.score_gain} pts</span></>}
          {a.monthly_savings ? <> · <span className="good">{money(a.monthly_savings)}/mo</span></> : null}
          {done > 0 && <> · <span className="good">{done} fixed</span></>}
        </span>
        <span aria-hidden className="chev">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="action-body">
          <p><strong>Why:</strong> {a.why}</p>
          <p><strong>How:</strong> {a.steps}</p>
          <p className="small muted">Effort: {EFFORT[a.effort]}. {a.verify}</p>
          {a.breaks.length > 0 && <p className="small"><strong>Breaks:</strong> {a.breaks.join(" · ")}</p>}
          <table className="table compact">
            <thead>
              <tr><th>Resource</th><th className="hide-s">Region</th><th className="hide-s">Detail</th><th /></tr>
            </thead>
            <tbody>
              {a.resources.map((r) => (
                <tr key={r.finding_id}>
                  <td className="mono truncate">{r.name}</td>
                  <td className="hide-s small">{r.region ?? "global"}</td>
                  <td className="hide-s small truncate">{r.message}</td>
                  <td className="num">
                    {r.console_url && (
                      <a className="btn btn-ghost btn-s" href={r.console_url} target="_blank" rel="noreferrer">
                        Open in {a.provider === "aws" ? "AWS" : "Azure"} ↗
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {a.terraform && <pre className="code">{a.terraform}</pre>}
        </div>
      )}
    </li>
  );
}

export function Strategy({ plan, onAsk, onRescan, scanning }: {
  plan: Plan | null;
  onAsk: (q: string) => void;
  onRescan: () => void;
  scanning: boolean;
}) {
  const [phase, setPhase] = useState<string | null>(null);
  if (!plan) return <Empty>No strategy yet. Run a scan first.</Empty>;
  const resolvedByRule = plan.diff.resolved.reduce<Record<string, number>>((m, r) => ({ ...m, [r.rule_id]: (m[r.rule_id] ?? 0) + 1 }), {});
  const current = phase ?? plan.phases[0]?.id;

  return (
    <div className="stack gap-m">
      <div className="stats">
        <Stat label="Posture score" value={`${plan.current_score ?? "—"} → ${plan.target_score ?? 100}`} hint="now → after the plan" />
        <Stat label="Attack paths" value={plan.scenarios_open} tone={plan.scenarios_open ? "bad" : "good"} hint="chained weaknesses" />
        <Stat label="Actions" value={plan.actions} hint={`${plan.findings} findings`} />
        <Stat
          label="Fixed since last scan"
          value={plan.resolved_since_last_scan}
          tone={plan.resolved_since_last_scan ? "good" : undefined}
          hint={plan.diff.previous_scan_id ? `${plan.diff.new.length} new` : "first scan of these targets"}
        />
      </div>

      <Card title="How this plan works" action={<button className="btn btn-s" onClick={onRescan} disabled={scanning}>{scanning ? "Scanning…" : "Re-scan to verify"}</button>}>
        <ol className="loop">
          <li><strong>Break attack paths</strong> (chains of weaknesses an attacker would use), cheapest link first.</li>
          <li><strong>Fix by phase</strong>: each action shows why, how, effort, score gain and a console link.</li>
          <li><strong>Verify</strong>: re-scan; fixed findings move to "resolved" and the score rises.</li>
          <li><strong>Prevent recurrence</strong> with guardrails (SCP / Azure Policy / CI checks).</li>
        </ol>
      </Card>

      {plan.scenarios.length > 0 && (
        <section>
          <h2 className="section-title">Attack paths ({plan.scenarios.length})</h2>
          <div className="scenarios">
            {plan.scenarios.map((s) => <ScenarioCard key={s.id} s={s} onAsk={onAsk} />)}
          </div>
        </section>
      )}

      <section>
        <h2 className="section-title">Remediation plan</h2>
        <div className="phase-tabs" role="tablist">
          {plan.phases.map((p) => (
            <button key={p.id} role="tab" aria-selected={current === p.id} className={`phase-tab ${current === p.id ? "on" : ""}`} onClick={() => setPhase(p.id)}>
              <span className="small muted">{p.horizon}</span>
              <strong>{p.title}</strong>
              <span className="small">
                {p.actions.length} actions{p.score_gain ? ` · +${p.score_gain} pts` : ""}
                {p.monthly_savings ? ` · ${money(p.monthly_savings)}/mo` : ""}
              </span>
            </button>
          ))}
        </div>
        {plan.phases.filter((p) => p.id === current).map((p) => (
          <Card key={p.id} title={`${p.horizon}: ${p.title}`}>
            <p className="small muted">{p.goal}</p>
            <ul className="actions">
              {p.actions.map((a) => <ActionRow key={a.rule_id} a={a} done={resolvedByRule[a.rule_id] ?? 0} />)}
            </ul>
          </Card>
        ))}
      </section>

      {plan.diff.resolved.length > 0 && (
        <Card title={`Resolved since last scan (${plan.diff.resolved.length})`}>
          <ul className="resolved">
            {plan.diff.resolved.map((r) => (
              <li key={r.id}><span className="good">✓</span> <code>{r.rule_id}</code> {r.resource_name} <span className="small muted">{r.title}</span></li>
            ))}
          </ul>
        </Card>
      )}

      <section>
        <h2 className="section-title">Prevent recurrence: guardrails</h2>
        <div className="guardrails">
          {plan.guardrails.map((g) => (
            <Card key={g.title} title={g.title} action={<span className="chip">{g.kind}</span>}>
              <p className="small">{g.why}</p>
              <pre className="code">{g.how}</pre>
              {g.rules.length > 0 && <p className="small muted">Prevents: {g.rules.join(", ")}</p>}
            </Card>
          ))}
        </div>
      </section>
    </div>
  );
}
