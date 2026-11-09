import { HBars } from "../components/charts";
import { Card, Empty, ProviderTag, Stat, money } from "../components/ui";
import type { Finding, Scan } from "../types";

export function Cost({ scan, findings, onOpen }: { scan: Scan; findings: Finding[]; onOpen: (f: Finding) => void }) {
  const costs = scan.costs ?? [];
  const opportunities = findings
    .filter((f) => f.category === "cost" && !f.suppressed)
    .sort((a, b) => (b.estimated_monthly_savings ?? 0) - (a.estimated_monthly_savings ?? 0));
  const savings = opportunities.reduce((a, f) => a + (f.estimated_monthly_savings ?? 0), 0);
  const total = costs.reduce((a, c) => a + c.total, 0);

  return (
    <div className="grid">
      <div className="span-12 stats">
        <Stat label="Spend (last 30 days)" value={total ? money(total) : "—"} />
        <Stat label="Identified savings" value={`${money(savings)}/mo`} tone="good" hint={`${money(savings * 12)}/year`} />
        <Stat label="Savings vs spend" value={total ? `${((savings / total) * 100).toFixed(1)}%` : "—"} />
        <Stat label="Opportunities" value={opportunities.length} />
      </div>

      {costs.length === 0 && (
        <Card className="span-12">
          <Empty>No billing data. Grant ce:GetCostAndUsage (AWS) or Cost Management Reader (Azure).</Empty>
        </Card>
      )}
      {costs.map((c) => (
        <Card
          key={c.provider}
          className="span-6"
          title={<><ProviderTag provider={c.provider} /> spend by service</>}
          action={
            <span className="small muted">
              {money(c.total, c.currency)}
              {c.forecast_month_end ? ` · forecast ${money(c.forecast_month_end, c.currency)}` : ""}
            </span>
          }
        >
          <HBars items={c.by_service.slice(0, 8).map((s) => ({ label: s.service, value: s.amount }))} format={(n) => money(n, c.currency)} />
        </Card>
      ))}

      <Card className="span-12" title="Savings opportunities" action={<span className="small muted">estimates at list price</span>}>
        <table className="table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Cloud</th>
              <th>Resource</th>
              <th className="hide-s">Detail</th>
              <th className="num">Per month</th>
            </tr>
          </thead>
          <tbody>
            {opportunities.map((f) => (
              <tr key={f.id} onClick={() => onOpen(f)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && onOpen(f)}>
                <td className="mono">{f.rule_id}</td>
                <td><ProviderTag provider={f.provider} /></td>
                <td className="mono truncate">{f.resource_name}</td>
                <td className="hide-s truncate">{f.message}</td>
                <td className="num good">{f.estimated_monthly_savings ? money(f.estimated_monthly_savings) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
