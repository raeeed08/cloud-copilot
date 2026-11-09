import { useMemo, useState } from "react";
import { api } from "../api";
import { Card, Empty, ProviderTag, SEVERITIES, SeverityBadge, money } from "../components/ui";
import type { Finding } from "../types";

export function Findings({ findings, provider, onOpen }: {
  findings: Finding[];
  provider: string;
  onOpen: (f: Finding) => void;
}) {
  const [severity, setSeverity] = useState("ALL");
  const [category, setCategory] = useState("ALL");
  const [service, setService] = useState("ALL");
  const [q, setQ] = useState("");
  const [showSuppressed, setShowSuppressed] = useState(false);

  const services = useMemo(() => [...new Set(findings.map((f) => f.service))].sort(), [findings]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter(
      (f) =>
        (provider === "all" || f.provider === provider) &&
        (severity === "ALL" || f.severity === severity) &&
        (category === "ALL" || f.category === category) &&
        (service === "ALL" || f.service === service) &&
        (showSuppressed || !f.suppressed) &&
        (!needle || `${f.rule_id} ${f.title} ${f.resource_name} ${f.message}`.toLowerCase().includes(needle)),
    );
  }, [findings, provider, severity, category, service, q, showSuppressed]);

  return (
    <Card
      title={`Findings (${rows.length})`}
      action={
        <div className="row gap-s">
          <a className="btn btn-ghost btn-s" href={api.exportUrl("csv")}>CSV</a>
          <a className="btn btn-ghost btn-s" href={api.exportUrl("md")}>Markdown</a>
        </div>
      }
    >
      <div className="filters">
        <input className="input" placeholder="Search rule, resource, message…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="ALL">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input" value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
          <option value="ALL">All categories</option>
          <option value="security">Security</option>
          <option value="cost">Cost</option>
          <option value="reliability">Reliability</option>
        </select>
        <select className="input" value={service} onChange={(e) => setService(e.target.value)} aria-label="Service">
          <option value="ALL">All services</option>
          {services.map((s) => <option key={s}>{s}</option>)}
        </select>
        <label className="check">
          <input type="checkbox" checked={showSuppressed} onChange={(e) => setShowSuppressed(e.target.checked)} /> Suppressed
        </label>
      </div>
      {rows.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Cloud</th>
                <th className="hide-s">Service</th>
                <th>Resource</th>
                <th className="hide-m">Region</th>
                <th className="hide-s">Issue</th>
                <th className="num hide-m">Savings</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr
                  key={f.id}
                  className={f.suppressed ? "is-suppressed" : ""}
                  onClick={() => onOpen(f)}
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && onOpen(f)}
                >
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td className="mono">{f.rule_id}</td>
                  <td><ProviderTag provider={f.provider} /></td>
                  <td className="hide-s">{f.service}</td>
                  <td className="mono truncate">{f.resource_name}</td>
                  <td className="hide-m small">{f.region ?? "global"}</td>
                  <td className="hide-s truncate">{f.message}</td>
                  <td className="num hide-m">{f.estimated_monthly_savings ? money(f.estimated_monthly_savings) : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
