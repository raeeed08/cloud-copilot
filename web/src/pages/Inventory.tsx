import { Card, ProviderTag, ago } from "../components/ui";
import type { Scan } from "../types";

export function Inventory({ scan, history }: { scan: Scan; history: Scan[] }) {
  const services = scan.services ?? [];
  return (
    <div className="grid">
      <Card className="span-8" title="Scanner coverage" action={<span className="small muted">{services.length} services</span>}>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Cloud</th>
                <th>Service</th>
                <th className="hide-s">Account</th>
                <th>Status</th>
                <th className="num">Resources</th>
                <th className="num hide-s">Rules</th>
                <th className="num hide-s">Time</th>
              </tr>
            </thead>
            <tbody>
              {services.map((s) => (
                <tr key={`${s.provider}:${s.account}:${s.service}`} title={s.error ?? s.warnings.join("\n")}>
                  <td><ProviderTag provider={s.provider} /></td>
                  <td>{s.service}</td>
                  <td className="hide-s mono small">{s.account ?? "—"}</td>
                  <td><span className={`pill pill-${s.status === "ok" ? "good" : s.status === "error" ? "bad" : "warn"}`}>{s.status}</span></td>
                  <td className="num">{s.resources}</td>
                  <td className="num hide-s">{s.rules_evaluated}</td>
                  <td className="num hide-s">{s.duration_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <div className="span-4 stack gap-m">
        <Card title="Accounts">
          <dl className="facts">
            {Object.entries(scan.accounts).map(([key, name]) => {
              const [prov, id] = key.includes(":") ? key.split(/:(.*)/s) : [key, name];
              return (
                <div key={key} className="contents">
                  <dt><ProviderTag provider={prov} /></dt>
                  <dd className="mono">{id}{name !== id ? ` · ${name}` : ""}</dd>
                </div>
              );
            })}
          </dl>
        </Card>
        <Card title="Scan history">
          <ul className="history">
            {history.map((h) => (
              <li key={h.id}>
                <span className={`pill pill-${h.status === "succeeded" ? "good" : h.status === "failed" ? "bad" : "warn"}`}>{h.status}</span>
                <span className="small">{ago(h.started_at)}</span>
                <span className="small muted">{h.trigger}</span>
                <span className="mono small">{h.score ?? "—"}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
