import { useState } from "react";
import { Card, Empty } from "../components/ui";
import type { Framework } from "../types";

export function Compliance({ frameworks }: { frameworks: Framework[] }) {
  const [open, setOpen] = useState<string | null>(frameworks[0]?.framework ?? null);
  if (!frameworks.length) return <Empty>No compliance data yet. Run a scan.</Empty>;
  return (
    <div className="stack gap-m">
      <div className="grid">
        {frameworks.map((f) => (
          <button
            key={f.framework}
            className={`card span-4 fw-card ${open === f.framework ? "selected" : ""}`}
            onClick={() => setOpen(f.framework)}
          >
            <span className="small muted">{f.framework}</span>
            <span className="fw-percent">{f.percent}%</span>
            <span className="meter">
              <span className="meter-fill" style={{ width: `${f.percent}%` }} />
            </span>
            <span className="small">
              {f.passed} / {f.total} controls passing
            </span>
          </button>
        ))}
      </div>
      {frameworks
        .filter((f) => f.framework === open)
        .map((f) => (
          <Card key={f.framework} title={f.framework} action={<span className="muted small">indicative mapping</span>}>
            <div className="controls">
              {f.controls.map((c) => (
                <div key={c.control} className={`control control-${c.status}`} title={c.rules.join(", ")}>
                  <span className="mono">{c.control}</span>
                  <span className="small">{c.status === "pass" ? "Pass" : "Fail"}</span>
                  <span className="small muted truncate">{c.rules.join(", ")}</span>
                </div>
              ))}
            </div>
          </Card>
        ))}
    </div>
  );
}
