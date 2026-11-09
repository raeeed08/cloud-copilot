import type { TrendPoint } from "../types";

export function scoreTone(score: number | null) {
  if (score === null) return "muted";
  if (score >= 80) return "good";
  if (score >= 50) return "warn";
  return "bad";
}

export function ScoreRing({ score, size = 132 }: { score: number | null; size?: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const pct = score ?? 0;
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={`Posture score ${score ?? "unknown"}`}>
      <circle cx="60" cy="60" r={r} className="ring-track" strokeWidth="10" fill="none" />
      <circle
        cx="60"
        cy="60"
        r={r}
        className={`ring-value tone-${scoreTone(score)}`}
        strokeWidth="10"
        fill="none"
        strokeLinecap="round"
        strokeDasharray={`${(pct / 100) * c} ${c}`}
        transform="rotate(-90 60 60)"
      />
      <text x="60" y="58" textAnchor="middle" className="ring-text">
        {score ?? "—"}
      </text>
      <text x="60" y="78" textAnchor="middle" className="ring-sub">
        / 100
      </text>
    </svg>
  );
}

export function TrendChart({ points }: { points: TrendPoint[] }) {
  const w = 520;
  const h = 140;
  const pad = 24;
  if (points.length < 2) return <p className="muted small">Run more scans to see the posture trend.</p>;
  const xs = (i: number) => pad + (i * (w - 2 * pad)) / (points.length - 1);
  const ys = (v: number) => h - pad - (v / 100) * (h - 2 * pad);
  const line = points.map((p, i) => `${i ? "L" : "M"}${xs(i)},${ys(p.score ?? 0)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="trend" role="img" aria-label="Posture score trend">
      {[0, 50, 100].map((v) => (
        <g key={v}>
          <line x1={pad} x2={w - pad} y1={ys(v)} y2={ys(v)} className="grid" />
          <text x={4} y={ys(v) + 4} className="axis">
            {v}
          </text>
        </g>
      ))}
      <path d={`${line} L${xs(points.length - 1)},${h - pad} L${xs(0)},${h - pad} Z`} className="trend-area" />
      <path d={line} className="trend-line" fill="none" />
      {points.map((p, i) => (
        <circle key={p.scan_id} cx={xs(i)} cy={ys(p.score ?? 0)} r="3.5" className="trend-dot">
          <title>{`${new Date(p.at).toLocaleString()}: score ${p.score}, ${p.findings} findings`}</title>
        </circle>
      ))}
    </svg>
  );
}

export function HBars({ items, format = (n: number) => String(n), tone = "accent" }: {
  items: { label: string; value: number }[];
  format?: (n: number) => string;
  tone?: string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="hbars">
      {items.map((i) => (
        <li key={i.label}>
          <span className="hbar-label" title={i.label}>
            {i.label}
          </span>
          <span className="hbar-track">
            <span className={`hbar-fill tone-${tone}`} style={{ width: `${(i.value / max) * 100}%` }} />
          </span>
          <span className="hbar-value">{format(i.value)}</span>
        </li>
      ))}
    </ul>
  );
}

export function SeverityStack({ counts }: { counts: Record<string, number> }) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const total = order.reduce((a, k) => a + (counts[k] ?? 0), 0) || 1;
  return (
    <div className="sevstack" role="img" aria-label="Findings by severity">
      {order.map((k) =>
        counts[k] ? (
          <span key={k} className={`sevstack-seg sev-${k.toLowerCase()}`} style={{ flex: counts[k] / total }}>
            <span className="sr-only">{`${k}: ${counts[k]}`}</span>
          </span>
        ) : null,
      )}
    </div>
  );
}
