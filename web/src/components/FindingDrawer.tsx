import { useState } from "react";
import { api } from "../api";
import type { Finding } from "../types";
import { ProviderTag, SeverityBadge, money } from "./ui";

export function FindingDrawer({ finding, onClose, onChanged, onAsk }: {
  finding: Finding;
  onClose: () => void;
  onChanged: () => void;
  onAsk: (q: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = async () => {
    setBusy(true);
    setError(null);
    try {
      if (finding.suppressed) await api.unsuppress(finding.id);
      else await api.suppress(finding.id, reason);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!finding.terraform) return;
    try {
      await navigator.clipboard.writeText(finding.terraform);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("Clipboard unavailable");
    }
  };

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-label={finding.title} onClick={(e) => e.stopPropagation()}>
        <header className="drawer-head">
          <div>
            <div className="row gap-s">
              <SeverityBadge severity={finding.severity} />
              <ProviderTag provider={finding.provider} />
              <code>{finding.rule_id}</code>
            </div>
            <h2>{finding.title}</h2>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <dl className="facts">
          <dt>Resource</dt>
          <dd className="mono">{finding.resource_name}</dd>
          <dt>Service</dt>
          <dd>{finding.service}</dd>
          {finding.region && (
            <>
              <dt>Region</dt>
              <dd>{finding.region}</dd>
            </>
          )}
          {finding.account && (
            <>
              <dt>Account</dt>
              <dd className="mono">{finding.account}</dd>
            </>
          )}
          {finding.estimated_monthly_savings ? (
            <>
              <dt>Est. savings</dt>
              <dd className="good">{money(finding.estimated_monthly_savings)}/month</dd>
            </>
          ) : null}
        </dl>

        <h3>Issue</h3>
        <p>{finding.message}</p>
        <h3>Remediation</h3>
        <p>{finding.remediation}</p>

        {finding.terraform && (
          <>
            <div className="row between">
              <h3>Terraform</h3>
              <button className="btn btn-ghost btn-s" onClick={copy}>
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="code">{finding.terraform}</pre>
          </>
        )}

        {Object.keys(finding.compliance).length > 0 && (
          <>
            <h3>Compliance</h3>
            <ul className="chips">
              {Object.entries(finding.compliance).flatMap(([fw, ids]) =>
                ids.map((id) => (
                  <li key={`${fw}-${id}`} className="chip" title={fw}>
                    {fw.startsWith("CIS") ? "CIS" : "NIST"} {id}
                  </li>
                )),
              )}
            </ul>
          </>
        )}

        <div className="drawer-actions">
          <button className="btn" onClick={() => onAsk(`Explain ${finding.rule_id} on ${finding.resource_name} and give me a step-by-step fix.`)}>
            Ask Copilot
          </button>
          {!finding.suppressed && (
            <input
              className="input"
              placeholder="Reason to accept risk…"
              value={reason}
              maxLength={500}
              onChange={(e) => setReason(e.target.value)}
            />
          )}
          <button
            className="btn btn-ghost"
            disabled={busy || (!finding.suppressed && reason.trim().length < 3)}
            onClick={toggle}
          >
            {finding.suppressed ? "Reactivate" : "Suppress"}
          </button>
        </div>
        {error && <p className="error small">{error}</p>}
      </aside>
    </div>
  );
}
