import { useState } from "react";
import { api } from "../api";
import { Card, Empty, ProviderTag, ago } from "../components/ui";
import type { CloudAccount } from "../types";

type Field = { key: string; label: string; secret?: boolean; placeholder?: string; list?: boolean; help?: string };

const METHODS: Record<string, { label: string; recommended?: boolean; help: string; config: Field[]; secret: Field[] }> = {
  "aws:assume_role": {
    label: "IAM role (assume role)",
    recommended: true,
    help: "Best practice: a read-only role (SecurityAudit + ViewOnlyAccess) in the target account. Base credentials come from the server (or the optional keys below). Terraform: infra/terraform/modules/aws-scanner-role.",
    config: [
      { key: "role_arn", label: "Role ARN", placeholder: "arn:aws:iam::123456789012:role/cloud-copilot-scanner" },
      { key: "external_id", label: "External ID (optional)" },
      { key: "regions", label: "Regions (optional, comma-separated)", list: true, placeholder: "eu-west-1, us-east-1" },
    ],
    secret: [
      { key: "access_key_id", label: "Base access key ID (optional)", secret: true },
      { key: "secret_access_key", label: "Base secret access key (optional)", secret: true },
    ],
  },
  "aws:access_keys": {
    label: "Access keys (IAM user)",
    help: "Quickest for a lab: an IAM user with SecurityAudit + ViewOnlyAccess. The lab Terraform (infra/terraform/lab-aws) creates one. Keys are encrypted at rest.",
    config: [{ key: "regions", label: "Regions (optional, comma-separated)", list: true, placeholder: "eu-west-1" }],
    secret: [
      { key: "access_key_id", label: "Access key ID", secret: true, placeholder: "AKIA…" },
      { key: "secret_access_key", label: "Secret access key", secret: true },
    ],
  },
  "aws:profile": {
    label: "Local AWS profile",
    help: "Uses a profile from ~/.aws on the server (works for `make dev`; in Docker, ~/.aws is mounted read-only).",
    config: [
      { key: "profile", label: "Profile name", placeholder: "default" },
      { key: "regions", label: "Regions (optional)", list: true },
    ],
    secret: [],
  },
  "aws:default": {
    label: "Server identity (IRSA / instance role / env)",
    help: "No credentials stored: uses whatever identity the server runs with.",
    config: [{ key: "regions", label: "Regions (optional)", list: true }],
    secret: [],
  },
  "azure:service_principal": {
    label: "Service principal",
    recommended: true,
    help: "az ad sp create-for-rbac --name cloud-copilot --role Reader --scopes /subscriptions/<id>   (add 'Security Reader' and 'Cost Management Reader' too).",
    config: [
      { key: "tenant_id", label: "Tenant ID" },
      { key: "client_id", label: "Client (app) ID" },
      { key: "subscription_ids", label: "Subscription IDs (optional, comma-separated)", list: true },
    ],
    secret: [{ key: "client_secret", label: "Client secret", secret: true }],
  },
  "azure:default": {
    label: "Server identity (az login / managed identity)",
    help: "Uses `az login` on the server, or the managed / workload identity in Azure.",
    config: [{ key: "subscription_ids", label: "Subscription IDs (optional)", list: true }],
    secret: [],
  },
};

function AddAccount({ onDone }: { onDone: () => void }) {
  const [provider, setProvider] = useState<"aws" | "azure">("aws");
  const [method, setMethod] = useState("assume_role");
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const spec = METHODS[`${provider}:${method}`];

  const switchProvider = (p: "aws" | "azure") => {
    setProvider(p);
    setMethod(p === "aws" ? "assume_role" : "service_principal");
    setValues({});
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const config: Record<string, unknown> = {};
    for (const f of spec.config) {
      const v = (values[f.key] ?? "").trim();
      if (v) config[f.key] = f.list ? v.split(",").map((x) => x.trim()).filter(Boolean) : v;
    }
    const secret: Record<string, string> = {};
    for (const f of spec.secret) if (values[f.key]?.trim()) secret[f.key] = values[f.key].trim();
    try {
      const acc = await api.addAccount({ name: name || `${provider.toUpperCase()} account`, provider, auth_method: method, config, secret });
      setValues({});
      setName("");
      if (acc.status === "error") setError(`Saved, but the connection failed: ${acc.status_detail}`);
      onDone();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Connect an account">
      <form className="stack gap-m" onSubmit={submit}>
        <div className="segmented">
          {(["aws", "azure"] as const).map((p) => (
            <button type="button" key={p} className={provider === p ? "on" : ""} onClick={() => switchProvider(p)}>
              {p === "aws" ? "AWS" : "Azure"}
            </button>
          ))}
        </div>
        <label className="field">
          <span>Authentication</span>
          <select className="input" value={method} onChange={(e) => { setMethod(e.target.value); setValues({}); }}>
            {Object.entries(METHODS).filter(([k]) => k.startsWith(provider)).map(([k, m]) => (
              <option key={k} value={k.split(":")[1]}>{m.label}{m.recommended ? " (recommended)" : ""}</option>
            ))}
          </select>
        </label>
        <p className="small muted">{spec.help}</p>
        <label className="field">
          <span>Display name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Personal lab / Prod" maxLength={128} />
        </label>
        {[...spec.config, ...spec.secret].map((f) => (
          <label className="field" key={f.key}>
            <span>{f.label}</span>
            <input
              className="input"
              type={f.secret ? "password" : "text"}
              autoComplete="off"
              placeholder={f.placeholder}
              value={values[f.key] ?? ""}
              onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
            />
          </label>
        ))}
        <p className="small muted">🔒 Secrets are encrypted at rest and never sent back to the browser. Use read-only permissions.</p>
        <button className="btn" disabled={busy}>{busy ? "Connecting…" : "Connect & verify"}</button>
        {error && <p className="error small">{error}</p>}
      </form>
    </Card>
  );
}

export function Accounts({ accounts, onChanged, onScan, scanning }: {
  accounts: CloudAccount[];
  onChanged: () => void;
  onScan: (target: { account_ids?: string[]; demo?: boolean }) => void;
  scanning: boolean;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const act = async (id: string, fn: () => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn();
      onChanged();
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="grid">
      <div className="span-7 stack gap-m">
        <Card title={`Connected accounts (${accounts.length})`}>
          {accounts.length === 0 ? (
            <Empty>
              No account connected yet. Connect one on the right, or
              <button className="btn btn-ghost" onClick={() => onScan({ demo: true })} disabled={scanning}>scan the demo estate</button>
            </Empty>
          ) : (
            <ul className="accounts">
              {accounts.map((a) => (
                <li key={a.id} className="account">
                  <div className="row between wrap gap-s">
                    <div className="row gap-s">
                      <ProviderTag provider={a.provider} />
                      <strong>{a.name}</strong>
                      <span className={`pill pill-${a.status === "connected" ? "good" : a.status === "error" ? "bad" : "muted"}`}>{a.status}</span>
                      {!a.enabled && <span className="pill pill-muted">disabled</span>}
                    </div>
                    <span className="small muted">{a.auth_method.replace("_", " ")} · verified {ago(a.verified_at)}</span>
                  </div>
                  <div className="small mono account-id">
                    {a.identity.account_id && <>Account {a.identity.account_id}{a.identity.alias ? ` (${a.identity.alias})` : ""} · {a.identity.arn}</>}
                    {a.identity.subscriptions && <>Tenant {a.identity.tenant_id} · {a.identity.subscriptions.map((s) => s.name).join(", ")}</>}
                  </div>
                  {a.status === "error" && <p className="error small">{a.status_detail}</p>}
                  <div className="row gap-s wrap">
                    <button className="btn btn-s" disabled={scanning || a.status === "error"} onClick={() => onScan({ account_ids: [a.id] })}>Scan</button>
                    {a.identity.console_url && (
                      <a className="btn btn-ghost btn-s" href={a.identity.console_url} target="_blank" rel="noreferrer">
                        Open {a.provider === "aws" ? "AWS console" : "Azure portal"} ↗
                      </a>
                    )}
                    <button className="btn btn-ghost btn-s" disabled={busy === a.id} onClick={() => act(a.id, () => api.verifyAccount(a.id))}>
                      {busy === a.id ? "…" : "Test connection"}
                    </button>
                    <button className="btn btn-ghost btn-s" onClick={() => act(a.id, () => api.updateAccount(a.id, { enabled: !a.enabled }))}>
                      {a.enabled ? "Disable" : "Enable"}
                    </button>
                    <button className="btn btn-ghost btn-s danger" onClick={() => confirm(`Remove ${a.name}? Stored credentials are deleted.`) && act(a.id, () => api.deleteAccount(a.id))}>
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Least privilege, by design">
          <ul className="small">
            <li>AWS: <code>SecurityAudit</code> + <code>ViewOnlyAccess</code> (+ <code>ce:GetCostAndUsage</code>), with an explicit deny on data reads.</li>
            <li>Azure: <code>Reader</code>, <code>Security Reader</code>, <code>Cost Management Reader</code> on the subscription.</li>
            <li>Cloud Copilot never changes your infrastructure: fixes are proposed, you apply them.</li>
          </ul>
        </Card>
      </div>
      <div className="span-5">
        <AddAccount onDone={onChanged} />
      </div>
    </div>
  );
}
