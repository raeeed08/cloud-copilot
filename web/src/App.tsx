import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "./api";
import { Chat } from "./components/Chat";
import { FindingDrawer } from "./components/FindingDrawer";
import { Empty, ago } from "./components/ui";
import { Accounts } from "./pages/Accounts";
import { Compliance } from "./pages/Compliance";
import { Cost } from "./pages/Cost";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Overview } from "./pages/Overview";
import { Settings } from "./pages/Settings";
import { Strategy } from "./pages/Strategy";
import type { CloudAccount, Finding, Framework, Info, Plan, Scan, TrendPoint } from "./types";

const TABS = [
  { id: "overview", label: "Overview", icon: "◎" },
  { id: "strategy", label: "Strategy", icon: "➜" },
  { id: "findings", label: "Findings", icon: "⚑" },
  { id: "compliance", label: "Compliance", icon: "✓" },
  { id: "cost", label: "Cost", icon: "$" },
  { id: "accounts", label: "Accounts", icon: "☁" },
  { id: "inventory", label: "Inventory", icon: "▤" },
  { id: "settings", label: "Settings", icon: "⚙" },
] as const;
type Tab = (typeof TABS)[number]["id"];

const tabFromHash = (): Tab => {
  const h = window.location.hash.replace("#/", "");
  return (TABS.find((t) => t.id === h)?.id ?? "overview") as Tab;
};

export default function App() {
  const [tab, setTab] = useState<Tab>(tabFromHash());
  const [provider, setProvider] = useState("all");
  const [info, setInfo] = useState<Info | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [history, setHistory] = useState<Scan[]>([]);
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [target, setTarget] = useState("default");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatSeed, setChatSeed] = useState<{ text: string; nonce: number } | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setError(null);
    try {
      setInfo(await api.info());
      setAccounts(await api.accounts());
      const latest = await api.latestScan();
      const [f, t, h, c, p] = await Promise.all([
        api.findings(latest.id),
        api.trend(),
        api.scans(),
        api.compliance(),
        api.plan(),
      ]);
      setScan(latest);
      setFindings(f);
      setTrend(t);
      setHistory(h);
      setFrameworks(c.frameworks);
      setPlan(p);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setScan(null);
      else if (e instanceof ApiError && e.status === 401) {
        setError("Authentication required: add your API key in Settings.");
        setTab("settings");
      } else setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const onHash = () => setTab(tabFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = (t: Tab) => {
    window.location.hash = `/${t}`;
    setTab(t);
  };

  const targetBody = (): { account_ids?: string[]; demo?: boolean } =>
    target === "demo" ? { demo: true } : target === "default" ? {} : { account_ids: [target] };

  const runScan = async (body?: { account_ids?: string[]; demo?: boolean }) => {
    setScanning(true);
    setError(null);
    try {
      const { id } = await api.startScan(body ?? targetBody());
      for (let i = 0; i < 600; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const s = await api.scan(id);
        if (!["queued", "running"].includes(s.status)) {
          if (s.status === "failed") setError(s.error ?? "Scan failed");
          break;
        }
      }
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const ask = (q: string) => {
    setSelected(null);
    setChatOpen(true);
    setChatSeed({ text: q, nonce: Date.now() });
  };

  const visible = provider === "all" ? findings : findings.filter((f) => f.provider === provider);

  return (
    <div className="app">
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={28} height={28} />
          <div>
            <strong>Cloud Copilot</strong>
            <span>Security & FinOps</span>
          </div>
        </div>
        {TABS.map((t) => (
          <button key={t.id} className={`nav-item ${tab === t.id ? "active" : ""}`} onClick={() => go(t.id)}>
            <span className="nav-icon" aria-hidden>{t.icon}</span>
            {t.label}
          </button>
        ))}
        <div className="sidebar-foot">
          {info?.demo_mode && <span className="pill pill-warn">Demo estate</span>}
          <span className="small">v{info?.version}</span>
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <div className="segmented" role="tablist" aria-label="Cloud provider">
            {["all", "aws", "azure"].map((p) => (
              <button key={p} role="tab" aria-selected={provider === p} className={provider === p ? "on" : ""} onClick={() => setProvider(p)}>
                {p === "all" ? "All clouds" : p === "aws" ? "AWS" : "Azure"}
              </button>
            ))}
          </div>
          <div className="row gap-s">
            {scan && <span className="small muted hide-s">Last scan {ago(scan.finished_at)}</span>}
            <button className="btn btn-ghost" onClick={() => setChatOpen((o) => !o)}>Copilot</button>
            <select className="input target" value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Scan target">
              <option value="default">{accounts.length ? `All connected accounts (${accounts.filter((a) => a.enabled).length})` : info?.demo_mode ? "Demo estate" : "Server credentials"}</option>
              {accounts.map((a) => <option key={a.id} value={a.id}>{a.provider.toUpperCase()} · {a.name}</option>)}
              {accounts.length > 0 && <option value="demo">Demo estate</option>}
            </select>
            <button className="btn" onClick={() => void runScan()} disabled={scanning}>
              {scanning ? "Scanning…" : "Run scan"}
            </button>
          </div>
        </header>

        <main className="content">
          {error && <div className="alert">{error}</div>}
          {loading ? (
            <Empty>Loading…</Empty>
          ) : tab === "settings" ? (
            <Settings info={info} onSaved={() => void load()} />
          ) : tab === "accounts" ? (
            <Accounts accounts={accounts} onChanged={() => void load()} onScan={(b) => void runScan(b)} scanning={scanning} />
          ) : !scan ? (
            <Welcome
              hasAccounts={accounts.length > 0}
              aiReady={!!info?.llm}
              scanning={scanning}
              onConnect={() => go("accounts")}
              onAi={() => go("settings")}
              onScan={(b) => void runScan(b)}
            />
          ) : tab === "strategy" ? (
            <Strategy plan={plan} onAsk={ask} onRescan={() => void runScan()} scanning={scanning} />
          ) : tab === "overview" ? (
            <Overview scan={scan} findings={visible} trend={trend} plan={plan} onOpen={setSelected} onStrategy={() => go("strategy")} />
          ) : tab === "findings" ? (
            <Findings findings={findings} provider={provider} onOpen={setSelected} />
          ) : tab === "compliance" ? (
            <Compliance frameworks={frameworks} />
          ) : tab === "cost" ? (
            <Cost scan={scan} findings={visible} onOpen={setSelected} />
          ) : (
            <Inventory scan={scan} history={history} />
          )}
        </main>
      </div>

      {selected && (
        <FindingDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onAsk={ask}
          onChanged={async () => {
            setSelected(null);
            await load();
          }}
        />
      )}
      <Chat open={chatOpen} onClose={() => setChatOpen(false)} seed={chatSeed} />
    </div>
  );
}

function Welcome({ hasAccounts, aiReady, scanning, onConnect, onAi, onScan }: {
  hasAccounts: boolean;
  aiReady: boolean;
  scanning: boolean;
  onConnect: () => void;
  onAi: () => void;
  onScan: (b: { account_ids?: string[]; demo?: boolean }) => void;
}) {
  return (
    <div className="welcome">
      <h1>Welcome to Cloud Copilot</h1>
      <p className="muted">From a cloud account to a prioritised, verified remediation strategy in four steps.</p>
      <ol className="steps">
        <li className={hasAccounts ? "done" : ""}>
          <strong>1. Connect an account</strong>
          <span className="small muted">AWS role or keys, Azure service principal. Read-only permissions.</span>
          <button className="btn btn-s" onClick={onConnect}>{hasAccounts ? "Manage accounts" : "Connect"}</button>
        </li>
        <li className={aiReady ? "done" : ""}>
          <strong>2. Plug in an AI provider</strong>
          <span className="small muted">Groq has a free tier. Optional: everything works offline too.</span>
          <button className="btn btn-s btn-ghost" onClick={onAi}>{aiReady ? "Configured ✓" : "Configure"}</button>
        </li>
        <li>
          <strong>3. Scan</strong>
          <span className="small muted">103 checks across 27 services, every region, attack-path correlation.</span>
          <div className="row gap-s wrap">
            {hasAccounts && <button className="btn btn-s" disabled={scanning} onClick={() => onScan({})}>{scanning ? "Scanning…" : "Scan my accounts"}</button>}
            <button className="btn btn-s btn-ghost" disabled={scanning} onClick={() => onScan({ demo: true })}>Try the demo estate</button>
          </div>
        </li>
        <li>
          <strong>4. Follow the strategy</strong>
          <span className="small muted">Break attack paths, fix by phase, re-scan to verify, add guardrails.</span>
        </li>
      </ol>
    </div>
  );
}
