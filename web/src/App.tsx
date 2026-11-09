import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "./api";
import { Chat } from "./components/Chat";
import { FindingDrawer } from "./components/FindingDrawer";
import { Empty, ago } from "./components/ui";
import { Compliance } from "./pages/Compliance";
import { Cost } from "./pages/Cost";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Overview } from "./pages/Overview";
import { Settings } from "./pages/Settings";
import type { Finding, Framework, Info, Scan, TrendPoint } from "./types";

const TABS = [
  { id: "overview", label: "Overview", icon: "◎" },
  { id: "findings", label: "Findings", icon: "⚑" },
  { id: "compliance", label: "Compliance", icon: "✓" },
  { id: "cost", label: "Cost", icon: "$" },
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
      const latest = await api.latestScan();
      const [f, t, h, c] = await Promise.all([api.findings(latest.id), api.trend(), api.scans(), api.compliance()]);
      setScan(latest);
      setFindings(f);
      setTrend(t);
      setHistory(h);
      setFrameworks(c.frameworks);
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

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { id } = await api.startScan();
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
            <button className="btn" onClick={runScan} disabled={scanning}>
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
          ) : !scan ? (
            <Empty>
              No scan yet. <button className="btn" onClick={runScan} disabled={scanning}>Run the first scan</button>
            </Empty>
          ) : tab === "overview" ? (
            <Overview scan={scan} findings={visible} trend={trend} onOpen={setSelected} />
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
