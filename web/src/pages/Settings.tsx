import { useEffect, useState } from "react";
import { api, getApiKey, setApiKey } from "../api";
import { Card } from "../components/ui";
import type { Info, LLMSettings } from "../types";

function AIProvider({ onSaved }: { onSaved: () => void }) {
  const [cfg, setCfg] = useState<LLMSettings | null>(null);
  const [provider, setProvider] = useState("groq");
  const [baseUrl, setBaseUrl] = useState("");
  const [models, setModels] = useState("");
  const [key, setKey] = useState("");
  const [language, setLanguage] = useState("English");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const fill = (c: LLMSettings, p = c.provider) => {
    const preset = c.presets[p];
    const same = p === c.provider;
    setProvider(p);
    setBaseUrl(same ? c.base_url : preset.base_url);
    setModels((same ? c.models : preset.models).join(", "));
    setLanguage(c.language);
  };

  useEffect(() => {
    api.llm().then((c) => {
      setCfg(c);
      fill(c, c.configured ? c.provider : "groq");
    }).catch(() => undefined);
  }, []);

  if (!cfg) return <Card title="AI provider"><p className="small muted">Loading…</p></Card>;
  const preset = cfg.presets[provider];

  const save = async (andTest: boolean) => {
    setBusy(true);
    setResult(null);
    try {
      const saved = await api.saveLlm({
        provider,
        base_url: baseUrl.trim() || undefined,
        models: models.split(",").map((m) => m.trim()).filter(Boolean),
        api_key: key.trim() || undefined,
        language,
      });
      setCfg(saved);
      setKey("");
      onSaved();
      if (andTest) {
        const t = await api.testLlm();
        setResult(t.ok ? { ok: true, text: `Connected: ${t.model} answered in ${t.latency_ms} ms.` } : { ok: false, text: t.error ?? "Failed" });
      } else setResult({ ok: true, text: "Saved." });
    } catch (e) {
      setResult({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title="AI provider"
      action={
        <span className={`pill pill-${!cfg.configured ? "warn" : cfg.health?.ok === false ? "bad" : cfg.health?.ok ? "good" : "muted"}`}>
          {!cfg.configured ? "not configured" : cfg.health?.ok === false ? "failing" : cfg.health?.ok ? "working" : "untested"}
          {cfg.configured ? ` · ${cfg.provider}${cfg.source === "env" ? " (server env)" : ""}` : ""}
        </span>
      }
    >
      <form className="stack gap-m" onSubmit={(e) => { e.preventDefault(); void save(true); }}>
        <p className="small muted">
          Powers the strategy briefing and the Copilot chat. Any OpenAI-compatible API works. Changes apply immediately, no restart.
        </p>
        <label className="field">
          <span>Provider</span>
          <select className="input" value={provider} onChange={(e) => fill(cfg, e.target.value)}>
            {Object.entries(cfg.presets).map(([id, p]) => <option key={id} value={id}>{p.label}</option>)}
          </select>
        </label>
        {preset.needs_key && (
          <label className="field">
            <span>
              API key {preset.key_url && <a href={preset.key_url} target="_blank" rel="noreferrer">(get one ↗)</a>}
            </span>
            <input
              className="input"
              type="password"
              autoComplete="off"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={cfg.has_key && cfg.provider === provider ? `stored ${cfg.key_hint}: leave empty to keep` : provider === "groq" ? "gsk_…" : "sk-…"}
            />
          </label>
        )}
        <label className="field">
          <span>Models (fallback order)</span>
          <input className="input" value={models} onChange={(e) => setModels(e.target.value)} />
        </label>
        <details>
          <summary className="small">Advanced</summary>
          <div className="stack gap-m" style={{ marginTop: 8 }}>
            <label className="field">
              <span>Base URL</span>
              <input className="input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
            </label>
            <label className="field">
              <span>Answer language</span>
              <select className="input" value={language} onChange={(e) => setLanguage(e.target.value)}>
                {["English", "French", "Arabic", "Spanish", "German"].map((l) => <option key={l}>{l}</option>)}
              </select>
            </label>
          </div>
        </details>
        <div className="row gap-s wrap">
          <button className="btn" disabled={busy}>{busy ? "Testing…" : "Save & test"}</button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => void save(false)}>Save only</button>
          {cfg.source === "ui" && (
            <button type="button" className="btn btn-ghost" disabled={busy} onClick={async () => { const c = await api.resetLlm(); setCfg(c); fill(c); onSaved(); }}>
              Reset to server default
            </button>
          )}
        </div>
        {result && <p className={`small ${result.ok ? "good" : "error"}`}>{result.text}</p>}
        {!result && cfg.health?.ok === false && <p className="small error">Last call failed: {cfg.health.detail}</p>}
        <p className="small muted">🔒 The key is encrypted at rest and never returned to the browser. Identifiers (account IDs, IPs, ARNs) are pseudonymised before prompts leave the platform.</p>
      </form>
    </Card>
  );
}

export function Settings({ info, onSaved }: { info: Info | null; onSaved: () => void }) {
  const [key, setKey] = useState(getApiKey());
  return (
    <div className="grid">
      <div className="span-6 stack gap-m">
        <AIProvider onSaved={onSaved} />
      </div>
      <div className="span-6 stack gap-m">
        <Card title="Platform">
          {info && (
            <dl className="facts">
              <dt>Version</dt>
              <dd className="mono">{info.version}</dd>
              <dt>Default target</dt>
              <dd>{info.accounts ? `${info.accounts} connected account(s)` : info.demo_mode ? "Demo estate (synthetic data)" : "Server credentials"}</dd>
              <dt>AI</dt>
              <dd>
                {!info.llm ? "Offline: deterministic answers"
                  : info.llm_health?.ok === false ? `Failing (${info.llm_provider}): ${info.llm_health.detail}`
                  : info.llm_health?.ok ? `Working (${info.llm_provider})`
                  : `Configured (${info.llm_provider}), not tested yet`}
              </dd>
              <dt>Retrieval</dt>
              <dd>{info.rag_mode === "hybrid" ? "Hybrid (BM25 + embeddings, RRF)" : "BM25 keyword retrieval"}</dd>
              <dt>Dashboard auth</dt>
              <dd>{info.auth ? "API key required" : "Disabled (local dev)"}</dd>
            </dl>
          )}
          <p className="small">
            <a href="/api/docs" target="_blank" rel="noreferrer">API docs (Swagger)</a> · <a href="/metrics" target="_blank" rel="noreferrer">Prometheus metrics</a>
          </p>
        </Card>
        <Card title="Dashboard access key">
          <p className="small muted">
            Only needed when the <em>server</em> is started with <code>API_KEYS</code> (production). This is <strong>not</strong> where the AI key goes: use “AI provider”.
          </p>
          <form className="row gap-s" onSubmit={(e) => { e.preventDefault(); setApiKey(key.trim()); onSaved(); }}>
            <input className="input" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder="X-API-Key value" />
            <button className="btn btn-ghost">Save</button>
          </form>
        </Card>
      </div>
    </div>
  );
}
