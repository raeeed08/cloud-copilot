import { useState } from "react";
import { getApiKey, setApiKey } from "../api";
import { Card } from "../components/ui";
import type { Info } from "../types";

export function Settings({ info, onSaved }: { info: Info | null; onSaved: () => void }) {
  const [key, setKey] = useState(getApiKey());
  return (
    <div className="grid">
      <Card className="span-6" title="API access">
        <p className="small muted">
          The key is kept in this browser tab only (sessionStorage) and sent as <code>X-API-Key</code>.
        </p>
        <form
          className="row gap-s"
          onSubmit={(e) => {
            e.preventDefault();
            setApiKey(key.trim());
            onSaved();
          }}
        >
          <input className="input" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder="API key" />
          <button className="btn">Save</button>
        </form>
      </Card>
      <Card className="span-6" title="Platform">
        {info && (
          <dl className="facts">
            <dt>Version</dt>
            <dd className="mono">{info.version}</dd>
            <dt>Mode</dt>
            <dd>{info.demo_mode ? "Demo estate (synthetic data)" : "Live accounts"}</dd>
            <dt>Providers</dt>
            <dd>{info.providers.join(", ")}</dd>
            <dt>Authentication</dt>
            <dd>{info.auth ? "API key required" : "Disabled (dev)"}</dd>
            <dt>LLM</dt>
            <dd>{info.llm ? "Connected" : "Offline: deterministic answers"}</dd>
            <dt>Retrieval</dt>
            <dd>{info.rag_mode === "hybrid" ? "Hybrid (BM25 + embeddings, RRF)" : "BM25"}</dd>
          </dl>
        )}
        <p className="small">
          <a href="/api/docs" target="_blank" rel="noreferrer">OpenAPI docs</a> · <a href="/metrics" target="_blank" rel="noreferrer">Prometheus metrics</a>
        </p>
      </Card>
    </div>
  );
}
