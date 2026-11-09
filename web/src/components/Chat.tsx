import { useEffect, useRef, useState } from "react";
import Markdown from "react-markdown";
import { api } from "../api";
import type { ChatAnswer } from "../types";

type Msg = { role: "user" | "assistant"; content: string; meta?: ChatAnswer };

const SUGGESTIONS = [
  "What should I fix first this week?",
  "How do I respond to a leaked AWS access key?",
  "Where can I save money?",
  "Explain our CIS AWS compliance gaps",
];

// react-markdown never renders raw HTML, so model output (which may echo attacker-controlled resource
// names) cannot inject script into the dashboard.
export function Chat({ open, onClose, seed }: {
  open: boolean;
  onClose: () => void;
  seed: { text: string; nonce: number } | null;
}) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const lastSeed = useRef<number | null>(null);

  const send = async (text: string) => {
    const q = text.trim();
    if (!q || busy) return;
    const history = messages.map(({ role, content }) => ({ role, content }));
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setBusy(true);
    try {
      const ans = await api.chat(q, history);
      setMessages((m) => [...m, { role: "assistant", content: ans.answer, meta: ans }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", content: `**Error:** ${(e as Error).message}` }]);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (seed && seed.nonce !== lastSeed.current) {
      lastSeed.current = seed.nonce;
      void send(seed.text);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seed]);

  useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [messages, busy]);

  return (
    <aside className={`chat ${open ? "open" : ""}`} aria-hidden={!open} aria-label="Copilot chat">
      <header className="chat-head">
        <div>
          <strong>Copilot</strong>
          <span className="muted small"> · RAG over findings & playbooks</span>
        </div>
        <button className="icon-btn" onClick={onClose} aria-label="Close chat">
          ✕
        </button>
      </header>
      <div className="chat-body">
        {messages.length === 0 && (
          <div className="suggestions">
            <p className="muted small">Ask about your findings, compliance gaps, incident response or cost.</p>
            {SUGGESTIONS.map((s) => (
              <button key={s} className="suggestion" onClick={() => send(s)}>
                {s}
              </button>
            ))}
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`msg msg-${m.role}`}>
            <div className="msg-bubble">
              {m.role === "assistant" ? <Markdown>{m.content}</Markdown> : m.content}
            </div>
            {m.meta && (
              <div className="msg-meta">
                <span className={`pill ${m.meta.mode === "llm" ? "pill-ok" : "pill-warn"}`}>
                  {m.meta.mode === "llm" ? m.meta.model : "offline"}
                </span>
                {m.meta.latency_ms > 0 && <span>{(m.meta.latency_ms / 1000).toFixed(1)}s</span>}
                {m.meta.citations.length > 0 && (
                  <details>
                    <summary>{m.meta.citations.length} sources</summary>
                    <ol>
                      {m.meta.citations.map((c) => (
                        <li key={c.id} title={c.id}>
                          {c.title}
                        </li>
                      ))}
                    </ol>
                  </details>
                )}
              </div>
            )}
          </div>
        ))}
        {busy && <div className="msg msg-assistant"><div className="msg-bubble typing">Thinking…</div></div>}
        <div ref={endRef} />
      </div>
      <form
        className="chat-input"
        onSubmit={(e) => {
          e.preventDefault();
          void send(input);
        }}
      >
        <input
          className="input"
          value={input}
          maxLength={2000}
          placeholder="Ask the Copilot…"
          onChange={(e) => setInput(e.target.value)}
        />
        <button className="btn" disabled={busy || !input.trim()}>
          Send
        </button>
      </form>
    </aside>
  );
}
