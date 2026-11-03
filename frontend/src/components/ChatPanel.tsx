import { useState, type FormEvent } from "react";
import { chat } from "../api";
import type { ChatHistoryMessage } from "../types";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  provider?: string;
  model?: string;
  fallback?: boolean;
}

interface ChatPanelProps {
  scanId: string | null;
}

let messageCounter = 0;

function nextId(): string {
  messageCounter += 1;
  return `msg-${messageCounter}`;
}

export default function ChatPanel({ scanId }: ChatPanelProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const send = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const text = draft.trim();
    if (!text || busy) {
      return;
    }

    const history: ChatHistoryMessage[] = messages.map((message) => ({
      role: message.role,
      content: message.text,
    }));

    setMessages((current) => [...current, { id: nextId(), role: "user", text }]);
    setDraft("");
    setBusy(true);
    setError(null);

    try {
      const payload = scanId ? { message: text, scan_id: scanId, history } : { message: text, history };
      const response = await chat(payload);
      setMessages((current) => [
        ...current,
        {
          id: nextId(),
          role: "assistant",
          text: response.reply,
          provider: response.provider,
          model: response.model,
          fallback: response.fallback,
        },
      ]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The chat request failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel chat-panel">
      <header className="panel-head">
        <h2>AI assistant</h2>
        <span className="muted">{scanId ? `scan ${scanId}` : "no scan context"}</span>
      </header>

      <div className="chat-log" role="log" aria-live="polite" aria-label="Assistant conversation">
        {messages.length === 0 ? (
          <p className="muted">
            Ask about the pipeline, findings, remediation or the current scan.
          </p>
        ) : (
          messages.map((message) => (
            <div className={`bubble ${message.role}`} key={message.id}>
              <p className="bubble-text">{message.text}</p>
              {message.role === "assistant" ? (
                <p className="chat-meta">
                  <span className="badge badge-quiet">
                    {message.provider || "unknown"} / {message.model || "unknown"}
                  </span>
                  {message.fallback ? (
                    <span className="badge badge-warn">fallback</span>
                  ) : (
                    <span className="badge badge-ok">model</span>
                  )}
                </p>
              ) : null}
            </div>
          ))
        )}
      </div>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      <form className="chat-form" onSubmit={send}>
        <div className="field">
          <label htmlFor="chat-input">Message</label>
          <textarea
            id="chat-input"
            name="message"
            rows={3}
            value={draft}
            placeholder="Explain this finding and how to verify it"
            onChange={(event) => setDraft(event.target.value)}
          />
        </div>
        <button className="btn btn-primary" type="submit" disabled={busy || draft.trim() === ""}>
          {busy ? "Thinking…" : "Send"}
        </button>
      </form>
    </section>
  );
}
