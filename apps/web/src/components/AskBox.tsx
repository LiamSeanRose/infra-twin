import { type FormEvent, useState } from "react";
import type { AskAnswer } from "../types";

interface Props {
  onAsk: (question: string) => Promise<AskAnswer>;
}

export function AskBox({ onAsk }: Props) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AskAnswer | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!question.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setAnswer(await onAsk(question));
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>Ask</h2>
      <form onSubmit={submit} className="ask-form">
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. what VPCs do I have?"
        />
        <button disabled={busy}>{busy ? "…" : "Ask"}</button>
      </form>
      {error && <p className="error">{error}</p>}
      {answer && (
        <div className="answer">
          <p className="summary">{answer.summary}</p>
          {answer.template && <p className="muted">via template: {answer.template}</p>}
          <pre>{JSON.stringify(answer.data, null, 2)}</pre>
        </div>
      )}
    </section>
  );
}
