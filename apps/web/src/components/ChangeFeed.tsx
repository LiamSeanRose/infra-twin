import type { ChangeEventItem } from "../types";

interface Props {
  changes: ChangeEventItem[];
}

export function ChangeFeed({ changes }: Props) {
  return (
    <section className="panel">
      <h2>Changes (7d)</h2>
      {changes.length === 0 ? (
        <p className="muted">No recent changes.</p>
      ) : (
        <ul className="feed">
          {changes.map((c) => (
            <li key={`${c.entity}-${c.id}-${c.at}`} className={`kind-${c.kind}`}>
              <span className="badge">{c.kind}</span>
              <span className="what">
                {c.entity === "ci" ? (c.name ?? c.type) : `${c.type} edge`}
              </span>
              <time>{new Date(c.at).toLocaleString()}</time>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
