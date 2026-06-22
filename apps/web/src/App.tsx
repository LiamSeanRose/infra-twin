import { useCallback, useEffect, useMemo, useState } from "react";
import { Api } from "./api";
import { AskBox } from "./components/AskBox";
import { ChangeFeed } from "./components/ChangeFeed";
import { GraphView } from "./components/GraphView";
import type { ChangeEventItem, Graph } from "./types";

export function App() {
  const [tenantId, setTenantId] = useState(() => localStorage.getItem("tenantId") ?? "");
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [changes, setChanges] = useState<ChangeEventItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set());
  const [sourceId, setSourceId] = useState<string | null>(null);
  const [impact, setImpact] = useState<string | null>(null);

  const api = useMemo(() => (tenantId ? new Api(tenantId) : null), [tenantId]);

  useEffect(() => {
    localStorage.setItem("tenantId", tenantId);
  }, [tenantId]);

  const load = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);
    setHighlighted(new Set());
    setSourceId(null);
    setImpact(null);
    try {
      const [g, c] = await Promise.all([api.graph(), api.changes()]);
      setGraph(g);
      setChanges(c);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [api]);

  const onSelect = useCallback(
    async (id: string) => {
      if (!api) return;
      setSourceId(id);
      try {
        const br = await api.blastRadius(id);
        setHighlighted(new Set(br.impacted.map((i) => i.id)));
        setImpact(`${br.impacted.length} resource(s) impacted`);
      } catch (e) {
        setError(String(e));
      }
    },
    [api],
  );

  return (
    <div className="app">
      <header>
        <h1>infra-twin</h1>
        <input
          className="tenant"
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          placeholder="tenant UUID"
        />
        <button onClick={load} disabled={!api || loading}>
          {loading ? "Loading…" : "Load"}
        </button>
        {error && <span className="error">{error}</span>}
      </header>
      <main>
        <div className="graph-wrap">
          {graph.nodes.length === 0 ? (
            <p className="muted center">Enter a tenant UUID and click Load. Click a node for its blast radius.</p>
          ) : (
            <GraphView
              graph={graph}
              highlighted={highlighted}
              sourceId={sourceId}
              onSelect={onSelect}
            />
          )}
          {impact && <div className="impact-badge">{impact}</div>}
        </div>
        <aside>
          {api && <AskBox onAsk={(q) => api.ask(q)} />}
          <ChangeFeed changes={changes} />
        </aside>
      </main>
    </div>
  );
}
