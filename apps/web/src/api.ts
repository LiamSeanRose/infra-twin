import type { AskAnswer, BlastRadius, ChangeEventItem, Graph } from "./types";

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8000";

/** Thin API client. Every request is authenticated via Authorization: Bearer <apiKey>. */
export class Api {
  constructor(
    private apiKey: string,
    private base: string = BASE,
  ) {}

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const resp = await fetch(`${this.base}${path}`, {
      method,
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) {
      const detail = await resp.text();
      throw new Error(`${resp.status} ${resp.statusText}: ${detail}`);
    }
    return (await resp.json()) as T;
  }

  graph(limit = 500): Promise<Graph> {
    return this.get<Graph>(`/graph?limit=${limit}`);
  }

  blastRadius(ciId: string, maxDepth = 4): Promise<BlastRadius> {
    return this.get<BlastRadius>(`/cis/${ciId}/blast-radius?max_depth=${maxDepth}`);
  }

  changes(days = 7): Promise<ChangeEventItem[]> {
    return this.get<ChangeEventItem[]>(`/changes?days=${days}`);
  }

  ask(question: string): Promise<AskAnswer> {
    return this.request<AskAnswer>("POST", "/ask", { question });
  }
}
