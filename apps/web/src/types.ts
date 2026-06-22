export interface CINode {
  id: string;
  type: string;
  external_id: string;
  name: string | null;
}

export interface GraphEdge {
  id: string;
  type: string;
  from_id: string;
  to_id: string;
  source: string;
  confidence: number;
}

export interface Graph {
  nodes: CINode[];
  edges: GraphEdge[];
}

export interface ImpactedCI {
  id: string;
  type: string;
  name: string | null;
  distance: number;
}

export interface BlastRadius {
  source_id: string;
  max_depth: number;
  impacted: ImpactedCI[];
  truncated_supernodes: { id: string; degree: number; depth: number }[];
}

export interface ChangeEventItem {
  entity: string;
  kind: string;
  at: string;
  id: string;
  type: string;
  name: string | null;
  from_id: string | null;
  to_id: string | null;
}

export interface AskAnswer {
  question: string;
  answered: boolean;
  template: string | null;
  params: Record<string, unknown>;
  summary: string;
  data: Record<string, unknown>;
}
