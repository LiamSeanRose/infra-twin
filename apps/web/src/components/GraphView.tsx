import cytoscape, {
  type Core,
  type ElementDefinition,
  type StylesheetStyle,
} from "cytoscape";
import { useEffect, useRef } from "react";
import type { Graph } from "../types";

const COLORS: Record<string, string> = {
  cloud_account: "#7c3aed",
  region: "#6366f1",
  vpc: "#2563eb",
  subnet: "#0891b2",
  security_group: "#16a34a",
  ec2_instance: "#ca8a04",
  elb: "#db2777",
  rds: "#dc2626",
  s3_bucket: "#ea580c",
  iam_role: "#0d9488",
  iam_user: "#65a30d",
  eks_cluster: "#9333ea",
};

function colorFor(type: string): string {
  return COLORS[type] ?? "#64748b";
}

const STYLE: StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      "background-color": "data(color)",
      label: "data(label)",
      "font-size": 7,
      color: "#e2e8f0",
      "text-valign": "bottom",
      "text-margin-y": 3,
      width: 18,
      height: 18,
    },
  },
  {
    selector: "edge",
    style: {
      width: 1,
      "line-color": "#475569",
      "target-arrow-color": "#475569",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "arrow-scale": 0.7,
    },
  },
  {
    selector: "node.impacted",
    style: { "border-width": 3, "border-color": "#f59e0b" },
  },
  {
    selector: "node.source",
    style: { "border-width": 4, "border-color": "#ef4444", width: 26, height: 26 },
  },
];

interface Props {
  graph: Graph;
  highlighted: Set<string>;
  sourceId: string | null;
  onSelect: (id: string) => void;
}

export function GraphView({ graph, highlighted, sourceId, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const elements: ElementDefinition[] = [
      ...graph.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.name ?? n.external_id,
          type: n.type,
          color: colorFor(n.type),
        },
      })),
      ...graph.edges.map((e) => ({
        data: { id: e.id, source: e.from_id, target: e.to_id },
      })),
    ];
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: STYLE,
      layout: { name: "cose", animate: false, padding: 30 },
    });
    cy.on("tap", "node", (evt) => onSelect(evt.target.id()));
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().removeClass("impacted source");
      highlighted.forEach((id) => cy.getElementById(id).addClass("impacted"));
      if (sourceId) cy.getElementById(sourceId).addClass("source");
    });
  }, [highlighted, sourceId]);

  return <div className="graph" ref={containerRef} />;
}
