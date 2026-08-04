import { useEffect, useMemo, useRef, useState, type ReactNode, type WheelEvent, type PointerEvent } from "react";
import { NAME_REF, type Graph, type GraphBlock, type Token } from "./api";

// Rough monospace metrics — good enough to size nodes before they're rendered.
const CHAR_W = 7.3;
const LINE_H = 18;
const PAD_X = 12;
const PAD_Y = 10;
const GAP_X = 44;
const GAP_Y = 56;

interface Placed {
  block: GraphBlock;
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Layout {
  nodes: Map<number, Placed>;
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

const MAX_RENDERED_BLOCKS = 750;
const MAX_PAN = 100000;

const EDGE_COLOR: Record<string, string> = {
  true: "#5fae5f", // taken conditional branch — green, like IDA
  false: "#cc5b5b", // fall-through — red
  uncond: "#5a8fd0", // unconditional jump — blue
};

function lineWidth(block: GraphBlock): number {
  let max = 0;
  for (const line of block.lines) {
    const addr = line.ea.length + 2;
    const text = line.tokens.reduce((sum, t) => sum + t.t.length, 0);
    max = Math.max(max, addr + text);
  }
  return max;
}

// Layered layout: rank blocks by BFS distance from the entry, center each rank.
function layout(graph: Graph): Layout {
  const nodes = new Map<number, Placed>();
  for (const block of graph.blocks) {
    nodes.set(block.id, {
      block,
      x: 0,
      y: 0,
      w: Math.max(120, lineWidth(block) * CHAR_W + PAD_X * 2),
      h: Math.max(LINE_H, block.lines.length * LINE_H) + PAD_Y * 2,
    });
  }

  if (nodes.size === 0) return { nodes, minX: 0, minY: 0, maxX: 0, maxY: 0 };

  const succ = new Map<number, number[]>();
  for (const edge of graph.edges) {
    if (!succ.has(edge.src)) succ.set(edge.src, []);
    succ.get(edge.src)!.push(edge.dst);
  }

  const entry = graph.blocks.find((b) => b.start === graph.ea)?.id ?? graph.blocks[0]?.id ?? 0;
  const rank = new Map<number, number>();
  const order: number[][] = [];
  const queue: number[] = [entry];
  rank.set(entry, 0);
  while (queue.length) {
    const id = queue.shift()!;
    const r = rank.get(id)!;
    (order[r] ??= []).push(id);
    for (const next of succ.get(id) ?? []) {
      if (!rank.has(next)) {
        rank.set(next, r + 1);
        queue.push(next);
      }
    }
  }
  // Park any unreachable blocks (data flow IDA couldn't trace) on a trailing rank.
  const orphans = graph.blocks.filter((b) => !rank.has(b.id)).map((b) => b.id);
  if (orphans.length) order.push(orphans);

  let y = 0;
  let minX = 0;
  for (const level of order) {
    if (!level || !level.length) continue;
    const rowHeight = Math.max(...level.map((id) => nodes.get(id)!.h));
    const totalWidth = level.reduce((sum, id) => sum + nodes.get(id)!.w, 0) + GAP_X * (level.length - 1);
    let x = -totalWidth / 2;
    for (const id of level) {
      const node = nodes.get(id)!;
      node.x = x;
      node.y = y;
      x += node.w + GAP_X;
    }
    minX = Math.min(minX, -totalWidth / 2);
    y += rowHeight + GAP_Y;
  }

  let maxX = 0;
  let maxY = 0;
  for (const node of nodes.values()) {
    maxX = Math.max(maxX, node.x + node.w);
    maxY = Math.max(maxY, node.y + node.h);
  }
  return { nodes, minX, minY: 0, maxX, maxY };
}

// Spread several edges that share an endpoint so they don't stack on one line.
function spread(index: number, count: number, width: number): number {
  if (count <= 1) return 0;
  const step = Math.min(16, (width - 24) / count);
  return (index - (count - 1) / 2) * step;
}

// Orthogonal routing: only horizontal and vertical segments, no diagonals.
function edgePath(from: Placed, to: Placed, exitOffset: number, entryOffset: number, lane: number): string {
  const sx = from.x + from.w / 2 + exitOffset;
  const sy = from.y + from.h;
  const tx = to.x + to.w / 2 + entryOffset;
  const ty = to.y;
  if (ty > sy + 1) {
    // Forward edge: down into the inter-row gap, across, then down into the target.
    const midY = sy + (ty - sy) / 2;
    return `M ${sx} ${sy} L ${sx} ${midY} L ${tx} ${midY} L ${tx} ${ty}`;
  }
  // Back edge (loop): drop, run out to the right past both blocks, climb, re-enter.
  const drop = 22;
  const sideX = Math.max(from.x + from.w, to.x + to.w) + 36 + lane * 16;
  return (
    `M ${sx} ${sy} L ${sx} ${sy + drop} L ${sideX} ${sy + drop} ` +
    `L ${sideX} ${ty - drop} L ${tx} ${ty - drop} L ${tx} ${ty}`
  );
}

// Tokens as SVG <tspan>s; sub_/loc_ names stay clickable for navigation.
function renderTspans(tokens: Token[], onNavigate: (addr: string) => void): ReactNode[] {
  return tokens.map((token, i) => {
    const match = token.t.match(NAME_REF);
    if (match) {
      return (
        <tspan key={i} className={`tok-${token.c} ref`} onClick={() => onNavigate("0x" + match[1])}>
          {token.t}
        </tspan>
      );
    }
    return (
      <tspan key={i} className={`tok-${token.c}`}>
        {token.t}
      </tspan>
    );
  });
}

export function GraphView({ graph, onNavigate }: { graph: Graph; onNavigate: (addr: string) => void }) {
  const { nodes, minX, minY, maxX, maxY } = useMemo(() => layout(graph), [graph]);
  const [view, setView] = useState(() => ({ x: 24 - minX, y: 24 - minY, scale: 1 }));
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ id: number; x: number; y: number; vx: number; vy: number } | null>(null);

  function fitGraph() {
    const element = svgRef.current;
    if (!element) return;
    const rect = element.getBoundingClientRect();
    const width = Math.max(1, maxX - minX);
    const height = Math.max(1, maxY - minY);
    const scale = Math.min(1.5, Math.max(0.15, Math.min((rect.width - 48) / width, (rect.height - 48) / height)));
    setView({
      x: (rect.width - width * scale) / 2 - minX * scale,
      y: 24 - minY * scale,
      scale,
    });
  }

  useEffect(() => {
    const frame = requestAnimationFrame(fitGraph);
    return () => cancelAnimationFrame(frame);
    // fitGraph intentionally follows the freshly-computed graph bounds.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, minX, minY, maxX, maxY]);

  // Zoom toward (px, py) in element-local coordinates, keeping that point fixed.
  function zoom(factor: number, px: number, py: number) {
    setView((v) => {
      const scale = Math.min(2.5, Math.max(0.15, v.scale * factor));
      return {
        scale,
        x: px - ((px - v.x) / v.scale) * scale,
        y: py - ((py - v.y) / v.scale) * scale,
      };
    });
  }

  function onWheel(e: WheelEvent) {
    e.preventDefault();
    const rect = e.currentTarget.getBoundingClientRect();
    zoom(e.deltaY < 0 ? 1.1 : 1 / 1.1, e.clientX - rect.left, e.clientY - rect.top);
  }

  function zoomButton(factor: number) {
    const el = svgRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    zoom(factor, rect.width / 2, rect.height / 2);
  }

  // Pointer Events cover mouse and touch with one path; pointer capture keeps the
  // drag tracking even past the graph's edge and guarantees we catch the release.
  function onPointerDown(e: PointerEvent<SVGSVGElement>) {
    if ((e.target as Element).closest(".ref")) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
  }

  function onPointerMove(e: PointerEvent<SVGSVGElement>) {
    const d = drag.current;
    if (!d || d.id !== e.pointerId) return;
    setView((v) => ({
      ...v,
      x: Math.max(-MAX_PAN, Math.min(MAX_PAN, d.vx + (e.clientX - d.x))),
      y: Math.max(-MAX_PAN, Math.min(MAX_PAN, d.vy + (e.clientY - d.y))),
    }));
  }

  function onPointerUp(e: PointerEvent<SVGSVGElement>) {
    if (drag.current?.id === e.pointerId) drag.current = null;
  }

  if (graph.blocks.length > MAX_RENDERED_BLOCKS) {
    return <div className="view dim">Graph has {graph.blocks.length} blocks; the safe browser limit is {MAX_RENDERED_BLOCKS}.</div>;
  }
  if (graph.blocks.length === 0) {
    return <div className="view dim">IDA returned an empty control-flow graph for this function.</div>;
  }

  const placed = [...nodes.values()];

  // Per-endpoint fan-out so multiple edges leaving/entering a block don't overlap.
  const outCount = new Map<number, number>();
  const inCount = new Map<number, number>();
  for (const edge of graph.edges) {
    outCount.set(edge.src, (outCount.get(edge.src) ?? 0) + 1);
    inCount.set(edge.dst, (inCount.get(edge.dst) ?? 0) + 1);
  }
  const outSeen = new Map<number, number>();
  const inSeen = new Map<number, number>();

  // One viewport-sized SVG with a single transformed group — no foreignObject,
  // no per-node compositing layers, so panning/zooming stays solid.
  return (
    <div className="graphwrap">
      <div className="graphzoom">
        <button onClick={() => zoomButton(1.25)} aria-label="Zoom in">+</button>
        <button onClick={() => zoomButton(1 / 1.25)} aria-label="Zoom out">−</button>
        <button onClick={fitGraph} aria-label="Fit graph" title="Fit graph">Fit</button>
      </div>
      <svg
        ref={svgRef}
        className="graph"
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onLostPointerCapture={() => {
          drag.current = null;
        }}
      >
        <defs>
          {Object.entries(EDGE_COLOR).map(([kind, color]) => (
            <marker key={kind} id={`arrow-${kind}`} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L8,4 L0,8 z" fill={color} />
            </marker>
          ))}
        </defs>
        <g transform={`translate(${view.x}, ${view.y}) scale(${view.scale})`}>
          {graph.edges.map((edge, i) => {
            const from = nodes.get(edge.src);
            const to = nodes.get(edge.dst);
            if (!from || !to) return null;
            const oi = outSeen.get(edge.src) ?? 0;
            outSeen.set(edge.src, oi + 1);
            const ii = inSeen.get(edge.dst) ?? 0;
            inSeen.set(edge.dst, ii + 1);
            const exitOffset = spread(oi, outCount.get(edge.src) ?? 1, from.w);
            const entryOffset = spread(ii, inCount.get(edge.dst) ?? 1, to.w);
            const color = EDGE_COLOR[edge.kind] ?? EDGE_COLOR.uncond;
            return (
              <path
                key={i}
                d={edgePath(from, to, exitOffset, entryOffset, oi)}
                fill="none"
                stroke={color}
                strokeWidth={1.6}
                markerEnd={`url(#arrow-${edge.kind})`}
              />
            );
          })}
          {placed.map((node) => (
            <g key={node.block.id} transform={`translate(${node.x}, ${node.y})`}>
              <rect className="gnode" width={node.w} height={node.h} rx={6} />
              {node.block.lines.map((line, li) => (
                <text key={line.ea} className="gtext mono" x={10} y={PAD_Y + 13 + li * LINE_H} xmlSpace="preserve">
                  <tspan className="dim">{line.ea}</tspan>
                  {"  "}
                  {renderTspans(line.tokens, onNavigate)}
                </text>
              ))}
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}
