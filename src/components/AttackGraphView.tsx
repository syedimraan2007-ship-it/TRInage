import React, { useState, useMemo, useRef } from 'react';
import { AttackPath, AttackPathNode, NormalizedFinding } from '../types';
import { ZoomIn, ZoomOut, RotateCcw, Filter, ShieldAlert, Crosshair, Sparkles, ExternalLink, X, Copy, Check, Info } from 'lucide-react';

interface AttackGraphViewProps {
  attackPaths: AttackPath[];
  findings: NormalizedFinding[];
  selectedPathId: string | null;
  onSelectPathId: (id: string | null) => void;
  onNavigateTab: (tab: string) => void;
}

interface PositionedNode extends AttackPathNode {
  x: number;
  y: number;
  col: number;
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({
  attackPaths,
  findings,
  selectedPathId,
  onSelectPathId,
  onNavigateTab,
}) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 40, y: 50 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<AttackPathNode | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [assetFilter, setAssetFilter] = useState<string>('ALL');
  const [copiedPayload, setCopiedPayload] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);

  // Filter paths
  const filteredPaths = useMemo(() => {
    return (attackPaths || []).filter(p => {
      if (severityFilter !== 'ALL' && p.severity !== severityFilter) return false;
      if (assetFilter !== 'ALL' && !(p.participatingAssets || []).includes(assetFilter)) return false;
      return true;
    });
  }, [attackPaths, severityFilter, assetFilter]);

  // Current active highlighted path
  const activePath = useMemo(() => {
    return (attackPaths || []).find(p => p.id === selectedPathId) || null;
  }, [attackPaths, selectedPathId]);

  // Collect unique assets for filter
  const allAssets = useMemo(() => {
    const set = new Set<string>();
    (attackPaths || []).forEach(p => (p.participatingAssets || []).forEach(a => set.add(a)));
    return Array.from(set);
  }, [attackPaths]);

  // Aggregate all nodes & edges for the selected scope
  const { nodes, edges } = useMemo(() => {
    const pathsToRender = activePath ? [activePath] : filteredPaths;
    const nodeMap = new Map<string, AttackPathNode>();
    const edgeMap = new Map<string, { id: string; fromNodeId: string; toNodeId: string; label: string; riskWeight: number }>();

    (pathsToRender || []).forEach(p => {
      (p?.nodes || []).forEach(n => {
        if (n && !nodeMap.has(n.id)) {
          nodeMap.set(n.id, n);
        }
      });
      (p?.edges || []).forEach(e => {
        if (!e) return;
        const edgeKey = `${e.fromNodeId}->${e.toNodeId}`;
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, e);
        }
      });
    });

    const rawNodes = Array.from(nodeMap.values());
    const rawEdges = Array.from(edgeMap.values());

    // Layered DAG positioning
    // 0 = threat_actor/entry, 1 = perimeter service/asset, 2 = vulnerability, 3 = target/datastore
    const colBuckets: AttackPathNode[][] = [[], [], [], []];

    rawNodes.forEach(n => {
      if (n.isEntrypoint || n.type === 'threat_actor') colBuckets[0].push(n);
      else if (n.type === 'asset' || n.type === 'service') colBuckets[1].push(n);
      else if (n.type === 'vulnerability') colBuckets[2].push(n);
      else colBuckets[3].push(n);
    });

    const positionedNodes: PositionedNode[] = [];
    const colSpacing = 280;
    const rowSpacing = 130;

    colBuckets.forEach((bucket, colIdx) => {
      const totalHeight = (bucket.length - 1) * rowSpacing;
      const startY = Math.max(90, 260 - totalHeight / 2);

      bucket.forEach((node, rowIdx) => {
        positionedNodes.push({
          ...node,
          x: 120 + colIdx * colSpacing,
          y: startY + rowIdx * rowSpacing,
          col: colIdx,
        });
      });
    });

    return { nodes: positionedNodes, edges: rawEdges };
  }, [filteredPaths, activePath]);

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target === containerRef.current || (e.target as HTMLElement).tagName === 'svg') {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  // Finding linked to currently inspected node
  const inspectedFinding = useMemo(() => {
    if (!selectedNode?.findingRef) return null;
    return findings.find(f => f.id === selectedNode.findingRef) || null;
  }, [selectedNode, findings]);

  const handleCopyEvidence = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Control Toolbar */}
      <div className="cyber-card rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-sm border border-slate-800">
        {/* Path Highlight Selector */}
        <div className="flex items-center space-x-2">
          <Crosshair className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="text-xs font-semibold text-slate-300">Highlight Chain:</span>
          <select
            id="attack-path-select"
            value={selectedPathId || ''}
            onChange={(e) => onSelectPathId(e.target.value ? e.target.value : null)}
            className="bg-slate-950 text-xs text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 max-w-xs truncate"
          >
            <option value="">All Correlated Paths ({attackPaths.length})</option>
            {attackPaths.map((p) => (
              <option key={p.id} value={p.id}>
                [{p.severity}] {p.title} ({p.contextualScore}/100)
              </option>
            ))}
          </select>
          {selectedPathId && (
            <button
              onClick={() => onSelectPathId(null)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 underline px-1"
            >
              Reset
            </button>
          )}
        </div>

        {/* Filters & Zoom */}
        <div className="flex items-center space-x-3">
          {/* Severity filter */}
          <div className="flex items-center space-x-1.5 text-xs text-slate-400">
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 text-xs text-slate-200 border border-slate-800 rounded-lg px-2 py-1"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical Only</option>
              <option value="High">High Only</option>
              <option value="Medium">Medium Only</option>
            </select>
          </div>

          {/* Asset filter */}
          {allAssets.length > 1 && (
            <div className="flex items-center space-x-1.5 text-xs text-slate-400">
              <span>Asset:</span>
              <select
                value={assetFilter}
                onChange={(e) => setAssetFilter(e.target.value)}
                className="bg-slate-950 text-xs text-slate-200 border border-slate-800 rounded-lg px-2 py-1 max-w-[140px] truncate"
              >
                <option value="ALL">All Assets</option>
                {allAssets.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Zoom controls */}
          <div className="flex items-center space-x-1 border-l border-slate-800 pl-3">
            <button
              onClick={() => setZoom(z => Math.max(0.4, z - 0.15))}
              className="p-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[11px] font-mono text-slate-400 w-10 text-center">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom(z => Math.min(2.0, z + 0.15))}
              className="p-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 40, y: 50 });
              }}
              className="p-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Canvas / Graph Container */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        className="relative bg-slate-950 border border-slate-800 rounded-2xl h-[620px] overflow-hidden cursor-grab active:cursor-grabbing select-none shadow-inner"
      >
        {/* Background Grid Accent */}
        <div
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(#06b6d4 1px, transparent 1px)`,
            backgroundSize: '24px 24px',
          }}
        />

        {/* Stage Columns Legend */}
        <div className="absolute top-3 left-8 right-8 flex justify-between pointer-events-none text-[11px] font-mono font-bold uppercase tracking-wider text-slate-500 z-10">
          <div>Stage 0: Ingress</div>
          <div>Stage 1: Perimeter Asset</div>
          <div>Stage 2: Exploited Weakness</div>
          <div>Stage 3: Crown Jewel Target</div>
        </div>

        {/* SVG Drawing Canvas */}
        <svg
          className="w-full h-full"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
            willChange: 'transform',
          }}
        >
          <defs>
            <marker
              id="arrow-marker"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#0891b2" opacity="0.8" />
            </marker>
            <marker
              id="arrow-marker-crit"
              viewBox="0 0 10 10"
              refX="22"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" opacity="0.95" />
            </marker>
          </defs>

          {/* Render Edges */}
          {edges.map((edge) => {
            const sourceNode = nodes.find(n => n.id === edge.fromNodeId);
            const targetNode = nodes.find(n => n.id === edge.toNodeId);
            if (!sourceNode || !targetNode) return null;

            const isHighlighted = activePath?.edges.some(
              e => e.fromNodeId === edge.fromNodeId && e.toNodeId === edge.toNodeId
            );

            // Bezier curve calculation
            const dx = targetNode.x - sourceNode.x;
            const controlX1 = sourceNode.x + dx * 0.5;
            const controlY1 = sourceNode.y;
            const controlX2 = sourceNode.x + dx * 0.5;
            const controlY2 = targetNode.y;

            const pathD = `M ${sourceNode.x} ${sourceNode.y} C ${controlX1} ${controlY1}, ${controlX2} ${controlY2}, ${targetNode.x} ${targetNode.y}`;

            return (
              <g key={edge.id}>
                <path
                  d={pathD}
                  fill="none"
                  stroke={isHighlighted ? '#f43f5e' : '#0891b2'}
                  strokeWidth={isHighlighted ? 3.5 : 1.5}
                  strokeDasharray={isHighlighted ? undefined : '4 3'}
                  opacity={isHighlighted ? 0.95 : 0.45}
                  markerEnd={isHighlighted ? 'url(#arrow-marker-crit)' : 'url(#arrow-marker)'}
                />
                {/* Edge Label */}
                <text
                  x={(sourceNode.x + targetNode.x) / 2}
                  y={(sourceNode.y + targetNode.y) / 2 - 8}
                  fill={isHighlighted ? '#fda4af' : '#94a3b8'}
                  fontSize="10"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="pointer-events-none"
                >
                  {edge.label}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNode?.id === node.id;
            const isInActivePath = activePath?.nodes.some(n => n.id === node.id);

            let nodeColor = '#0f172a';
            let strokeColor = '#334155';

            if (node.isEntrypoint || node.type === 'threat_actor') {
              nodeColor = '#020617';
              strokeColor = '#06b6d4';
            } else if (node.isTarget || node.type === 'datastore') {
              nodeColor = '#4c0519';
              strokeColor = '#f43f5e';
            } else if (node.type === 'vulnerability') {
              if (node.severity === 'Critical') {
                nodeColor = '#3f0713';
                strokeColor = '#e11d48';
              } else {
                nodeColor = '#331b05';
                strokeColor = '#f59e0b';
              }
            } else {
              nodeColor = '#082f49';
              strokeColor = '#38bdf8';
            }

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNode(node);
                }}
                className="cursor-pointer group"
              >
                {/* Node Box */}
                <rect
                  x="-90"
                  y="-32"
                  width="180"
                  height="64"
                  rx="10"
                  fill={nodeColor}
                  stroke={isSelected ? '#38bdf8' : strokeColor}
                  strokeWidth={isSelected ? 3 : isInActivePath ? 2.2 : 1}
                  className="transition-all duration-150 group-hover:brightness-125"
                  filter="drop-shadow(0 6px 12px rgba(0,0,0,0.6))"
                />

                {/* Node Category Badge */}
                <text
                  x="-80"
                  y="-14"
                  fill="#94a3b8"
                  fontSize="9"
                  fontFamily="monospace"
                  fontWeight="bold"
                  className="uppercase tracking-wider"
                >
                  {node.type.replace('_', ' ')}
                  {node.severity ? ` • ${node.severity}` : ''}
                </text>

                {/* Node Primary Label */}
                <text
                  x="-80"
                  y="4"
                  fill="#f8fafc"
                  fontSize="11"
                  fontWeight="bold"
                  className="truncate"
                >
                  {node.label.length > 22 ? node.label.slice(0, 20) + '...' : node.label}
                </text>

                {/* Node SubLabel */}
                {node.subLabel && (
                  <text
                    x="-80"
                    y="20"
                    fill="#64748b"
                    fontSize="9"
                    fontFamily="monospace"
                  >
                    {node.subLabel.length > 26 ? node.subLabel.slice(0, 24) + '...' : node.subLabel}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Empty state overlay */}
        {nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-400">
            <ShieldAlert className="w-12 h-12 text-slate-600 mb-2" />
            <p className="font-semibold text-slate-300">No attack graph nodes match current filters.</p>
            <p className="text-xs text-slate-500 mt-1">Try resetting severity or asset filters above.</p>
          </div>
        )}

        {/* Interactive Side Drawer Inspector (When Node is Clicked) */}
        {selectedNode && (
          <div className="absolute top-3 right-3 bottom-3 w-80 sm:w-96 bg-slate-900/95 backdrop-blur-md border border-slate-800 rounded-2xl p-5 shadow-2xl overflow-y-auto z-20 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-slate-800">
                  {selectedNode.type.replace('_', ' ')}
                </span>
                <h3 className="text-base font-bold text-slate-100 mt-1">{selectedNode.label}</h3>
                {selectedNode.subLabel && (
                  <p className="text-xs font-mono text-slate-400">{selectedNode.subLabel}</p>
                )}
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* If linked to finding */}
            {inspectedFinding ? (
              <div className="space-y-3 pt-2 border-t border-slate-800">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      inspectedFinding.severity === 'Critical'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}
                  >
                    {inspectedFinding.severity}
                  </span>
                  {inspectedFinding.cwe && (
                    <span className="text-xs font-mono text-slate-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {inspectedFinding.cwe}
                    </span>
                  )}
                  {inspectedFinding.cve && (
                    <span className="text-xs font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                      {inspectedFinding.cve}
                    </span>
                  )}
                </div>

                {/* AI Triage Calibrated Confidence */}
                {inspectedFinding.aiTriage && (
                  <div className="bg-slate-950/90 border border-cyan-900/50 rounded-xl p-3.5 space-y-2">
                    <div className="flex items-center space-x-1.5 text-xs text-cyan-400 font-bold">
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>AI Triage Assessment</span>
                    </div>
                    <div className="text-xs text-slate-300">
                      <strong>Confidence:</strong>{' '}
                      <span className="text-cyan-300 font-mono">
                        {inspectedFinding.aiTriage.calibratedConfidence}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      {inspectedFinding.aiTriage.businessImpact}
                    </p>
                  </div>
                )}

                {/* Evidence snippet */}
                {inspectedFinding.evidence && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span className="font-semibold">Scanner Payload Evidence:</span>
                      <button
                        onClick={() => handleCopyEvidence(inspectedFinding.evidence?.payload || inspectedFinding.evidence?.request || '')}
                        className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedPayload ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedPayload ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="bg-slate-950 p-3 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36 border border-slate-800">
                      {inspectedFinding.evidence.payload || inspectedFinding.evidence.request || inspectedFinding.evidence.rawOutput || 'No raw payload captured.'}
                    </pre>
                  </div>
                )}

                <button
                  onClick={() => onNavigateTab('findings')}
                  className="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-bold flex items-center justify-center space-x-1.5 transition"
                >
                  <span>Open in Findings Matrix</span>
                  <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                </button>
              </div>
            ) : (
              <div className="space-y-2 pt-2 border-t border-slate-800 text-xs text-slate-400">
                <p>
                  <strong>Asset / Node:</strong> {selectedNode.label}
                </p>
                <p>
                  <strong>Role:</strong> {selectedNode.isEntrypoint ? 'External threat entrypoint' : selectedNode.isTarget ? 'Critical backend database & customer data target' : 'Internal service boundary'}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
