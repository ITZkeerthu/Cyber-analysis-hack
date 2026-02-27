import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import './GraphView.css';

function GraphView({ graphData }) {
  const cyRef = useRef(null);
  const containerRef = useRef(null);
  const [stats, setStats] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!graphData || !containerRef.current) return;

    const { nodes, edges, central_nodes } = graphData;

    // Create central node IDs set
    const centralNodeIds = new Set(
      (central_nodes || []).map(n => n.id)
    );

    // Transform to Cytoscape format
    const cyNodes = (nodes || []).map(node => ({
      data: {
        id: node.id,
        label: node.label,
        type: node.type,
        riskScore: node.risk_score || 0
      },
      classes: centralNodeIds.has(node.id) ? 'central' : ''
    }));

    const cyEdges = (edges || []).map((edge, idx) => ({
      data: {
        id: `e${idx}`,
        source: edge.source,
        target: edge.target,
        label: edge.relation,
        relation: edge.relation
      }
    }));

    // Initialize Cytoscape
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: {
        nodes: cyNodes,
        edges: cyEdges
      },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#2a2a4a',
            'label': 'data(label)',
            'color': '#e0e0e0',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 40,
            'height': 40,
            'border-width': 2,
            'border-color': '#4a4a6a'
          }
        },
        {
          selector: 'node[type="user"]',
          style: {
            'background-color': '#4466bb',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="file"]',
          style: {
            'background-color': '#44ab6b',
            'shape': 'rectangle'
          }
        },
        {
          selector: 'node[type="device"]',
          style: {
            'background-color': '#ab44a0',
            'shape': 'triangle'
          }
        },
        {
          selector: 'node[type="ip"]',
          style: {
            'background-color': '#ab6b44',
            'shape': 'diamond'
          }
        },
        {
          selector: 'node[type="process"]',
          style: {
            'background-color': '#6b44ab',
            'shape': 'hexagon'
          }
        },
        {
          selector: 'node.central',
          style: {
            'border-width': 4,
            'border-color': '#ff4444',
            'width': 55,
            'height': 55
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#4a4a6a',
            'target-arrow-color': '#4a4a6a',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'color': '#888',
            'font-size': '10px',
            'text-background-color': '#1a1a2e',
            'text-background-opacity': 0.8,
            'text-background-shape': 'roundrectangle'
          }
        },
        {
          selector: 'edge[relation="EXECUTED"]',
          style: {
            'line-color': '#44ab6b',
            'target-arrow-color': '#44ab6b'
          }
        },
        {
          selector: 'edge[relation="ACCESSED"]',
          style: {
            'line-color': '#4466bb',
            'target-arrow-color': '#4466bb'
          }
        },
        {
          selector: 'edge[relation="CONNECTED"]',
          style: {
            'line-color': '#ab44a0',
            'target-arrow-color': '#ab44a0'
          }
        },
        {
          selector: ':selected',
          style: {
            'border-width': 3,
            'border-color': '#00ffff'
          }
        }
      ],
      layout: {
        name: 'cose',
        padding: 20,
        nodeRepulsion: 8000,
        idealEdgeLength: 100,
        edgeElasticity: 100,
        gravity: 0.5,
        numIter: 1000
      }
    });

    // Add click handler
    cyRef.current.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode({
        id: node.id(),
        ...node.data()
      });
    });

    // Calculate stats
    setStats({
      totalNodes: nodes?.length || 0,
      totalEdges: edges?.length || 0,
      centralNodes: central_nodes?.length || 0,
      nodeTypes: (nodes || []).reduce((acc, n) => {
        acc[n.type] = (acc[n.type] || 0) + 1;
        return acc;
      }, {})
    });

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
      }
    };
  }, [graphData]);

  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() / 1.2);
  };

  const handleFit = () => {
    cyRef.current?.fit();
  };

  if (!graphData) {
    return (
      <div className="graph-view">
        <div className="no-data">
          <h3>🕸️ Crime Graph</h3>
          <p>No graph data available.</p>
          <p>Run full analysis to generate graph.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="graph-view">
      <div className="graph-header">
        <h3>🕸️ Crime Reconstruction Graph</h3>
        <div className="graph-controls">
          <button onClick={handleZoomIn}>🔍+</button>
          <button onClick={handleZoomOut}>🔍-</button>
          <button onClick={handleFit}>Fit</button>
        </div>
      </div>

      <div className="graph-container"
        ref={containerRef}
        style={{ height: '500px', border: '1px solid #2a2a4a', borderRadius: '8px' }}
      />

      {stats && (
        <div className="graph-stats">
          <div className="stat-item">
            <span className="stat-value">{stats.totalNodes}</span>
            <span className="stat-label">Nodes</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{stats.totalEdges}</span>
            <span className="stat-label">Edges</span>
          </div>
          <div className="stat-item">
            <span className="stat-value highlight">{stats.centralNodes}</span>
            <span className="stat-label">Suspicious</span>
          </div>
        </div>
      )}

      <div className="graph-legend">
        <h4>Legend</h4>
        <div className="legend-items">
          <div className="legend-item">
            <span className="legend-shape user">⬤</span>
            <span>User</span>
          </div>
          <div className="legend-item">
            <span className="legend-shape file">■</span>
            <span>File</span>
          </div>
          <div className="legend-item">
            <span className="legend-shape device">▲</span>
            <span>Device</span>
          </div>
          <div className="legend-item">
            <span className="legend-shape ip">◆</span>
            <span>IP Address</span>
          </div>
          <div className="legend-item">
            <span className="legend-shape process">⬡</span>
            <span>Process</span>
          </div>
          <div className="legend-item">
            <span className="legend-shape central">⬤</span>
            <span>Central (Suspicious)</span>
          </div>
        </div>
      </div>

      {selectedNode && (
        <div className="node-details">
          <h4>📌 Node Details</h4>
          <p><strong>ID:</strong> {selectedNode.id}</p>
          <p><strong>Label:</strong> {selectedNode.label}</p>
          <p><strong>Type:</strong> {selectedNode.type}</p>
          <p><strong>Risk Score:</strong> {(selectedNode.riskScore * 100).toFixed(1)}%</p>
          <button onClick={() => setSelectedNode(null)}>Close</button>
        </div>
      )}
    </div>
  );
}

export default GraphView;