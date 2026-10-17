import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { chartMetrics, chartResources, chartRuns, scannerColor, formatChartResource } from '../utils/scanChart';

const W = 1100, H = 440, left = 70, right = 32, top = 32, bottom = 65;
const pct = value => `${(value * 100).toFixed(1)}%`;
const amount = formatChartResource;
const runName = scan => `#${scan.id} · ${scan.scanner_name || 'Unknown scanner'}${scan.scanner_version ? ` ${scan.scanner_version}` : ''} · ${scan.app_name || 'Unknown app'}${scan.app_version ? ` ${scan.app_version}` : ''}`;

export function ScanPerformanceChart({ scans, labelsMap, resource = 'cost', metric = 'weighted_f05', onAxisChange, latest }) {
  const [selectedId, setSelectedId] = useState(null);
  const [hoveredId, setHoveredId] = useState(null);
  const { points, excluded, missingResource, missingScore } = useMemo(() => chartRuns(scans, resource, metric), [scans, resource, metric]);
  const scanners = [...new Set(points.map(p => p.scan.scanner_name || 'Unknown scanner'))].sort();
  const color = scan => scannerColor(scan.scanner_name);
  const extent = points.reduce((max, p) => Math.max(max, p.x), 0) * 1.08 || 1;
  const magnitude = 10 ** Math.floor(Math.log10(extent / 4));
  const step = [1, 2, 5, 10].find(value => value * magnitude >= extent / 4) * magnitude;
  const maxX = step * 4;
  const px = value => left + value / maxX * (W - left - right);
  const py = value => H - bottom - value * (H - top - bottom);
  const active = points.find(p => p.scan.id === (hoveredId ?? selectedId));
  const selected = points.find(p => p.scan.id === selectedId);
  const reviewedMetric = ['weighted_f05', 'weighted_precision'].includes(metric);
  const awaitingReview = reviewedMetric ? scans.filter(scan => scan.metrics?.weighted_score_provisional !== false).length : 0;
  const provisional = !reviewedMetric && points.some(p => p.scan.metrics.pending > 0);
  const mixedApps = new Set(points.map(p => p.scan.app_id)).size > 1;

  return <section className="card scan-chart" aria-label="Run performance chart">
    <div className="scan-chart-header">
      <div><h2>Quality vs. resources</h2><p className="text-muted">One point per run · Better results toward the upper left</p></div>
      <div className="scan-chart-controls">
        <label>Y · Quality<select className="form-select" value={metric} onChange={e => onAxisChange('chart_y', e.target.value)}>
          {Object.entries(chartMetrics).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>
        <label>X · Resources<select className="form-select" value={resource} onChange={e => onAxisChange('chart_x', e.target.value)}>
          {Object.entries(chartResources).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>
      </div>
    </div>
    <p className="scan-chart-coverage" role="status">{points.length} of {scans.length} filtered runs plotted{latest ? ' · Latest per scanner and app' : ' · All matching runs'}.
      {excluded > 0 && ` ${excluded} omitted: ${missingResource} missing or restricted ${resource}, ${missingScore} unavailable scores${awaitingReview ? `, including ${awaitingReview} awaiting review` : ''} (reasons can overlap).`}</p>
    {mixedApps && <p className="scan-summary-note">These runs span multiple apps. Compare the same app version and benchmark corpus.</p>}
    {points.length ? <>
      <div className="scan-chart-plot">
        <svg viewBox={`0 0 ${W} ${H}`} role="group" aria-label={`${chartMetrics[metric]} versus ${chartResources[resource]}. Each dot is a scan; focus or select a dot to inspect it.`}>
          {[0, .25, .5, .75, 1].map(value => <g key={value}>
            <line x1={left} x2={W - right} y1={py(value)} y2={py(value)} className="scan-chart-grid" />
            <text x={left - 12} y={py(value) + 4} textAnchor="end">{Math.round(value * 100)}%</text>
          </g>)}
          {[0, .25, .5, .75, 1].map(fraction => <g key={fraction}>
            <line x1={px(maxX * fraction)} x2={px(maxX * fraction)} y1={top} y2={H - bottom} className="scan-chart-grid" />
            <text x={px(maxX * fraction)} y={H - bottom + 25} textAnchor="middle">{amount(maxX * fraction, resource)}</text>
          </g>)}
          <text x={left} y={17} className="scan-chart-axis">{chartMetrics[metric]} ↑</text>
          <text x={(W + left - right) / 2} y={H - 9} textAnchor="middle" className="scan-chart-axis">{chartResources[resource]} →</text>
          <g className="scan-chart-ideal" aria-label="Preferred area: higher quality with fewer resources. Visual guide, not a threshold.">
            <title>Preferred direction, not a pass/fail threshold</title>
            <rect x={left + 4} y={top + 4} width={(W - left - right) * .24} height={(H - top - bottom) * .22} rx="6" />
            <text x={left + 17} y={top + 27}>Higher quality</text>
            <text x={left + 17} y={top + 47}>{resource === 'cost' ? 'Lower cost' : 'Shorter duration'} ↖</text>
          </g>
          {points.map(point => <circle key={point.scan.id} cx={px(point.x)} cy={py(point.y)} r={active?.scan.id === point.scan.id ? 8 : 6}
            fill={color(point.scan)} className="scan-chart-dot" tabIndex={0} role="button"
            aria-label={`${runName(point.scan)}, ${amount(point.x, resource)}, ${chartMetrics[metric]} ${pct(point.y)}`}
            aria-pressed={selectedId === point.scan.id}
            onMouseEnter={() => setHoveredId(point.scan.id)} onMouseLeave={() => setHoveredId(null)}
            onFocus={() => setHoveredId(point.scan.id)} onBlur={() => setHoveredId(null)}
            onClick={() => setSelectedId(point.scan.id)}
            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedId(point.scan.id); } }}>
            <title>{runName(point.scan)} — {amount(point.x, resource)} · {pct(point.y)}</title>
          </circle>)}
        </svg>
      </div>
      <div className="scan-chart-legend">{scanners.map(scanner => <span key={scanner}><i style={{ background: scannerColor(scanner) }} />{scanner}</span>)}</div>
      <div className="scan-chart-inspector">
        <label>Inspect a run<select className="form-select" value={selected?.scan.id ?? ''} onChange={e => setSelectedId(e.target.value ? Number(e.target.value) : null)}>
          <option value="">Select a point or run…</option>
          {points.map(p => <option key={p.scan.id} value={p.scan.id}>{runName(p.scan)} · {amount(p.x, resource)} · {pct(p.y)}</option>)}
        </select></label>
        <div className="scan-chart-run" aria-live="polite">{active ? <>
          <Link to={`/scans/${active.scan.id}`}>{runName(active.scan)} ↗</Link>
          <strong>{chartMetrics[metric]} {pct(active.y)} · {amount(active.x, resource)}</strong>
          <span className="text-muted">{active.scan.scan_date || 'Date unavailable'} · {active.scan.metrics.pending ?? 0} pending</span>
          <span className="text-muted">{(labelsMap[active.scan.id] || []).map(label => label.name).join(' · ') || 'No labels'}</span>
        </> : <span className="text-muted">Hover to preview; click to select. Use the selector to inspect overlapping runs.</span>}</div>
      </div>
    </> : <div className="scan-chart-empty"><h3>{awaitingReview > 0 && awaitingReview === scans.length ? 'Awaiting review' : 'No runs to plot'}</h3><p>{reviewedMetric ? 'Weighted scores require completed finding and FP impact review, plus an accessible cost or duration.' : 'Try another axis or change the filters. Runs need a score and a recorded cost or duration you can access.'}</p></div>}
    <p className="scan-summary-note">{reviewedMetric
      ? 'Reviewed scans only. Conservative estimates for scans awaiting review are available in scan detail.'
      : metric === 'f05'
      ? 'F₀.₅ favors precision. Pending findings count against the score.'
      : metric === 'weighted_rate' ? 'Weighted detection includes vulnerability and chain impact points.'
        : 'Pending findings are excluded from this score.'} {provisional && 'Scores awaiting finding or FP penalty review are provisional.'}</p>
    <details className="scan-stat-help"><summary>Scoring and comparison limits</summary>
      <p>Weighted F₀.₅ = 1.25 × credited impact / (credited impact + 0.25 × available impact + FP penalties). Weighted precision = credited impact / (credited impact + FP penalties). Credited vulnerability and chain impact is counted once. FP clusters use the maximum reviewer penalty (1/3/9/27). These weighted scores are plotted only after all findings and FP penalties are reviewed. Conservative estimates, with 27-point penalties for pending findings and unreviewed FP clusters, remain available in scan detail.</p>
      <p>F₀.₅ = 1.25 TP / (1.25 TP + 0.25 FN + FP + pending). Precision has four times recall’s weight. As in testbed, pending findings count against this score. FP uses clustered false positives; a benchmark corpus is required.</p>
      <p>Precision = TP/(TP+FP), recall = TP/(TP+FN), and F1 = 2TP/(2TP+FP+FN). These exclude pending findings. Weighted detection is credited impact points divided by available points, including chains.</p>
      <p>Scores use the current benchmark revision. Missing values are omitted, not treated as zero. Points are individual runs and may overlap. Compare the same app version, corpus, and settings; one run cannot establish a reliable performance advantage.</p>
    </details>
  </section>;
}
