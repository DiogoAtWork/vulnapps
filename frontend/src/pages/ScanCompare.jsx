import { useState, useEffect, useRef } from 'react';
import { SeverityBreakdown } from '../components/SeverityBreakdown';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LabelBadge } from '../components/LabelBadge';
import { scanQuality, weightedScoreWinner } from '../utils/scanStatistics';

export default function ScanCompare() {
  const { id: appId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [app, setApp] = useState(null);
  const [available, setAvailable] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(true);

  const scanIds = searchParams.get('scans') || '';

  useEffect(() => {
    const qs = scanIds ? `?scans=${scanIds}` : '';
    api.get(`/apps/${appId}/compare${qs}`).then(data => {
      setApp(data.app);
      setAvailable(data.available_scans || []);
      if (data.scanners) setComparison(data);
      setLoading(false);
    });
  }, [appId, scanIds]);

  const toggleScan = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const doCompare = () => {
    setSearchParams({ scans: Array.from(selected).join(',') });
  };

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Compare Scans <span className="text-muted text-sm">{app?.name}{app?.version ? ` v${app.version}` : ''}</span></h1>
        <Link to={`/apps/${appId}`} className="btn btn-outline">Back to App</Link>
      </div>

      {!comparison ? (
        <ScanSelector scans={available} selected={selected} onToggle={toggleScan} onCompare={doCompare} />
      ) : (
        <ComparisonView data={comparison} appId={appId} />
      )}
    </>
  );
}

function ScanSelector({ scans, selected, onToggle, onCompare }) {
  return (
    <div className="card">
      <h3 className="card-title mb-2">Select scans to compare</h3>
      {scans.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead><tr><th style={{ width: 40 }}></th><th>Scanner</th><th>Date</th><th>Submitted by</th></tr></thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id}>
                    <td><input type="checkbox" checked={selected.has(s.id)} onChange={() => onToggle(s.id)} style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }} /></td>
                    <td><strong>{s.scanner_name}</strong></td>
                    <td>{s.scan_date}</td>
                    <td className="text-secondary">{s.submitter_name || s.submitted_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-2">
            <button className="btn btn-primary" onClick={onCompare} disabled={selected.size < 2}>Compare Selected</button>
            <span className="text-muted text-sm" style={{ marginLeft: '0.75rem' }}>{selected.size} selected</span>
          </div>
        </>
      ) : <div className="empty-state"><p>No scans available for this app yet.</p></div>}
    </div>
  );
}

const TIER_ROWS = [
  ['commodity', 'Commodity'],
  ['business_logic', 'Business logic'],
  ['chained', 'Chained'],
];

// Detection Matrix's per-row tier tag. All three tiers are labelled the same
// way — a vuln's tier is worth showing regardless of which one it is, not
// just when it happens to be non-commodity.
const DETECTION_TIER_LABELS = {
  commodity: 'commodity',
  business_logic: 'business logic',
  chained: 'chained',
};

// Reporting guards. Advisory on purpose: comparing an old scan with a new one is
// how you notice ground truth moved, so this view never refuses.
function ReportingGuards({ guards, label, appId }) {
  if (!guards) return null;
  const warnings = [];

  // Gated on cells that are ACTUALLY out of scope, not on revision stamps
  // differing — see _reporting_guards in app/services/scans.py. Stamps drift
  // every time ground truth grows, but a vuln marked as having existed all
  // along (the default) is still in scope for every scan, so nothing reads
  // "n/a" and there is nothing to explain.
  if (guards.out_of_scope_cells > 0) {
    warnings.push(
      `These scans ran against different corpus revisions (${guards.corpus_revisions.join(', ')}), ` +
      `and ${guards.out_of_scope_cells} cell(s) cover ground truth that did not exist yet when a ` +
      `scan ran — those read "n/a" rather than as a miss.`
    );
  }
  if (guards.suppress_precision) {
    warnings.push(
      `${guards.adjudication_incomplete_scans.length} scan(s) are not fully adjudicated, ` +
      `so precision is shown as a range instead of a single value.`
    );
  }

  if (!warnings.length) return null;
  return (
    <div className="alert alert-warning mb-2">
      <strong>{label}</strong>
      <ul style={{ margin: '0.5rem 0 0 1rem', padding: 0 }}>
        {warnings.map((w, i) => <li key={i} className="text-sm">{w}</li>)}
      </ul>
    </div>
  );
}

// Module-scope so both ComparisonView's own table headers and ChainsMatrix
// (a sibling component further down) can share the exact same header cell.
function ScannerHeader({ s, isWinner }) {
  return (
    <>
      {isWinner && (
        <div title="Highest reviewed weighted F₀.₅" style={{ fontSize: '1rem', lineHeight: 1, marginBottom: '0.15rem' }}>🏆</div>
      )}
      <Link to={`/scans/${s.scan.id}`}>{s.scan.scanner_name}</Link>
      {s.scan.scanner_version && <span className="text-muted text-xs"> v{s.scan.scanner_version}</span>}
      <br />
      <span className="text-muted text-xs">{s.short_date}</span>
      {s.labels && s.labels.length > 0 && (
        <div
          className="scan-labels-cell"
          style={{
            justifyContent: 'center',
            marginTop: '0.25rem',
            maxWidth: 240,
            marginLeft: 'auto',
            marginRight: 'auto',
          }}
        >
          {s.labels.map(l => <LabelBadge key={l.id} label={l} />)}
        </div>
      )}
    </>
  );
}

function ComparisonView({ data, appId }) {
  const { scanners, matrix, fp_matrix, guards, label, chains } = data;
  const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const [sevFilter, setSevFilter] = useState(new Set(ALL_SEVERITIES));

  const toggleSev = (sev) => {
    setSevFilter(prev => {
      const next = new Set(prev);
      if (next.has(sev)) { if (next.size > 1) next.delete(sev); }
      else next.add(sev);
      return next;
    });
  };

  const filteredMatrix = matrix.filter(row => sevFilter.has(row.vuln.severity));

  // Unfiltered, the server's numbers are authoritative — they include chains.
  // Under a severity filter we recompute from the matrix, which covers vulns
  // only; the heading says "(filtered)" wherever that is the case.
  const computeMetrics = (scannerIdx) => {
    const m = scanners[scannerIdx].metrics;
    const applicable = filteredMatrix.filter(row => row.applicable[scannerIdx]);
    const tp = applicable.filter(row => row.detections[scannerIdx]).length;
    const fn = applicable.filter(row => !row.detections[scannerIdx]).length;
    const fpGroups = m.fp_groups;
    const pending = m.pending;
    const precisionUpper = (tp + fpGroups) > 0 ? tp / (tp + fpGroups) : 0;
    const precisionLower = (tp + fpGroups + pending) > 0 ? tp / (tp + fpGroups + pending) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const f1 = (precisionUpper + recall) > 0
      ? 2 * precisionUpper * recall / (precisionUpper + recall) : 0;
    const weightedTotal = applicable.reduce((a, row) => a + (row.vuln.impact_weight || 0), 0);
    const weightedFound = applicable.reduce(
      (a, row) => a + (row.vuln.impact_weight || 0) * (row.credits[scannerIdx] || 0), 0);

    // Severity accuracy: of ALL TP rows (detected + in scope), how many had a
    // finding that reported the vuln's ground-truth severity. A finding that
    // reported no severity at all still counts against the scanner here — it
    // gave no usable rating, which is a failure to rate, not a neutral skip.
    // Mirrors app/scoring.py's compute_metrics exactly, just recomputed over
    // the severity-filtered vuln subset.
    const tpRows = applicable.filter(row => row.detections[scannerIdx]);

    // The TP split, by the vuln's ground-truth severity rather than what the
    // scanner called it. Derived from tpRows so it follows the severity filter
    // and always sums to the `tp` shown above it.
    const tpBySeverity = tpRows.reduce((acc, row) => {
      const sev = (row.vuln.severity || '').toLowerCase();
      if (acc[sev] !== undefined) acc[sev] += 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });

    const severityChecked = tpRows.length;
    const severityCorrect = tpRows.filter(
      row => row.severity_reported?.[scannerIdx]?.toLowerCase() === (row.vuln.severity || '').toLowerCase()
    ).length;

    // Per-tier rates, recomputed for the filtered vuln subset — 'commodity'
    // and 'business_logic' are per-vuln fields so this works the same way
    // every other filtered metric above does. 'chained' is deliberately
    // omitted: chains aren't in the matrix at all (it's vulns only), so
    // there is no filtered subset to compute a rate over — showing a
    // leftover unfiltered number here would just be wrong, not "filtered".
    const tiers = {};
    for (const tier of ['commodity', 'business_logic']) {
      const rows = applicable.filter(row => (row.vuln.difficulty_tier || 'commodity') === tier);
      const count = rows.length;
      const found = rows.filter(row => row.detections[scannerIdx]).length;
      const tWeightedTotal = rows.reduce((a, row) => a + (row.vuln.impact_weight || 0), 0);
      const tWeightedFound = rows.reduce(
        (a, row) => a + (row.vuln.impact_weight || 0) * (row.credits[scannerIdx] || 0), 0);
      tiers[tier] = {
        count, found,
        rate: count > 0 ? found / count : 0,
        weighted_total: tWeightedTotal,
        weighted_found: Math.round(tWeightedFound * 100) / 100,
        weighted_rate: tWeightedTotal > 0 ? tWeightedFound / tWeightedTotal : 0,
      };
    }

    return {
      tp, fn, fp: m.fp, fp_groups: fpGroups, pending,
      precision_lower: precisionLower, precision_upper: precisionUpper, recall, f1,
      adjudication_complete: m.adjudication_complete,
      weighted_found: Math.round(weightedFound * 100) / 100,
      weighted_total: weightedTotal,
      weighted_rate: weightedTotal > 0 ? weightedFound / weightedTotal : 0,
      severity_checked: severityChecked,
      severity_correct: severityCorrect,
      severity_accuracy: severityChecked > 0 ? severityCorrect / severityChecked : 0,
      tp_by_severity: tpBySeverity,
      tiers,
    };
  };

  // Best-effort alignment of the radar panels below with these table
  // columns: measure each scanner <th>'s actual rendered width (and the
  // sticky label column's), re-measuring on resize/reflow. Null until
  // measured or when the table hasn't rendered scanner columns yet.
  const metricsHeaderRef = useRef(null);
  const [colWidths, setColWidths] = useState(null);
  useEffect(() => {
    const row = metricsHeaderRef.current;
    if (!row) return;
    const measure = () => {
      const ths = Array.from(row.querySelectorAll('th'));
      if (ths.length < 2) { setColWidths(null); return; }
      setColWidths({
        label: ths[0].getBoundingClientRect().width,
        cols: ths.slice(1).map(th => th.getBoundingClientRect().width),
      });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(row);
    return () => ro.disconnect();
  }, [scanners.length]);

  const isSevFiltered = sevFilter.size < ALL_SEVERITIES.length;
  const filteredMetrics = scanners.map((s, i) => isSevFiltered ? computeMetrics(i) : s.metrics);
  const filteredVulnCount = filteredMatrix.length;
  const isFiltered = isSevFiltered;

  const winnerIdx = isFiltered ? -1 : weightedScoreWinner(scanners.map(s => ({ metrics: s.metrics })));

  const pctColor = v => v >= 0.7 ? 'text-success' : v >= 0.4 ? 'text-warning' : 'text-error';

  const METRIC_TOOLTIPS = {
    tp: 'Known vulnerabilities detected by the scanner (unique matched vulns)',
    fp_groups: 'Distinct false-positive clusters. Findings sharing an fp_group count once, so a verbose scanner is not penalised for describing one non-issue three times.',
    fn: 'Known vulnerabilities the scanner failed to detect',
    pending: 'Findings not yet mapped to a known vulnerability',
    precision: 'TP / (TP + FP clusters). Shown as a range while findings are still unadjudicated: the lower bound counts every pending finding as a false positive, the upper bound as a true one.',
    recall: 'TP / (TP + FN) — How many of the known vulnerabilities were found',
    f1: 'Harmonic mean of Precision and Recall — Overall scanner accuracy',
    weighted_f05: 'Reviewed impact-weighted F₀.₅ favors precision. Available after finding adjudication and FP penalty review. Credited impact includes chains; reviewer-assigned FP penalties use 1/3/9/27 points. Clusters take their maximum penalty; unreviewed FPs and pending findings cost 27. Requires the full corpus and cannot be recalculated from the severity-filtered vulnerability matrix.',
    weighted_rate: 'Severity-weighted detection rate: points found / points available on the 1/3/9/27 scale, including chain credit.',
    severity_accuracy: 'Of all true positives, the fraction rated at the same severity as ground truth. A finding that reported no severity at all counts against the scanner too — no rating is still a failure to rate. A miss is bad; a hit rated "low" when it is actually critical is a different kind of bad, and this is the axis that sees it.',
  };

  const MetricLabel = ({ k }) => {
    const names = {
      tp: 'True Positives', fp_groups: 'False Positives', fn: 'False Negatives',
      pending: 'Pending', precision: 'Precision', recall: 'Recall', f1: 'F1 Score',
      weighted_f05: 'Weighted F₀.₅', weighted_rate: 'Weighted detection', severity_accuracy: 'Severity Accuracy',
    };
    const tip = METRIC_TOOLTIPS[k];
    return (
      <>
        {names[k]}
        {tip && (
          <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>
            ⓘ
            <span className="tooltip-text">{tip}</span>
          </span>
        )}
      </>
    );
  };

  const WINNER_BG = 'rgba(249, 115, 22, 0.08)';
  const winnerStyle = (i) => (i === winnerIdx ? { background: WINNER_BG } : undefined);

  return (
    <>
      <ReportingGuards guards={guards} label={label} appId={appId} />

      <div className="flex gap-1 items-center mb-2" style={{ flexWrap: 'wrap' }}>
        <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>Severity:</span>
        {ALL_SEVERITIES.map(sev => (
          <button key={sev} onClick={() => toggleSev(sev)}
            className={`badge badge-${sev}`}
            style={{ cursor: 'pointer', opacity: sevFilter.has(sev) ? 1 : 0.3, transition: 'opacity 0.15s' }}>
            {sev}
          </button>
        ))}
        {isFiltered && <span className="text-muted text-xs" style={{ marginLeft: '0.25rem' }}>({filteredVulnCount} of {matrix.length} vulns)</span>}
      </div>

      <div className="card mb-2">
        <h3 className="card-title mb-2">
          Metrics Comparison{isFiltered ? <span className="text-muted text-sm"> (filtered — vulns only, chains excluded)</span> : ''}
          <span className="text-muted text-sm font-mono" style={{ marginLeft: 8 }}>{label}</span>
        </h3>
        <div className="compare-scroll">
          <table>
            <thead>
              <tr ref={metricsHeaderRef}>
                <th className="sticky-col">Metric</th>
                {scanners.map((s, i) => (
                  <th
                    key={s.scan.id}
                    className="text-center"
                    style={winnerStyle(i)}
                  >
                    <ScannerHeader s={s} isWinner={i === winnerIdx} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="detail-label sticky-col"><MetricLabel k="weighted_f05" /></td>
                {scanners.map(s => {
                  const score = isFiltered ? null : scanQuality({ metrics: s.metrics }).weighted_f05;
                  return <td key={s.scan.id} className={`text-center font-mono ${score === null ? 'text-muted' : pctColor(score)}`}>
                    {!isFiltered && s.metrics.weighted_score_provisional !== false ? 'Awaiting review' : score === null ? '—' : `${(score * 100).toFixed(1)}%`}
                    {isFiltered ? <div className="text-muted text-xs">Requires full corpus</div> : null}
                  </td>;
                })}
              </tr>
              <tr>
                <td className="detail-label sticky-col"><MetricLabel k="weighted_rate" /></td>
                {filteredMetrics.map((m, i) => {
                  const baseStyle = winnerStyle(i);
                  const style = baseStyle;
                  return (
                    <td key={scanners[i].scan.id} className={`text-center font-mono ${pctColor(m.weighted_rate)}`} style={style}>
                      {(m.weighted_rate * 100).toFixed(1)}%
                      <div className="text-muted text-xs">{m.weighted_found}/{m.weighted_total} pts</div>
                    </td>
                  );
                })}
              </tr>
              {['tp', 'fp_groups', 'fn', 'pending'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => (
                    <td
                      key={scanners[i].scan.id}
                      className={`text-center font-mono ${k === 'tp' ? 'text-success' : k === 'fp_groups' || k === 'fn' ? 'text-error' : 'text-warning'}`}
                      style={winnerStyle(i)}
                    >
                      {m[k]}
                      {k === 'tp' && (
                        <div style={{ marginTop: 2 }}>
                          <SeverityBreakdown counts={m.tp_by_severity} label="true positives"
                            style={{ justifyContent: 'center' }} />
                        </div>
                      )}
                      {k === 'fp_groups' && m.fp !== m.fp_groups && (
                        <div className="text-muted text-xs">{m.fp} findings</div>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
              {/* Precision is a range until adjudication completes, and a range
                  is what gets shown — never the flattering upper bound alone. */}
              <tr>
                <td className="detail-label sticky-col"><MetricLabel k="precision" /></td>
                {filteredMetrics.map((m, i) => (
                  <td key={scanners[i].scan.id}
                      className={`text-center font-mono ${m.adjudication_complete ? pctColor(m.precision_upper) : 'text-warning'}`}
                      style={winnerStyle(i)}>
                    {m.adjudication_complete
                      ? `${(m.precision_upper * 100).toFixed(1)}%`
                      : `${(m.precision_lower * 100).toFixed(1)}–${(m.precision_upper * 100).toFixed(1)}%`}
                    {!m.adjudication_complete && (
                      <div className="text-muted text-xs">{m.pending} pending</div>
                    )}
                  </td>
                ))}
              </tr>
              {['recall', 'f1'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => (
                    <td
                      key={scanners[i].scan.id}
                      className={`text-center font-mono ${pctColor(m[k])}`}
                      style={winnerStyle(i)}
                    >
                      {(m[k] * 100).toFixed(1)}%
                    </td>
                  ))}
                </tr>
              ))}
              <tr>
                <td className="detail-label sticky-col"><MetricLabel k="severity_accuracy" /></td>
                {filteredMetrics.map((m, i) => (
                  <td
                    key={scanners[i].scan.id}
                    className={`text-center font-mono ${m.severity_checked > 0 ? pctColor(m.severity_accuracy) : 'text-muted'}`}
                    style={winnerStyle(i)}
                  >
                    {m.severity_checked > 0 ? `${(m.severity_accuracy * 100).toFixed(1)}%` : '-'}
                    {m.severity_checked > 0 && (
                      <div className="text-muted text-xs">{m.severity_correct}/{m.severity_checked}</div>
                    )}
                  </td>
                ))}
              </tr>
              {/* Per-tier detection: where on the difficulty curve each run sits.
                  Commodity/business logic are per-vuln fields, so they're
                  recomputed for the filtered subset same as every other row
                  above. Chained is server-only (chains aren't in the vuln
                  matrix at all) and is hidden under a filter rather than
                  show a stale unfiltered number mislabelled as filtered. */}
              {TIER_ROWS.map(([tier, tierLabel]) => (
                !(isFiltered && tier === 'chained') &&
                filteredMetrics.some(m => m.tiers?.[tier]?.count > 0) && (
                  <tr key={tier}>
                    <td className="detail-label sticky-col" style={{ paddingLeft: '1.25rem' }}>
                      <span className="text-muted text-sm">
                        {tierLabel}
                        {tier === 'chained' && (
                          <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>
                            ⓘ
                            <span className="tooltip-text">
                              Counts registered exploit chains, not a 4th bucket of the vulns
                              above — each chain's own members are already counted once under
                              Commodity/Business logic. See the Chains section below for the
                              full list.
                            </span>
                          </span>
                        )}
                      </span>
                    </td>
                    {filteredMetrics.map((m, i) => {
                      const t = m.tiers?.[tier];
                      return (
                        <td key={scanners[i].scan.id} className="text-center font-mono text-secondary text-sm" style={winnerStyle(i)}>
                          {t && t.count > 0 ? (
                            <>
                              {(t.rate * 100).toFixed(0)}%
                              <span className="text-muted text-xs"> ({t.found}/{t.count})</span>
                            </>
                          ) : '-'}
                        </td>
                      );
                    })}
                  </tr>
                )
              ))}
              {scanners.some(s => s.scan.duration != null) && (
                <tr>
                  <td className="detail-label sticky-col">Duration</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>
                      {s.scan.duration != null ? (s.scan.duration >= 60 ? `${Math.floor(s.scan.duration / 60)}m ${s.scan.duration % 60}s` : `${s.scan.duration}s`) : '-'}
                    </td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.tokens != null) && (
                <tr>
                  <td className="detail-label sticky-col">Tokens</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>{s.scan.tokens != null ? s.scan.tokens.toLocaleString() : '-'}</td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.cost != null) && (
                <tr>
                  <td className="detail-label sticky-col">Cost</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>{s.scan.cost != null ? `$${s.scan.cost.toFixed(4)}` : '-'}</td>
                  ))}
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <TierRadar scanners={scanners} metrics={filteredMetrics} isFiltered={isFiltered} winnerIdx={winnerIdx} label={label} colWidths={colWidths} />

      <div className="card mb-2">
        <h3 className="card-title mb-2">Detection Matrix{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}</h3>
        <div className="compare-scroll">
          <table className="matrix-table">
            <thead>
              <tr>
                <th className="sticky-col" style={{ left: 0, minWidth: 70 }}>ID</th>
                <th className="sticky-col" style={{ left: 70, minWidth: 200 }}>Vulnerability</th>
                <th>Severity</th>
                {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                <th className="text-center">Found</th>
              </tr>
            </thead>
            <tbody>
              {filteredMatrix.map((row, i) => (
                <tr key={i}>
                  <td className="font-mono text-sm sticky-col" style={{ left: 0 }}>{row.vuln.vuln_id}</td>
                  <td className="sticky-col" style={{ left: 70 }}>
                    {row.vuln.title}
                    <span className="text-muted text-xs" style={{ marginLeft: 6 }}>
                      {DETECTION_TIER_LABELS[row.vuln.difficulty_tier] || DETECTION_TIER_LABELS.commodity}
                    </span>
                  </td>
                  <td>
                    <Badge severity={row.vuln.severity} />
                    {row.vuln.impact_weight != null && (
                      <span className="text-muted text-xs font-mono" style={{ marginLeft: 4 }}>
                        {row.vuln.impact_weight}p
                      </span>
                    )}
                  </td>
                  {row.detections.map((d, j) => {
                    // A vuln that postdates the run is not a miss for it.
                    if (!row.applicable[j]) {
                      return (
                        <td key={j} className="text-center text-muted"
                            title="Not in scope for this scan — the flaw did not exist when it ran">
                          n/a
                        </td>
                      );
                    }
                    return (
                      <td key={j} className={`text-center ${d ? 'matrix-hit' : 'matrix-miss'}`}>
                        {d ? '✓' : '✗'}
                      </td>
                    );
                  })}
                  <td className={`text-center font-mono ${row.found_by === row.applicable_count ? 'text-success' : row.found_by === 0 ? 'text-error' : 'text-warning'}`}>
                    {row.found_by}/{row.applicable_count ?? scanners.length}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {!isFiltered && <ChainsMatrix chains={chains} scanners={scanners} matrix={matrix} label={label} />}

      {fp_matrix && fp_matrix.length > 0 && (
        <div className="card">
          <h3 className="card-title mb-2">False Positives</h3>
          <div className="compare-scroll">
            <table className="matrix-table">
              <thead>
                <tr>
                  <th className="sticky-col" style={{ left: 0, minWidth: 120 }}>Type</th>
                  <th>Location</th>
                  <th>Parameter</th>
                  {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                  <th className="text-center">Flagged</th>
                </tr>
              </thead>
              <tbody>
                {fp_matrix.map((row, i) => (
                  <tr key={i}>
                    <td className="text-error sticky-col" style={{ left: 0 }}>{row.vuln_type}</td>
                    <td className="font-mono text-sm">{row.location || '-'}</td>
                    <td className="font-mono">{row.parameter || '-'}</td>
                    {row.flagged_by.map((f, j) => (
                      <td key={j} className={`text-center ${f ? 'matrix-hit' : 'matrix-miss'}`}>{f ? '✓' : '✗'}</td>
                    ))}
                    <td className="text-center font-mono text-error">{row.flagged_count}/{scanners.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <TrendChart scanners={scanners} metrics={filteredMetrics} isFiltered={isFiltered} label={label} />

      <div className="mt-2">
        <Link to={`/apps/${appId}/compare`} className="btn btn-outline">Change Selection</Link>
      </div>
    </>
  );
}

// Read-only, cross-scanner view of chain credit — each chain earns its
// weight only once a reviewer explicitly confirms (on the scan's own detail
// page) that its findings demonstrate the chain end to end. Matching every
// member is shown separately from that confirmation on purpose: a scan
// whose findings independently match both members but never connect them is
// exactly the case this distinction exists to catch, and this table is
// where you can see the gap between the two states across every scanner at
// once, without having to open each scan and re-derive it.
function ChainsMatrix({ chains, scanners, matrix, label }) {
  if (!chains || chains.length === 0) return null;

  const vulnById = new Map(matrix.map(row => [row.vuln.id, row.vuln]));

  return (
    <div className="card mb-2">
      <h3 className="card-title mb-2">
        Chains
        <span className="text-muted text-sm font-mono" style={{ marginLeft: 8 }}>{label}</span>
      </h3>
      <div className="compare-scroll">
        <table className="matrix-table">
          <thead>
            <tr>
              <th className="sticky-col" style={{ left: 0, minWidth: 220 }}>Chain</th>
              {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
            </tr>
          </thead>
          <tbody>
            {chains.map(chain => (
              <tr key={chain.id}>
                <td className="sticky-col" style={{ left: 0 }}>
                  <strong>{chain.chain_id}</strong>
                  <div className="text-muted text-xs">{chain.title}</div>
                  <div className="text-muted text-xs">
                    {chain.members.map(vid => vulnById.get(vid)?.vuln_id || `#${vid}`).join(' + ')}
                  </div>
                </td>
                {scanners.map(s => {
                  // A chain either scored its weight or it didn't — there is no
                  // partial/in-between state to show here. "Every member matched
                  // independently" is NOT evidence of a demonstrated chain (see
                  // app/scoring.py) — it can be, and in production has been,
                  // pure coincidence between two unrelated findings. That case
                  // renders identically to any other miss (✗); the title
                  // attribute carries the diagnostic detail for anyone who
                  // wants to dig in, but the visible glyph never implies a
                  // scored outcome that didn't happen. Reviewing/confirming a
                  // real candidate happens on the scan's own detail page.
                  const allMatched = chain.members.every(vid => s.matched_vuln_ids.includes(vid));
                  const credited = s.metrics.credit_by_chain?.[String(chain.id)] === 1;
                  return (
                    <td key={s.scan.id} className="text-center">
                      {credited ? (
                        <span className="text-success" title="Confirmed — demonstrated end to end">✓ confirmed</span>
                      ) : (
                        <span
                          className="text-muted"
                          title={allMatched
                            ? 'Every member matched independently, but nothing demonstrated the chain itself — not credited. Review on the scan detail page.'
                            : undefined}
                        >
                          ✗
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const TREND_METRICS = [
  ['weighted_rate', 'Weighted detection'],
  ['f1', 'F1 Score'],
];

// Metric-vs-date scatter shown below the matrices. Single series (all points are
// scans of this app), so one accent hue + direct labels carry identity — no
// legend, no rank-based coloring. Values come from the severity-filtered
// metrics, so the chart recomputes live with the filter. Honest 0–100% y-axis.
//
// Defaults to weighted detection, with F1 kept
// one click away. The chart carries the app@revision label because scores are
// expected to drift downward as ground truth grows: an unlabelled downward
// trend reads as a regression when it can just as easily be a bigger corpus.
function TrendChart({ scanners, metrics, isFiltered, label }) {
  const [hover, setHover] = useState(null);
  const [metricKey, setMetricKey] = useState('weighted_rate');
  const metricLabel = TREND_METRICS.find(([k]) => k === metricKey)[1];

  const pts = scanners.map((s, i) => {
    const raw = String(s.scan.scan_date || '');
    const t = Date.parse(raw.replace(' ', 'T'));
    return {
      i,
      name: s.scan.scanner_name || 'scan',
      version: s.scan.scanner_version,
      dateLabel: s.short_date || raw,
      t: Number.isFinite(t) ? t : null,
      f1: metrics[i][metricKey],
    };
  });
  if (pts.length < 2) return null;

  const W = 820, H = 340;
  const M = { top: 24, right: 128, bottom: 40, left: 46 };
  const plotW = W - M.left - M.right;
  const plotH = H - M.top - M.bottom;
  const XPAD = 0.06;

  const times = pts.map(p => p.t).filter(v => v != null);
  const tMin = times.length ? Math.min(...times) : 0;
  const tMax = times.length ? Math.max(...times) : 1;
  const tSpan = tMax - tMin;

  const xOf = (p, idx) => {
    let frac;
    if (tSpan > 0 && p.t != null) frac = (p.t - tMin) / tSpan;
    else frac = pts.length > 1 ? idx / (pts.length - 1) : 0.5; // all same/unknown date → even spread
    return M.left + plotW * (XPAD + frac * (1 - 2 * XPAD));
  };
  const yOf = f1 => M.top + plotH * (1 - Math.max(0, Math.min(1, f1)));

  const yTicks = [0, 0.2, 0.4, 0.6, 0.8, 1.0];
  const trunc = n => (n.length > 22 ? n.slice(0, 21) + '…' : n);

  // YY-MM-DD from an epoch-ms (UTC so it matches the stored date string).
  const pad = v => String(v).padStart(2, '0');
  const fmtYMD = ms => {
    const d = new Date(ms);
    return `${pad(d.getUTCFullYear() % 100)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  };

  // X-axis ticks: a handful of evenly-spaced dates across the range (or a
  // single centered date when every scan shares one date).
  const N_TICKS = Math.min(6, Math.max(2, pts.length));
  const xTicks = tSpan > 0
    ? Array.from({ length: N_TICKS }, (_, k) => {
        const ms = tMin + (tSpan * k) / (N_TICKS - 1);
        return { x: M.left + plotW * (XPAD + (k / (N_TICKS - 1)) * (1 - 2 * XPAD)), label: fmtYMD(ms) };
      })
    : [{ x: M.left + plotW / 2, label: pts.find(p => p.t != null) ? fmtYMD(pts.find(p => p.t != null).t) : pts[0].dateLabel }];

  // Least-squares trend line over the plotted points (best fit, not a
  // point-to-point connector). Fit f1 = a + b*x in pixel-x; draw across the
  // plot and clip to the box so an extrapolated end can't escape the axes.
  const xs = pts.map((p, idx) => xOf(p, idx));
  const ys = pts.map(p => p.f1);
  const n = xs.length;
  const sx = xs.reduce((a, v) => a + v, 0);
  const sy = ys.reduce((a, v) => a + v, 0);
  const sxx = xs.reduce((a, v) => a + v * v, 0);
  const sxy = xs.reduce((a, v, i) => a + v * ys[i], 0);
  const denom = n * sxx - sx * sx;
  const b = denom !== 0 ? (n * sxy - sx * sy) / denom : 0;
  const a = (sy - b * sx) / n;
  const yRaw = f1 => M.top + plotH * (1 - f1); // unclamped (trend line is clipped instead)
  const trendX0 = M.left, trendX1 = W - M.right;
  const trendY0 = yRaw(a + b * trendX0), trendY1 = yRaw(a + b * trendX1);

  // Vertical de-collision for the point labels: two labels only clash when
  // their points are close in x (labels sit to the right), so push the later
  // one down until it clears any already-placed label within a label-width.
  const LABEL_W = 132, LABEL_H = 13;
  const labelY = {};
  const placed = [];
  pts.map((p, idx) => ({ idx, x: xOf(p, idx), y: yOf(p.f1) }))
    .sort((q, r) => q.x - r.x || q.y - r.y)
    .forEach(o => {
      let ly = o.y + 3.5;
      let guard = 0;
      while (guard++ < 40 && placed.some(q => Math.abs(q.x - o.x) < LABEL_W && Math.abs(q.ly - ly) < LABEL_H)) ly += LABEL_H;
      if (ly > M.top + plotH - 2) ly = o.y + 3.5 - LABEL_H; // pushed off the bottom → flip above
      placed.push({ x: o.x, ly });
      labelY[o.idx] = ly;
    });

  const ACCENT = 'var(--accent)', GRID = 'var(--border)', MUTED = 'var(--text-muted)';
  const SECN = 'var(--text-secondary)', SURF = 'var(--bg-panel)';
  const clipId = 'f1plot';

  return (
    <div className="card mb-2">
      <div className="flex items-center justify-between mb-2" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
        <h3 className="card-title" style={{ margin: 0 }}>
          {metricLabel} over Time{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}
          <span className="text-muted text-sm font-mono" style={{ marginLeft: 8 }}>{label}</span>
        </h3>
        <div className="flex gap-1">
          {TREND_METRICS.map(([k, name]) => (
            <button key={k} onClick={() => setMetricKey(k)}
              className={`btn btn-sm ${metricKey === k ? 'btn-primary' : 'btn-outline'}`}
              style={{ height: 24, padding: '0 0.5rem', fontSize: '0.7rem' }}>
              {name}
            </button>
          ))}
        </div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: 'block', maxHeight: 380 }}
        role="img" aria-label={`${metricLabel} of each scan plotted against its scan date, with a linear trend line`}>
        <defs>
          <clipPath id={clipId}><rect x={M.left} y={M.top} width={plotW} height={plotH} /></clipPath>
        </defs>
        {yTicks.map(t => {
          const y = yOf(t);
          return (
            <g key={t}>
              <line x1={M.left} y1={y} x2={W - M.right} y2={y} stroke={GRID} strokeWidth="1" />
              <text x={M.left - 8} y={y + 3.5} textAnchor="end" fontSize="11" fill={MUTED}>{Math.round(t * 100)}%</text>
            </g>
          );
        })}
        <line x1={M.left} y1={M.top + plotH} x2={W - M.right} y2={M.top + plotH} stroke={GRID} strokeWidth="1" />

        {/* X-axis ticks + YY-MM-DD labels */}
        {xTicks.map((tk, k) => (
          <g key={k}>
            <line x1={tk.x} y1={M.top + plotH} x2={tk.x} y2={M.top + plotH + 5} stroke={GRID} strokeWidth="1" />
            <text x={tk.x} y={M.top + plotH + 20} textAnchor="middle" fontSize="11" fill={MUTED} className="font-mono">{tk.label}</text>
          </g>
        ))}

        {/* linear trend line (clipped to the plot box) */}
        <line x1={trendX0} y1={trendY0} x2={trendX1} y2={trendY1} clipPath={`url(#${clipId})`}
          stroke={ACCENT} strokeWidth="2" strokeDasharray="6 4" opacity="0.55" />

        {pts.map((p, idx) => {
          const x = xOf(p, idx), y = yOf(p.f1);
          const ly = labelY[idx];
          const offset = Math.abs(ly - (y + 3.5)) > 2;
          return (
            <g key={p.i}>
              {offset && <line x1={x} y1={y} x2={x + 8} y2={ly - 3.5} stroke={GRID} strokeWidth="1" opacity="0.7" />}
              <circle cx={x} cy={y} r={hover === idx ? 7 : 5.5} fill={ACCENT} stroke={SURF} strokeWidth="2"
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHover(idx)} onMouseLeave={() => setHover(null)} />
              <text x={x + 10} y={ly} fontSize="11" fill={SECN}>{trunc(p.name)}</text>
            </g>
          );
        })}

        {hover != null && (() => {
          const p = pts[hover], x = xOf(p, hover), y = yOf(p.f1);
          const label = `${p.name}${p.version ? ' v' + p.version : ''} · ${p.t != null ? fmtYMD(p.t) : p.dateLabel} · ${metricLabel} ${(p.f1 * 100).toFixed(1)}%`;
          const w = Math.min(360, 14 + label.length * 6.1);
          const tx = Math.min(Math.max(x - w / 2, 4), W - w - 4);
          const ty = y - 34 < M.top ? y + 14 : y - 34;
          return (
            <g pointerEvents="none">
              <rect x={tx} y={ty} width={w} height="24" rx="4" fill="var(--bg)" stroke={GRID} strokeWidth="1" />
              <text x={tx + w / 2} y={ty + 16} textAnchor="middle" fontSize="11" fill="var(--text)">{label}</text>
            </g>
          );
        })()}
      </svg>
    </div>
  );
}

// Coverage (tier rate) + quality (precision/recall/F1) on one shape per
// scanner, so a run's shape tells you WHERE it's strong at a glance instead
// of scanning six separate table rows. Small multiples (one polygon per
// panel), not one chart with N overlaid polygons: this page can compare an
// unbounded number of scans, and overlaid same-hue-family polygons stop
// being tellable-apart well before that — each panel's own title already
// carries scanner identity, so no legend/categorical palette is needed.
const RADAR_AXES = [
  ['commodity', 'Commodity', true],
  ['business_logic', 'Business logic', true],
  ['chained', 'Chained', true],
  ['severity_accuracy', 'Severity Accuracy', false],
  ['precision_upper', 'Precision', false],
  ['weighted_rate', 'Weighted detection', false],
];

// The panel's own fixed drawing size (see RadarPanel) plus its card padding
// (1.5rem = 24px each side). A slot narrower than this would either clip the
// panel or force it to shrink — every panel must stay the same visual size
// to be comparable, so the slot is never let get smaller than this, even if
// that means it no longer lines up exactly under a narrower table column.
const MIN_PANEL_SLOT = 268;

function TierRadar({ scanners, metrics, isFiltered, winnerIdx, label, colWidths }) {
  if (metrics.length < 2) return null;

  // Same gating the table above uses: commodity/business logic are
  // per-vuln and get recomputed for a filtered subset upstream, so they
  // stay on the chart under a filter; chained is server-only ground truth
  // with no filtered subset to compute, so it drops out under a filter
  // instead of showing a stale unfiltered rate.
  const axes = RADAR_AXES.filter(([key, , isTier]) => {
    if (!isTier) return true;
    if (isFiltered && key === 'chained') return false;
    return metrics.some(m => (m.tiers?.[key]?.count || 0) > 0);
  });
  if (axes.length < 3) return null;

  const countsFor = (m, key, isTier) => {
    if (isTier) return m.tiers?.[key];
    if (key === 'severity_accuracy') return { found: m.severity_correct, count: m.severity_checked };
    return null;
  };

  // Best-effort alignment with the Metrics Comparison table's scanner
  // columns above (see the ResizeObserver in ComparisonView): when the
  // table's per-scanner column widths are known and there's room, lay panels
  // out in a non-wrapping row at those exact widths, with a leading spacer
  // matching the table's sticky label column — so panel N sits directly
  // under scanner column N. Otherwise fall back to the plain responsive grid.
  const aligned = !!colWidths;

  return (
    <div className="card mb-2">
      <h3 className="card-title mb-2">
        Coverage &amp; Quality Shape{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}
        <span className="text-muted text-sm font-mono" style={{ marginLeft: 8 }}>{label}</span>
      </h3>
      {aligned ? (
        <div className="compare-scroll">
          <div style={{ display: 'flex', gap: 0 }}>
            <div style={{ flex: `0 0 ${colWidths.label}px` }} />
            {scanners.map((s, i) => (
              <div
                key={s.scan.id}
                style={{
                  flex: `0 0 ${Math.max(colWidths.cols[i], MIN_PANEL_SLOT)}px`,
                  minWidth: 0,
                  padding: '0 0.4rem',
                  display: 'flex',
                  justifyContent: 'center',
                }}
              >
                <RadarPanel
                  name={s.scan.scanner_name || 'scan'}
                  version={s.scan.scanner_version}
                  isWinner={i === winnerIdx}
                  axes={axes}
                  values={axes.map(([key, , isTier]) => isTier ? (metrics[i].tiers?.[key]?.rate ?? 0) : (metrics[i][key] ?? 0))}
                  counts={axes.map(([key, , isTier]) => countsFor(metrics[i], key, isTier))}
                />
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="card-grid">
          {scanners.map((s, i) => (
            <RadarPanel
              key={s.scan.id}
              name={s.scan.scanner_name || 'scan'}
              version={s.scan.scanner_version}
              isWinner={i === winnerIdx}
              axes={axes}
              values={axes.map(([key, , isTier]) => isTier ? (metrics[i].tiers?.[key]?.rate ?? 0) : (metrics[i][key] ?? 0))}
              counts={axes.map(([key, , isTier]) => countsFor(metrics[i], key, isTier))}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function RadarPanel({ name, version, isWinner, axes, values, counts }) {
  const [hover, setHover] = useState(null);

  const SIZE = 260;
  const CX = SIZE / 2, CY = SIZE / 2 + 4;
  const R = 68;
  const N = axes.length;
  const LABEL_R = R * 1.42;

  const angleFor = i => -Math.PI / 2 + (i * 2 * Math.PI) / N;
  const pointAt = (i, frac) => {
    const a = angleFor(i);
    return [CX + R * frac * Math.cos(a), CY + R * frac * Math.sin(a)];
  };

  // GRID needs to read clearly against the card's own near-black surface —
  // --border (used for ordinary card outlines) measures under 1.2:1 contrast
  // against --bg-panel, essentially invisible as a chart gridline. --text-muted
  // clears ~3.7:1, still visually recessive (this is the axis-label color too)
  // but the spokes/rings stay legible on every panel, winner or not.
  const GRID = 'var(--text-muted)', MUTED = 'var(--text-muted)', ACCENT = 'var(--accent)';
  const ringLevels = [0.25, 0.5, 0.75, 1];
  const ringPoints = frac => axes.map((_, i) => pointAt(i, frac).join(',')).join(' ');
  const clamped = values.map(v => Math.max(0, Math.min(1, v)));
  const dataPoints = clamped.map((v, i) => pointAt(i, v).join(',')).join(' ');

  // Fixed physical size (not width:100%): every panel must draw at the same
  // size to be visually comparable. The alignment feature above can make a
  // panel's SLOT wider or narrower than another's to match the table column
  // above it, but the panel itself never stretches or shrinks to fill that
  // slot — it just centers within it (margin: auto).
  const RENDER_SIZE = 220;

  return (
    <div className="card" style={isWinner ? { borderColor: 'var(--accent)', borderWidth: '1.5px' } : undefined}>
      <div className="text-center mb-1">
        {isWinner && <span title="Highest reviewed weighted F₀.₅" style={{ marginRight: 4 }}>🏆</span>}
        <span className="font-mono text-sm" style={{ color: 'var(--text)' }}>{name}</span>
        {version && <span className="text-muted text-xs"> v{version}</span>}
      </div>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} width={RENDER_SIZE} height={RENDER_SIZE} style={{ display: 'block', margin: '0 auto' }}
        role="img" aria-label={`${name}: ${axes.map(([, l], i) => `${l} ${Math.round(clamped[i] * 100)}%`).join(', ')}`}>
        {ringLevels.map(f => (
          <polygon key={f} points={ringPoints(f)} fill="none" stroke={GRID} strokeWidth="1" />
        ))}
        {axes.map(([key], i) => {
          const [x, y] = pointAt(i, 1);
          return <line key={key} x1={CX} y1={CY} x2={x} y2={y} stroke={GRID} strokeWidth="1" />;
        })}
        <polygon points={dataPoints} fill={ACCENT} fillOpacity="0.14" stroke={ACCENT} strokeWidth="2" />
        {clamped.map((v, i) => {
          const [x, y] = pointAt(i, v);
          return (
            <circle key={i} cx={x} cy={y} r={hover === i ? 6 : 4} fill={ACCENT}
              stroke="var(--bg-panel)" strokeWidth="1.5" style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
          );
        })}
        {axes.map(([key, label], i) => {
          const a = angleFor(i);
          const [x, y] = pointAt(i, LABEL_R / R);
          const c = Math.cos(a);
          const anchor = Math.abs(c) < 0.2 ? 'middle' : (c > 0 ? 'start' : 'end');
          return <text key={key} x={x} y={y + 3} textAnchor={anchor} fontSize="10" fill={MUTED}>{label}</text>;
        })}
        {hover != null && (() => {
          const [x, y] = pointAt(hover, clamped[hover]);
          const [, axisLabel] = axes[hover];
          const cnt = counts[hover];
          const pctText = `${axisLabel} ${(clamped[hover] * 100).toFixed(0)}%${cnt ? ` (${cnt.found}/${cnt.count})` : ''}`;
          const w = Math.min(SIZE - 8, 16 + pctText.length * 5.6);
          const tx = Math.min(Math.max(x - w / 2, 4), SIZE - w - 4);
          const ty = y < CY ? y - 26 : y + 10;
          return (
            <g pointerEvents="none">
              <rect x={tx} y={ty} width={w} height="20" rx="4" fill="var(--bg)" stroke={GRID} strokeWidth="1" />
              <text x={tx + w / 2} y={ty + 14} textAnchor="middle" fontSize="10.5" fill="var(--text)">{pctText}</text>
            </g>
          );
        })()}
      </svg>
    </div>
  );
}
