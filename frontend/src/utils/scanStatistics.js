export function scanStatistics(scans, field) {
  const values = scans.map(scan => scan[field]).filter(Number.isFinite);
  const n = values.length;
  if (!n) return { n, mean: null, std: null, min: null, max: null };
  const mean = values.reduce((sum, value) => sum + value, 0) / n;
  const std = n > 1
    ? Math.sqrt(values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (n - 1))
    : null;
  return { n, mean, std, min: Math.min(...values), max: Math.max(...values) };
}

export function scanQuality(scan) {
  const metrics = scan.metrics;
  const tp = metrics ? metrics.tp : scan.tp_count;
  const fp = metrics ? metrics.fp_groups : scan.fp_count;
  const fn = metrics ? metrics.fn : scan.fn_count;
  const valid = (...values) => values.every(value => Number.isFinite(value) && value >= 0);
  return {
    ...scan,
    cost_per_point: valid(scan.cost, metrics?.weighted_found) && metrics.weighted_found > 0
      ? scan.cost / metrics.weighted_found : null,
    weighted_f05: metrics?.weighted_score_provisional === false && valid(metrics?.weighted_f05) && metrics.weighted_f05 <= 1 ? metrics.weighted_f05 : null,
    weighted_precision: metrics?.weighted_score_provisional === false && valid(metrics?.weighted_precision) && metrics.weighted_precision <= 1 ? metrics.weighted_precision : null,
    weighted_found: valid(metrics?.weighted_found) ? metrics.weighted_found : null,
    weighted_total: valid(metrics?.weighted_total) ? metrics.weighted_total : null,
    weighted_rate: valid(metrics?.weighted_found, metrics?.weighted_total) && metrics.weighted_total > 0
      ? metrics.weighted_found / metrics.weighted_total : null,
    precision: valid(tp, fp) && tp + fp > 0 ? tp / (tp + fp) : null,
    recall: valid(tp, fn) && tp + fn > 0 ? tp / (tp + fn) : null,
    f1: valid(tp, fp, fn) && 2 * tp + fp + fn > 0 ? 2 * tp / (2 * tp + fp + fn) : null,
  };
}

export function canonicalScanCounts(scan) {
  if (!scan.metrics) return scan;
  // The tp_* split needs no mapping here: when metrics are included the
  // service already replaces those columns with the scorer's own split, so it
  // still sums to the tp_count taken below.
  return {
    ...scan,
    tp_count: scan.metrics.tp,
    fp_count: scan.metrics.fp_groups,
    pending_count: scan.metrics.pending,
    fn_count: scan.metrics.fn,
  };
}

export function metricExtremes(stats, field) {
  if (['fp_count', 'fn_count', 'pending_count'].includes(field)) {
    return [['Best', stats.min], ['Worst', stats.max]];
  }
  if (['weighted_f05', 'weighted_precision', 'weighted_rate', 'weighted_found', 'precision', 'recall', 'f1', 'tp_count'].includes(field)) {
    return [['Best', stats.max], ['Worst', stats.min]];
  }
  return [['Min', stats.min], ['Max', stats.max]];
}

export function weightedScoreWinner(scans) {
  const scores = scans.map(scan => scanQuality(scan).weighted_f05);
  if (scores.length < 2 || scores.some(score => score === null)) return -1;
  const best = Math.max(...scores);
  return best > 0 && scores.filter(score => score === best).length === 1 ? scores.indexOf(best) : -1;
}
