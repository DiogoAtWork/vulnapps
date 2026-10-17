import test from 'node:test';
import assert from 'node:assert/strict';
import { conservativeF05, chartRuns, formatChartResource } from './scanChart.js';

const scan = { id: 1, cost: 2, duration: 120, metrics: { tp: 8, fp_groups: 2, fn: 2, pending: 3, weighted_found: 27, weighted_total: 30 } };

test('conservative F0.5 penalizes unresolved items with canonical clustered FP and requires a corpus', () => {
  assert.equal(conservativeF05(scan), 10 / 15.5);
  assert.equal(conservativeF05({ ...scan, metrics: { ...scan.metrics, pending: 0 } }), 10 / 12.5);
  assert.equal(conservativeF05({ metrics: { tp: 0, fp_groups: 0, fn: 5, pending: 0 } }), 0);
  assert.equal(conservativeF05({ metrics: { tp: 0, fp_groups: 1, fn: 0, pending: 0 } }), null);
  assert.equal(conservativeF05({ metrics: { tp: 1, fp_groups: 0, fn: 2 } }), null);
});

test('chart preserves individual runs and zero values, excludes unavailable axes, and converts seconds to minutes', () => {
  const runs = [scan, { ...scan, id: 2, cost: 0 }, { ...scan, id: 3, cost: null }, { ...scan, id: 4, metrics: null }, { ...scan, id: 5, cost: -1, metrics: null }];
  const result = chartRuns(runs, 'cost', 'f05');
  assert.deepEqual(result.points.map(p => p.scan.id), [1, 2]);
  assert.equal(result.points[1].x, 0);
  assert.equal(result.excluded, 3);
  assert.equal(result.missingResource, 2);
  assert.equal(result.missingScore, 2);
  assert.equal(chartRuns([scan], 'duration', 'recall').points[0].x, 2);
  assert.equal(chartRuns([scan], 'cost', 'weighted_rate').points[0].y, 0.9);
});

test('short-duration and tiny-cost ticks remain distinct instead of rounding to zero', () => {
  for (const resource of ['cost', 'duration']) {
    const ticks = [0, .005, .01, .015, .02].map(value => formatChartResource(value, resource));
    assert.equal(new Set(ticks).size, 5);
    assert.notEqual(formatChartResource(.000001, resource), formatChartResource(0, resource));
  }
});


test('weighted chart plots only reviewed scores and excludes awaiting or unscored runs', () => {
  const scored = { ...scan, metrics: { ...scan.metrics, weighted_score_provisional: false, weighted_f05: .42, weighted_f05_upper: .9 } };
  const zero = { ...scored, id: 2, metrics: { ...scored.metrics, weighted_f05: 0 } };
  const runs = chartRuns([scored, zero, scan, { ...scored, metrics: { ...scored.metrics, weighted_score_provisional: true } }], 'cost', 'weighted_f05');
  assert.deepEqual(runs.points.map(point => point.y), [.42, 0]);
  assert.equal(runs.missingScore, 2);
});
