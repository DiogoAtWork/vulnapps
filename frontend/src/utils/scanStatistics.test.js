import test from 'node:test';
import assert from 'node:assert/strict';
import { scanStatistics, scanQuality, canonicalScanCounts, metricExtremes, weightedScoreWinner } from './scanStatistics.js';

const summarize = values => scanStatistics(values.map(tp_count => ({ tp_count })), 'tp_count');

test('summarizes observed scan counts with sample standard deviation, retaining zero and excluding missing data', () => {
  assert.deepEqual(summarize([0, 4, 8, null, undefined, NaN, Infinity]), {
    n: 3, mean: 4, std: 4, min: 0, max: 8,
  });
});

test('distinguishes no observations, a single scan, and constant repeated scans', () => {
  assert.deepEqual(summarize([null]), { n: 0, mean: null, std: null, min: null, max: null });
  assert.deepEqual(summarize([7]), { n: 1, mean: 7, std: null, min: 7, max: 7 });
  assert.deepEqual(summarize([7, 7]), { n: 2, mean: 7, std: 0, min: 7, max: 7 });
});

test('computes per-scan quality and excludes undefined denominators rather than manufacturing scores', () => {
  const scan = scanQuality({ tp_count: 3, fp_count: 1, fn_count: 2 });
  assert.equal(scan.precision, 0.75);
  assert.equal(scan.recall, 0.6);
  assert.equal(scan.f1, 2 / 3);
  const empty = scanQuality({ tp_count: 0, fp_count: 0, fn_count: 0 });
  assert.equal(empty.precision, null);
  assert.equal(empty.recall, null);
  assert.equal(empty.f1, null);
  const missing = scanQuality({ tp_count: 0, fp_count: null, fn_count: 4 });
  assert.equal(missing.precision, null);
  assert.equal(missing.recall, 0);
  assert.equal(missing.f1, null);
  const runs = [scanQuality({ tp_count: 1, fp_count: 0, fn_count: 0 }), scanQuality({ tp_count: 1, fp_count: 9, fn_count: 0 })];
  assert.equal(scanStatistics(runs, 'precision').mean, 0.55);
});

test('weighted detection uses canonical impact points, including fractional credit, with no count fallback', () => {
  const scan = scanQuality({ tp_count: 9, fp_count: 0, fn_count: 1,
    metrics: { tp: 1, fp_groups: 1, fn: 3, weighted_found: 13.5, weighted_total: 30 } });
  assert.equal(scan.weighted_rate, 0.45);
  assert.equal(scan.weighted_found, 13.5);
  assert.equal(scan.recall, 0.25);
  assert.equal(scan.precision, 0.5);
  assert.equal(scanQuality({ tp_count: 9, fn_count: 1 }).weighted_rate, null);
  assert.equal(scanQuality({ metrics: { weighted_found: 0, weighted_total: 0 } }).weighted_rate, null);
  assert.equal(scanQuality({ metrics: { weighted_found: 0, weighted_total: 30 } }).weighted_rate, 0);
});

test('Counts and Quality use the same corpus-scoped canonical counts, including drill-down rows', () => {
  const scan = canonicalScanCounts({ tp_count: 1, fn_count: 1, fp_count: 2, pending_count: 3,
    metrics: { tp: 1, fn: 0, fp_groups: 0, pending: 0 } });
  assert.equal(scanQuality(scan).recall, 1);
  assert.equal(scanStatistics([scan], 'fn_count').mean, 0);
  assert.equal(scan.fp_count, 0);
  assert.equal(scan.pending_count, 0);
  const legacy = { tp_count: 1, fn_count: 1 };
  assert.equal(canonicalScanCounts(legacy), legacy);
});

test('best/worst direction follows the metric while corpus size stays neutral', () => {
  const stats = { min: 2, max: 8 };
  for (const field of ['weighted_f05', 'weighted_precision', 'weighted_rate', 'weighted_found', 'precision', 'recall', 'f1', 'tp_count']) {
    assert.deepEqual(metricExtremes(stats, field), [['Best', 8], ['Worst', 2]]);
  }
  for (const field of ['fp_count', 'fn_count', 'pending_count']) {
    assert.deepEqual(metricExtremes(stats, field), [['Best', 2], ['Worst', 8]]);
  }
  assert.deepEqual(metricExtremes(stats, 'weighted_total'), [['Min', 2], ['Max', 8]]);
  assert.deepEqual(metricExtremes({ min: null, max: null }, 'recall'), [['Best', null], ['Worst', null]]);
});


test('weighted headlines require completed review and never substitute estimates or count scores', () => {
  const metrics = { tp: 10, fp_groups: 0, fn: 0, weighted_found: 27, weighted_total: 30,
    weighted_score_provisional: false, weighted_f05: .4, weighted_f05_upper: .9, weighted_precision: .5, weighted_precision_upper: 1 };
  const quality = scanQuality({ metrics });
  assert.equal(quality.weighted_f05, .4);
  assert.equal(quality.weighted_precision, .5);
  assert.equal(scanQuality({ metrics: { ...metrics, weighted_f05: 0 } }).weighted_f05, 0);
  assert.equal(scanQuality({ metrics: { weighted_f05_upper: .9, weighted_precision_upper: 1 } }).weighted_f05, null);
  assert.equal(scanQuality({ metrics: { weighted_f05: 1.1, weighted_precision: NaN } }).weighted_f05, null);
  assert.equal(scanQuality({ tp_count: 10, fp_count: 0, fn_count: 0 }).weighted_precision, null);
});

test('incomplete or unknown review is excluded from headlines and group means', () => {
  const metrics = { weighted_f05: .9, weighted_precision: 1, weighted_found: 27, weighted_total: 30 };
  for (const review of [true, undefined]) {
    const quality = scanQuality({ metrics: { ...metrics, weighted_score_provisional: review } });
    assert.equal(quality.weighted_f05, null);
    assert.equal(quality.weighted_precision, null);
    assert.equal(quality.weighted_rate, .9);
  }
  const scans = [true, false].map(review => scanQuality({ metrics: { ...metrics, weighted_score_provisional: review } }));
  assert.equal(scanStatistics(scans, 'weighted_f05').n, 1);
  assert.equal(scanStatistics(scans, 'weighted_f05').mean, .9);
});

test('comparison crowns a unique reviewed weighted F0.5 winner only when all scores are available', () => {
  const run = score => ({ metrics: { weighted_f05: score, weighted_score_provisional: false } });
  assert.equal(weightedScoreWinner([run(.7), run(.9)]), 1);
  assert.equal(weightedScoreWinner([run(.7), run(.7)]), -1);
  assert.equal(weightedScoreWinner([run(0), run(0)]), -1);
  assert.equal(weightedScoreWinner([run(.7)]), -1);
  assert.equal(weightedScoreWinner([run(.7), { metrics: { weighted_f05: .9, weighted_score_provisional: true } }]), -1);
  assert.equal(weightedScoreWinner([run(.7), { metrics: {} }]), -1);
});
