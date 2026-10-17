import { scanQuality } from './scanStatistics.js';

export const chartMetrics = {
  weighted_f05: 'Weighted F₀.₅',
  f05: 'F₀.₅ (conservative)',
  weighted_rate: 'Weighted detection',
  weighted_precision: 'Weighted precision',
  precision: 'Precision',
  recall: 'Recall',
  f1: 'F1',
};
export const chartResources = { cost: 'Cost (USD)', duration: 'Duration (minutes)' };

export function conservativeF05(scan) {
  const { tp, fp_groups: fp, fn, pending } = scan.metrics || {};
  if (![tp, fp, fn, pending].every(value => Number.isFinite(value) && value >= 0) || tp + fn === 0) return null;
  return 1.25 * tp / (1.25 * tp + 0.25 * fn + fp + pending);
}

export function chartRuns(scans, resource, metric) {
  const points = [];
  let missingResource = 0;
  let missingScore = 0;
  for (const scan of scans) {
    const rawX = scan[resource];
    const y = metric === 'f05' ? conservativeF05(scan) : scan.metrics ? scanQuality(scan)[metric] : null;
    const validX = Number.isFinite(rawX) && rawX >= 0;
    const validY = Number.isFinite(y) && y >= 0 && y <= 1;
    if (!validX) missingResource++;
    if (!validY) missingScore++;
    if (validX && validY) points.push({ scan, x: resource === 'duration' ? rawX / 60 : rawX, y });
  }
  return { points, missingResource, missingScore, excluded: scans.length - points.length };
}

export function scannerColor(name) {
  let hash = 0;
  for (const character of name || 'Unknown scanner') hash = ((hash * 31) + character.codePointAt(0)) >>> 0;
  return `hsl(${hash % 360} 75% 65%)`;
}

export function formatChartResource(value, resource) {
  const number = value.toLocaleString(undefined, { maximumSignificantDigits: 6 });
  return resource === 'cost' ? `$${number}` : `${number} min`;
}
