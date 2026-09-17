const METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 1, L: 0.62, H: 0.27 },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 'U', C: 'C' },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 }
};
function roundUp(value) { return Math.ceil(value * 10) / 10; }
function parseVector(vector) {
  const parts = String(vector).split('/');
  if (parts.shift() !== 'CVSS:3.1') throw new Error('only CVSS:3.1 vectors are supported');
  return Object.fromEntries(parts.map((part) => part.split(/[:=]/)));
}
function calculateCvss31(vector) {
  const metrics = typeof vector === 'string' ? parseVector(vector) : vector;
  for (const name of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) if (metrics[name] === undefined || METRICS[name]?.[metrics[name]] === undefined) throw new Error(`missing or invalid CVSS metric: ${name}`);
  const exploitability = 8.22 * METRICS.AV[metrics.AV] * METRICS.AC[metrics.AC] * (metrics.S === 'U' ? { N: 0.85, L: 0.62, H: 0.27 }[metrics.PR] : { N: 0.85, L: 0.68, H: 0.5 }[metrics.PR]) * METRICS.UI[metrics.UI];
  const isc = 1 - ((1 - METRICS.C[metrics.C]) * (1 - METRICS.I[metrics.I]) * (1 - METRICS.A[metrics.A]));
  const impact = metrics.S === 'U' ? 6.42 * isc : 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc * 0.9731 - 0.02, 13);
  const score = impact <= 0 ? 0 : roundUp(Math.min(impact + exploitability, 10));
  const severity = score === 0 ? 'None' : score < 4 ? 'Low' : score < 7 ? 'Medium' : score < 9 ? 'High' : 'Critical';
  return { version: '3.1', score, severity, vector: typeof vector === 'string' ? vector : `CVSS:3.1/${Object.entries(metrics).map(([key, value]) => `${key}=${value}`).join('/')}` };
}
module.exports = { calculateCvss31, parseVector };