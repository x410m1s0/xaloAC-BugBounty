function bodyText(response) { return String(response?.body || ''); }

function similarity(left, right) {
  const a = bodyText(left);
  const b = bodyText(right);
  if (a === b) return 1;
  if (!a.length && !b.length) return 1;
  const max = Math.max(a.length, b.length);
  const common = [...new Set(a)].filter((character) => b.includes(character)).length;
  return Math.max(0, Math.min(1, 1 - Math.abs(a.length - b.length) / max * 0.7 - (Math.max(0, 20 - common) / 20) * 0.3));
}

function compareResponses(baseline, candidate) {
  const baselineHeaders = Object.fromEntries(Object.entries(baseline?.headers || {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
  const candidateHeaders = Object.fromEntries(Object.entries(candidate?.headers || {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
  return {
    statusChanged: baseline?.status !== candidate?.status,
    status: { baseline: baseline?.status ?? null, candidate: candidate?.status ?? null },
    bodySimilarity: similarity(baseline, candidate),
    bodyLength: { baseline: bodyText(baseline).length, candidate: bodyText(candidate).length },
    contentTypeChanged: baselineHeaders['content-type'] !== candidateHeaders['content-type'],
    timingDeltaMs: (candidate?.durationMs || 0) - (baseline?.durationMs || 0)
  };
}

module.exports = { compareResponses };