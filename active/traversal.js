const { compareResponses } = require('./differential');

function createPathTraversalPlugin() {
  return {
    metadata: () => ({ id: 'path-traversal', name: 'Path traversal differential signal', category: 'traversal', destructive: false }),
    can_test: async ({ url }) => /file|path|folder|download/i.test(url),
    prepare: async (context) => {
      const parsed = new URL(context.url);
      const parameter = [...parsed.searchParams.keys()].find((name) => /file|path|folder|download/i.test(name)) || [...parsed.searchParams.keys()][0];
      const candidate = new URL(parsed); candidate.searchParams.set(parameter, '../../etc/passwd');
      return { ...context, parameter, candidateUrl: candidate.toString() };
    },
    execute: async ({ request, url, candidateUrl }) => ({ baseline: await request(url), candidate: await request(candidateUrl) }),
    analyze: async ({ baseline, candidate }) => ({ difference: compareResponses(baseline, candidate), marker: /root:x:0:0|\[boot loader\]|etc\/passwd/i.test(candidate?.body || '') }),
    validate: async (analysis, execution, prepared) => {
      const signal = analysis.marker && analysis.difference.bodyLength.candidate !== analysis.difference.bodyLength.baseline;
      return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'traversal', title: 'Path traversal signal', severity: 'high', asset: prepared.url, parameter: prepared.parameter, detail: 'A controlled traversal candidate produced a sensitive file marker and a response difference.', request: { method: 'GET', url: execution.candidate?.url }, response: execution.candidate, reason: 'Sensitive fixture marker and differential response observed.' } : null };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ parameter: prepared.parameter, baseline: execution.baseline, candidate: execution.candidate, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.marker ? 'High' : 'Low'
  };
}
module.exports = { createPathTraversalPlugin };