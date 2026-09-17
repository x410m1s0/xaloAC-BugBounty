function createSstiPlugin() {
  return {
    metadata: () => ({ id: 'ssti', name: 'Safe template evaluation check', category: 'ssti', destructive: false }),
    can_test: async ({ url }) => /template|render|view|name/i.test(url),
    prepare: async (context) => { const parsed = new URL(context.url); const parameter = [...parsed.searchParams.keys()].find((name) => /template|name|view/i.test(name)) || [...parsed.searchParams.keys()][0]; const candidate = new URL(parsed); candidate.searchParams.set(parameter, '{{7*7}}'); return { ...context, parameter, candidateUrl: candidate.toString() }; },
    execute: async ({ request, candidateUrl }) => ({ candidate: await request(candidateUrl) }),
    analyze: async ({ candidate }) => ({ evaluated: /(?:^|[^0-9])49(?:[^0-9]|$)/.test(String(candidate?.body || '')), body: String(candidate?.body || '') }),
    validate: async (analysis, execution, prepared) => ({ status: analysis.evaluated ? 'potential' : 'false-positive', finding: analysis.evaluated ? { type: 'ssti', title: 'Template expression evaluation signal', severity: 'high', asset: prepared.url, parameter: prepared.parameter, detail: 'A harmless arithmetic template expression produced its evaluated result. RCE was not attempted.', response: execution.candidate, reason: 'Controlled expression evaluation was observed.' } : null }),
    createEvidence: async ({ prepared, execution, analysis }) => ({ parameter: prepared.parameter, payload: '{{7*7}}', candidate: execution.candidate, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.evaluated ? 'Medium' : 'Low'
  };
}
module.exports = { createSstiPlugin };