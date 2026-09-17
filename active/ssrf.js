function createSsrfPlugin({ callbackUrl } = {}) {
  return {
    metadata: () => ({ id: 'ssrf', name: 'Controlled SSRF callback validation', category: 'ssrf', destructive: false }),
    can_test: async ({ url }) => Boolean(callbackUrl) && /url|uri|target|callback|webhook|fetch/i.test(url),
    prepare: async (context) => { const parsed = new URL(context.url); const parameter = [...parsed.searchParams.keys()].find((name) => /url|uri|target|callback|webhook|fetch/i.test(name)) || [...parsed.searchParams.keys()][0]; const candidate = new URL(parsed); candidate.searchParams.set(parameter, context.callbackUrl); return { ...context, parameter, candidateUrl: candidate.toString() }; },
    execute: async ({ request, candidateUrl, callbackProbe }) => ({ candidate: await request(candidateUrl), callbackReceived: typeof callbackProbe === 'function' ? await callbackProbe() : false }),
    analyze: async ({ callbackReceived, candidate }) => ({ callbackReceived: callbackReceived === true, responseStatus: candidate?.status || null }),
    validate: async (analysis, execution, prepared) => ({ status: analysis.callbackReceived ? 'validated' : 'false-positive', finding: analysis.callbackReceived ? { type: 'ssrf', title: 'Controlled SSRF callback received', severity: 'high', asset: prepared.url, parameter: prepared.parameter, detail: 'The local validation callback received the server-side request. No internal or third-party destination was contacted.', response: execution.candidate, reason: 'Correlated local callback receipt with the candidate request.' } : null }),
    createEvidence: async ({ prepared, execution, analysis }) => ({ callbackUrl: prepared.callbackUrl, parameter: prepared.parameter, candidate: execution.candidate, validation: analysis }),
    calculateConfidence: async ({ analysis }) => analysis.callbackReceived ? 'High' : 'Low'
  };
}
module.exports = { createSsrfPlugin };