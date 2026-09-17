function createCsrfPlugin() {
  return {
    metadata: () => ({ id: 'csrf', name: 'CSRF protection analysis', category: 'csrf', destructive: false }),
    can_test: async ({ method = 'GET', url }) => String(method).toUpperCase() !== 'GET' && Boolean(url),
    prepare: async (context) => context,
    execute: async ({ request, url, method = 'POST' }) => ({ candidate: await request(url, { method, headers: { origin: 'https://xaloac-invalid-origin.test', referer: 'https://xaloac-invalid-origin.test/form' }, body: '' }) }),
    analyze: async ({ candidate }) => ({ status: candidate?.status || null, allowOrigin: candidate?.headers?.['access-control-allow-origin'] || '', body: String(candidate?.body || '') }),
    validate: async (analysis, execution, prepared) => { const cookieAuth = Boolean(prepared.authenticatedCookie); const tokenMissing = !/csrf|xsrf/i.test(analysis.body); const accepted = analysis.status >= 200 && analysis.status < 400; const signal = cookieAuth && tokenMissing && accepted; return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'csrf', title: 'Potential CSRF protection weakness', severity: 'medium', asset: prepared.url, detail: 'A state-changing request with an untrusted Origin was accepted in an authenticated cookie context without an observed CSRF token.', response: execution.candidate, reason: 'GET was excluded; method, cookie context, origin, referer, and token indicators were evaluated.' } : null }; },
    createEvidence: async ({ prepared, execution, analysis }) => ({ method: prepared.method, candidate: execution.candidate, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.status >= 200 && analysis.status < 400 ? 'Medium' : 'Low'
  };
}
module.exports = { createCsrfPlugin };