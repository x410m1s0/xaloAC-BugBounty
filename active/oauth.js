function createOauthPlugin() {
  return {
    metadata: () => ({ id: 'oauth', name: 'OAuth/OIDC configuration analysis', category: 'oauth', destructive: false }),
    can_test: async ({ url }) => /oauth|authorize|openid|oidc|callback/i.test(url),
    prepare: async (context) => { const parsed = new URL(context.url); return { ...context, parameters: Object.fromEntries(parsed.searchParams) }; },
    execute: async ({ parameters }) => ({ parameters }),
    analyze: async ({ parameters }) => ({ hasState: Boolean(parameters.state), hasNonce: Boolean(parameters.nonce), hasPkce: Boolean(parameters.code_challenge), redirectUri: parameters.redirect_uri || null, tokenInUrl: Boolean(parameters.access_token || parameters.id_token || parameters.code) }),
    validate: async (analysis, execution, prepared) => { const signal = analysis.tokenInUrl || (!analysis.hasState && Boolean(analysis.redirectUri)); return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'oauth', title: 'OAuth/OIDC flow configuration signal', severity: analysis.tokenInUrl ? 'high' : 'medium', asset: prepared.url, detail: `${analysis.tokenInUrl ? 'Token or authorization code appears in URL.' : 'Redirect flow lacks an observed state parameter.'} No account takeover flow was attempted.`, response: execution, reason: 'OAuth/OIDC parameters were analyzed without following destructive authorization flows.' } : null }; },
    createEvidence: async ({ prepared, analysis }) => ({ url: prepared.url, parameters: { ...analysis, tokenInUrl: analysis.tokenInUrl } }),
    calculateConfidence: async ({ analysis }) => analysis.tokenInUrl ? 'High' : 'Medium'
  };
}
module.exports = { createOauthPlugin };