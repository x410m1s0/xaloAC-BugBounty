const { compareResponses } = require('./differential');

function createIdorPlugin() {
  return {
    metadata: () => ({ id: 'idor', name: 'IDOR/BOLA authorization comparison', category: 'authorization', destructive: false }),
    can_test: async ({ url, authContexts = [] }) => authContexts.length >= 2 && /(?:id|user|account|object|resource)/i.test(url),
    prepare: async (context) => ({ ...context, owner: context.authContexts[0], other: context.authContexts[1] }),
    execute: async ({ request, url, owner, other }) => ({ owner: await request(url, { authContext: owner }), other: await request(url, { authContext: other }) }),
    analyze: async ({ owner, other }) => ({ difference: compareResponses(owner, other), sameBody: String(owner?.body || '') === String(other?.body || '') && String(owner?.body || '').length > 0 }),
    validate: async (analysis, execution, prepared) => {
      const signal = analysis.sameBody && execution.other?.status >= 200 && execution.other?.status < 300;
      return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'idor', title: 'Potential IDOR/BOLA authorization bypass', severity: 'high', asset: prepared.url, detail: 'Distinct authorization contexts received the same non-empty resource response.', response: execution.other, reason: 'Cross-context response and resource-body comparison produced a signal.' } : null };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ contexts: [prepared.owner.name || 'owner', prepared.other.name || 'other'], owner: execution.owner, other: execution.other, difference: analysis.difference }),
    calculateConfidence: async ({ analysis }) => analysis.sameBody ? 'High' : 'Low'
  };
}
module.exports = { createIdorPlugin };