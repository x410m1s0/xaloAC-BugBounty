const { compareResponses } = require('./differential');

function createAuthorizationPlugin() {
  return {
    metadata: () => ({ id: 'authorization', name: 'Function-level authorization comparison', category: 'authorization', destructive: false }),
    can_test: async ({ url, authContexts = [] }) => authContexts.length >= 2 && /admin|manage|delete|update|export|billing/i.test(url),
    prepare: async (context) => ({ ...context, contexts: context.authContexts.slice(0, 3) }),
    execute: async ({ request, url, contexts }) => ({ responses: await Promise.all(contexts.map((authContext) => request(url, { authContext }))) }),
    analyze: async ({ responses }) => ({ comparisons: responses.slice(1).map((response) => compareResponses(responses[0], response)) }),
    validate: async (analysis, execution, prepared) => {
      const exposed = execution.responses.slice(1).some((response) => response?.status >= 200 && response?.status < 300 && response?.body);
      return { status: exposed ? 'potential' : 'false-positive', finding: exposed ? { type: 'authorization', title: 'Potential function-level authorization bypass', severity: 'high', asset: prepared.url, detail: 'A lower-privilege context received a successful response from a privileged-looking endpoint.', response: execution.responses[1], reason: 'Compared privileged and lower-privilege authorization contexts.' } : null };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ contexts: prepared.contexts.map((context) => context.name || context.type), responses: execution.responses, comparisons: analysis.comparisons }),
    calculateConfidence: async ({ analysis }) => analysis.comparisons.length ? 'Medium' : 'Low'
  };
}
module.exports = { createAuthorizationPlugin };