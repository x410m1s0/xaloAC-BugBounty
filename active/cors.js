const { compareResponses } = require('./differential');

function createCorsPlugin({ origin = 'https://xaloac-invalid-origin.test' } = {}) {
  return {
    metadata: () => ({ id: 'cors-origin-policy', name: 'CORS origin policy', category: 'cors', destructive: false }),
    can_test: async () => true,
    prepare: async (context) => ({ ...context, origin }),
    execute: async ({ request, url, origin: requestOrigin }) => ({
      baseline: await request(url),
      untrusted: await request(url, { headers: { origin: requestOrigin } })
    }),
    analyze: async ({ baseline, untrusted }) => {
      const headers = Object.fromEntries(Object.entries(untrusted?.headers || {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
      return { allowOrigin: headers['access-control-allow-origin'] || '', allowCredentials: headers['access-control-allow-credentials'] || '', difference: compareResponses(baseline, untrusted) };
    },
    validate: async (analysis, execution, prepared) => {
      const reflected = analysis.allowOrigin === prepared.origin;
      const credentialed = reflected && /^true$/i.test(analysis.allowCredentials);
      return {
        status: credentialed ? 'potential' : 'false-positive',
        finding: credentialed ? {
          type: 'cors', title: 'Untrusted origin accepted with credentials', severity: 'high', asset: prepared.url, method: 'GET',
          detail: 'The response reflected an untrusted Origin and enabled credentials. Confirm impact with an authenticated browser context.',
          request: { method: 'GET', url: execution.untrusted?.url, headers: { Origin: prepared.origin } }, response: execution.untrusted,
          reason: 'Untrusted origin reflection and credentialed CORS response observed.'
        } : null
      };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ origin: prepared.origin, baseline: execution.baseline, untrusted: execution.untrusted, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.allowOrigin && analysis.allowCredentials.toLowerCase() === 'true' ? 'High' : 'Low'
  };
}

module.exports = { createCorsPlugin };