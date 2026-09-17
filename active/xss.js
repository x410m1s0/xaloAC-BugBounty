const { compareResponses } = require('./differential');
const { findingFromValidation } = require('./engine');

function createReflectedXssPlugin() {
  return {
    metadata: () => ({ id: 'xss-reflected', name: 'Reflected XSS signal', category: 'xss', destructive: false }),
    can_test: async ({ url }) => { try { return [...new URL(url).searchParams.keys()].length > 0; } catch { return false; } },
    prepare: async (context) => {
      const parsed = new URL(context.url);
      const parameter = [...parsed.searchParams.keys()][0];
      const marker = `xaloac-reflect-${Date.now().toString(36)}`;
      const candidateUrl = new URL(parsed);
      candidateUrl.searchParams.set(parameter, marker);
      return { ...context, parameter, marker, candidateUrl: candidateUrl.toString() };
    },
    execute: async ({ request, candidateUrl, ...prepared }) => ({
      prepared,
      baseline: await request(prepared.url),
      candidate: await request(candidateUrl)
    }),
    analyze: async ({ baseline, candidate, prepared }) => ({
      difference: compareResponses(baseline, candidate),
      reflected: String(candidate?.body || '').includes(prepared.marker),
      contentType: String(candidate?.headers?.['content-type'] || '')
    }),
    validate: async (analysis, execution, prepared) => {
      const confirmedReflection = analysis.reflected && /text\/html/i.test(analysis.contentType);
      return {
        status: confirmedReflection ? 'potential' : 'false-positive',
        finding: confirmedReflection ? {
          type: 'xss', title: 'Reflected input observed', severity: 'medium', asset: prepared.url, method: 'GET', parameter: prepared.parameter,
          detail: 'A controlled marker was reflected into an HTML response. Browser sink validation is still required before confirmation.',
          request: { method: 'GET', url: execution.candidate?.url || prepared.candidateUrl }, response: execution.candidate,
          reason: 'Controlled marker reflection was observed; executable browser context was not claimed.'
        } : null
      };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ parameter: prepared.parameter, marker: prepared.marker, baseline: execution.baseline, candidate: execution.candidate, difference: analysis.difference }),
    calculateConfidence: async ({ analysis }) => analysis.reflected && /text\/html/i.test(analysis.contentType) ? 'Medium' : 'Low'
  };
}

module.exports = { createReflectedXssPlugin };