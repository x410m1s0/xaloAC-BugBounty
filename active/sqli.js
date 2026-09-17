const { compareResponses } = require('./differential');
const { findingFromValidation } = require('./engine');

function createSqlInjectionPlugin() {
  return {
    metadata: () => ({ id: 'sqli-differential', name: 'SQL injection differential signal', category: 'sqli', destructive: false }),
    can_test: async ({ url }) => { try { return [...new URL(url).searchParams.keys()].length > 0; } catch { return false; } },
    prepare: async (context) => {
      const parsed = new URL(context.url);
      const parameter = [...parsed.searchParams.keys()][0];
      const baseline = parsed.searchParams.get(parameter) || '1';
      const trueUrl = new URL(parsed); trueUrl.searchParams.set(parameter, `${baseline}' OR '1'='1`);
      const falseUrl = new URL(parsed); falseUrl.searchParams.set(parameter, `${baseline}' AND '1'='2`);
      return { ...context, parameter, baseline, trueUrl: trueUrl.toString(), falseUrl: falseUrl.toString() };
    },
    execute: async ({ request, url, trueUrl, falseUrl }) => ({ baseline: await request(url), candidateTrue: await request(trueUrl), candidateFalse: await request(falseUrl) }),
    analyze: async ({ baseline, candidateTrue, candidateFalse }) => {
      const errorText = /sql syntax|database error|sqlite error|mysql|postgresql|odbc|unterminated quote/i;
      const trueDiff = compareResponses(baseline, candidateTrue);
      const falseDiff = compareResponses(baseline, candidateFalse);
      return { errorSignal: errorText.test(candidateTrue?.body || '') || errorText.test(candidateFalse?.body || ''), booleanDifferential: trueDiff.bodySimilarity > falseDiff.bodySimilarity + 0.2 || trueDiff.status.candidate !== falseDiff.status.candidate, trueDiff, falseDiff };
    },
    validate: async (analysis, execution, prepared) => {
      const signal = analysis.errorSignal || analysis.booleanDifferential;
      return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'sqli', title: 'SQL injection differential signal', severity: 'high', asset: prepared.url, parameter: prepared.parameter, detail: 'Controlled quote and boolean candidates produced a differential response. Manual/database-specific validation is required.', request: { method: 'GET', url: execution.candidateTrue?.url }, response: execution.candidateTrue, reason: 'More than one controlled candidate was compared against a baseline.' } : null };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ parameter: prepared.parameter, baseline: execution.baseline, candidateTrue: execution.candidateTrue, candidateFalse: execution.candidateFalse, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.errorSignal && analysis.booleanDifferential ? 'High' : analysis.errorSignal || analysis.booleanDifferential ? 'Medium' : 'Low'
  };
}
module.exports = { createSqlInjectionPlugin };