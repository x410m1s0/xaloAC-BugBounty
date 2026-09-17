function decodePart(value) { try { return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { return null; } }
function createJwtPlugin() {
  return {
    metadata: () => ({ id: 'jwt', name: 'JWT structural analysis', category: 'jwt', destructive: false }),
    can_test: async ({ jwt }) => typeof jwt === 'string' && jwt.split('.').length === 3,
    prepare: async (context) => ({ ...context, header: decodePart(context.jwt.split('.')[0]), claims: decodePart(context.jwt.split('.')[1]) }),
    execute: async ({ header, claims }) => ({ header, claims }),
    analyze: async ({ header, claims }) => ({ algorithm: header?.alg || null, missingExpiry: !claims?.exp, issuer: claims?.iss || null, audience: claims?.aud || null, tokenExposure: true }),
    validate: async (analysis, execution, prepared) => { const weakAlgorithm = !analysis.algorithm || /^none$/i.test(analysis.algorithm); const missingExpiry = analysis.missingExpiry; const signal = weakAlgorithm || missingExpiry; return { status: signal ? 'potential' : 'false-positive', finding: signal ? { type: 'jwt', title: 'JWT configuration weakness', severity: weakAlgorithm ? 'high' : 'medium', asset: prepared.url || 'JWT context', detail: `JWT structure was parsed safely. ${weakAlgorithm ? 'Weak or missing algorithm.' : 'Expiry claim is missing.'} Signature cracking was not attempted.`, response: execution, reason: 'Structural JWT analysis identified a configuration signal.' } : null }; },
    createEvidence: async ({ prepared, analysis }) => ({ header: prepared.header, claimNames: Object.keys(prepared.claims || {}), token: '[REDACTED]', analysis }),
    calculateConfidence: async ({ analysis }) => analysis.algorithm ? 'Medium' : 'Low'
  };
}
module.exports = { createJwtPlugin };