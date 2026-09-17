function createOpenRedirectPlugin({ destination = 'https://xaloac-invalid-destination.test/' } = {}) {
  return {
    metadata: () => ({ id: 'open-redirect', name: 'Open redirect signal', category: 'redirect', destructive: false }),
    can_test: async ({ url }) => /redirect|next|return|continue|url/i.test(url),
    prepare: async (context) => {
      const parsed = new URL(context.url);
      const parameter = [...parsed.searchParams.keys()].find((name) => /redirect|next|return|continue|url/i.test(name)) || [...parsed.searchParams.keys()][0];
      const candidate = new URL(parsed); candidate.searchParams.set(parameter, destination);
      return { ...context, parameter, destination, candidateUrl: candidate.toString() };
    },
    execute: async ({ request, candidateUrl }) => ({ candidate: await request(candidateUrl) }),
    analyze: async ({ candidate }) => ({ location: String(candidate?.headers?.location || ''), status: candidate?.status || null }),
    validate: async (analysis, execution, prepared) => {
      const external = (() => { try { return new URL(analysis.location).origin !== new URL(prepared.url).origin; } catch { return false; } })();
      return { status: external ? 'potential' : 'false-positive', finding: external ? { type: 'redirect', title: 'Open redirect signal', severity: 'medium', asset: prepared.url, parameter: prepared.parameter, detail: 'A controlled external destination was returned in the Location header. Follow-up was not performed.', request: { method: 'GET', url: execution.candidate?.url }, response: execution.candidate, reason: 'External Location header observed without following the redirect.' } : null };
    },
    createEvidence: async ({ prepared, execution, analysis }) => ({ parameter: prepared.parameter, destination: prepared.destination, candidate: execution.candidate, analysis }),
    calculateConfidence: async ({ analysis }) => analysis.location ? 'Medium' : 'Low'
  };
}
module.exports = { createOpenRedirectPlugin };