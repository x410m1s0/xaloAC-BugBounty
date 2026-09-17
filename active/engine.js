const { validateTarget } = require('../scope');
const { createFinding } = require('../finding');

function lifecyclePlugin(plugin) {
  for (const method of ['metadata', 'can_test', 'prepare', 'execute', 'analyze', 'validate', 'createEvidence', 'calculateConfidence']) {
    if (typeof plugin[method] !== 'function') throw new TypeError(`active plugin missing ${method}()`);
  }
  return plugin;
}

async function runPlugin(plugin, context) {
  const activePlugin = lifecyclePlugin(plugin);
  if (!await activePlugin.can_test(context)) return { state: 'not-tested', plugin: activePlugin.metadata() };
  const prepared = await activePlugin.prepare(context);
  const execution = await activePlugin.execute(prepared);
  const analysis = await activePlugin.analyze(execution, prepared);
  const validation = await activePlugin.validate(analysis, execution, prepared);
  const evidence = await activePlugin.createEvidence({ prepared, execution, analysis, validation });
  const confidence = await activePlugin.calculateConfidence({ prepared, execution, analysis, validation });
  return { state: validation?.status || 'potential', plugin: activePlugin.metadata(), analysis, validation, evidence, confidence, finding: validation?.finding || null };
}

function createActiveContext({ url, scope, exclude = [], request, signal, labMode = false, authContexts = [], callbackProbe, method, authenticatedCookie, jwt }) {
  if (typeof request !== 'function') throw new TypeError('active request function is required');
  const requestInScope = async (target, options = {}) => {
    const check = validateTarget(target, scope, exclude);
    if (!check.allowed) return { ok: false, blocked: true, error: `scope: ${check.reason}`, url: target };
    return request(target, { ...options, signal, labMode });
  };
  return { url, scope, exclude, signal, labMode, authContexts, callbackProbe, method, authenticatedCookie, jwt, request: requestInScope };
}

function findingFromValidation(validation, evidence, confidence) {
  if (!validation?.finding) return null;
  return createFinding({ ...validation.finding, evidence: JSON.stringify(evidence), confidence, source: `active:${validation.finding.type || 'plugin'}` });
}

module.exports = { createActiveContext, runPlugin, findingFromValidation };