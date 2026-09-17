const { request } = require('../scanner');
const { createActiveContext, runPlugin, findingFromValidation } = require('./engine');
const { createPlugins } = require('./registry');

async function runActiveChecks(options) {
  const context = createActiveContext({ ...options, request: options.request || request });
  const results = [];
  for (const plugin of options.plugins || createPlugins(options.pluginNames)) {
    if (options.signal?.aborted) break;
    const result = await runPlugin(plugin, context);
    const finding = findingFromValidation(result.validation, result.evidence, result.confidence);
    results.push({ ...result, finding });
  }
  return { state: options.signal?.aborted ? 'cancelled' : 'complete', results, findings: results.map((result) => result.finding).filter(Boolean) };
}

module.exports = { runActiveChecks };