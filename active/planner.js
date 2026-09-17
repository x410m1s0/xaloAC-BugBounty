const { hasPlugin } = require('./registry');

function select(selected, name) { if (hasPlugin(name)) selected.add(name); }
function planTests({ endpoint = '', method = 'GET', parameters = [], technologies = [] } = {}) {
  const lowerEndpoint = endpoint.toLowerCase();
  const selected = new Set();
  for (const parameter of parameters) {
    const name = String(parameter.name || '').toLowerCase();
    if (/redirect|next|return|continue|url/.test(name)) select(selected, 'redirect');
    if (/file|path|folder|template/.test(name)) select(selected, /template/.test(name) ? 'ssti' : 'traversal');
    if (/id|user|account|object/.test(name)) select(selected, 'idor');
    if (/query|search|filter|sort|name|value/.test(name)) select(selected, 'sqli');
    if (/url|uri|target|callback|webhook/.test(name)) select(selected, 'ssrf');
    if (parameter.location === 'query' || parameter.location === 'form') select(selected, 'xss');
  }
  if (/graphql/.test(lowerEndpoint) || technologies.some((technology) => /graphql/i.test(technology))) select(selected, 'graphql');
  if (String(method).toUpperCase() !== 'GET') select(selected, 'csrf');
  return [...selected];
}
module.exports = { planTests };