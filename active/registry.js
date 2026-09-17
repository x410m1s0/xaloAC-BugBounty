const { createReflectedXssPlugin } = require('./xss');
const { createCorsPlugin } = require('./cors');
const { createSqlInjectionPlugin } = require('./sqli');
const { createOpenRedirectPlugin } = require('./redirect');
const { createPathTraversalPlugin } = require('./traversal');
const { createIdorPlugin } = require('./idor');
const { createAuthorizationPlugin } = require('./authorization');
const { createSsrfPlugin } = require('./ssrf');
const { createCsrfPlugin } = require('./csrf');
const { createSstiPlugin } = require('./ssti');
const { createJwtPlugin } = require('./jwt');
const { createOauthPlugin } = require('./oauth');

const factories = new Map([
  ['xss', createReflectedXssPlugin],
  ['cors', createCorsPlugin],
  ['sqli', createSqlInjectionPlugin],
  ['redirect', createOpenRedirectPlugin],
  ['traversal', createPathTraversalPlugin],
  ['idor', createIdorPlugin],
  ['authorization', createAuthorizationPlugin]
  ,['ssrf', createSsrfPlugin]
  ,['csrf', createCsrfPlugin]
  ,['ssti', createSstiPlugin]
  ,['jwt', createJwtPlugin]
  ,['oauth', createOauthPlugin]
]);

function listPlugins() { return [...factories.keys()]; }
function createPlugins(names = listPlugins()) { return names.map((name) => factories.get(String(name).toLowerCase())?.()).filter(Boolean); }
function hasPlugin(name) { return factories.has(String(name).toLowerCase()); }
function pluginCapabilities() { return Object.fromEntries([...factories].map(([id, factory]) => [id, factory().metadata()])); }
module.exports = { listPlugins, createPlugins, hasPlugin, pluginCapabilities };