function parseOpenApi(document) {
  if (!document || typeof document !== 'object') throw new TypeError('OpenAPI document must be an object');
  const version = document.openapi || (document.swagger ? '2.0' : null);
  if (!version) throw new Error('OpenAPI or Swagger version is missing');
  const endpoints = [];
  for (const [path, definition] of Object.entries(document.paths || {})) {
    for (const [method, operation] of Object.entries(definition || {})) {
      if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) continue;
      endpoints.push({ path, method: method.toUpperCase(), operationId: operation.operationId || null, parameters: [...(definition.parameters || []), ...(operation.parameters || [])].map((parameter) => ({ name: parameter.name, location: parameter.in, required: parameter.required === true, type: parameter.schema?.type || parameter.type || 'unknown' })), requestBody: operation.requestBody || null, responses: Object.keys(operation.responses || {}), security: operation.security || document.security || [] });
    }
  }
  return { version, title: document.info?.title || null, servers: (document.servers || []).map((server) => server.url), endpoints };
}
module.exports = { parseOpenApi };