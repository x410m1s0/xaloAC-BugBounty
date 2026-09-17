function parseGraphqlDocument(source) {
  const text = String(source || '');
  const types = [...text.matchAll(/\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\}/g)].map((match) => ({ name: match[1], fields: [...match[2].matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*([\[\]!A-Za-z0-9_]+)/g)].map((field) => ({ name: field[1], type: field[2] })) }));
  const operations = [...text.matchAll(/\b(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?\s*(?:\(([^)]*)\))?/g)].map((match) => ({ kind: match[1], name: match[2] || null, arguments: [...(match[3] || '').matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\[\]!A-Za-z0-9_]+)/g)].map((argument) => ({ name: argument[1], type: argument[2] })) }));
  return { introspection: !/__schema|__type/.test(text), types, operations };
}
module.exports = { parseGraphqlDocument };
