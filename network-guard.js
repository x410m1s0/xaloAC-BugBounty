const dns = require('node:dns').promises;
const net = require('node:net');
const { ipv4InCidr } = require('./scope');

const PRIVATE_RANGES = ['10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24'];
function isPrivateAddress(address) { if (net.isIP(address) === 4) return PRIVATE_RANGES.some((range) => ipv4InCidr(address, range)); const value = address.toLowerCase(); return value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80:'); }
async function resolveAndGuard(hostname, { labMode = false } = {}) { if (labMode) return { allowed: true, addresses: [hostname], reason: 'lab-mode' }; const addresses = (await dns.lookup(hostname, { all: true })).map((item) => item.address); if (!addresses.length) return { allowed: false, addresses, reason: 'dns-empty' }; const privateAddress = addresses.find((address) => isPrivateAddress(address)); if (privateAddress) return { allowed: false, addresses, reason: `private-address:${privateAddress}` }; return { allowed: true, addresses }; }
module.exports = { isPrivateAddress, resolveAndGuard };
