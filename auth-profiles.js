const crypto = require('node:crypto');

class AuthProfileManager {
  constructor() { this.profiles = new Map(); }
  create(input) {
    const type = String(input.type || 'custom').toLowerCase();
    if (!['anonymous', 'user', 'admin', 'custom'].includes(type)) throw new Error('unsupported auth profile type');
    const profile = { id: input.id || crypto.randomUUID(), name: String(input.name || type), type, headers: { ...(input.headers || {}) }, cookies: { ...(input.cookies || {}) }, storageState: input.storageState || null, metadata: input.metadata || {}, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    this.profiles.set(profile.id, profile);
    return this.public(profile);
  }
  get(id) { return this.profiles.get(id) || null; }
  public(profile) { return profile ? { id: profile.id, name: profile.name, type: profile.type, metadata: profile.metadata, createdAt: profile.createdAt, updatedAt: profile.updatedAt } : null; }
  headers(id) {
    const profile = this.get(id);
    if (!profile) throw new Error('auth profile not found');
    const headers = { ...profile.headers };
    if (Object.keys(profile.cookies).length) headers.cookie = Object.entries(profile.cookies).map(([name, value]) => `${name}=${value}`).join('; ');
    return headers;
  }
}

module.exports = { AuthProfileManager };