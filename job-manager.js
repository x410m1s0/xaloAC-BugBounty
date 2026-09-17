const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { scanSite } = require('./scanner');

class JobManager extends EventEmitter {
  constructor({ maxJobs = 20 } = {}) { super(); this.jobs = new Map(); this.maxJobs = maxJobs; }
  create(input) {
    if (this.jobs.size >= this.maxJobs) throw new Error('job capacity reached');
    const id = crypto.randomUUID();
    const job = { id, state: 'Queued', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), input, result: null, error: null, controller: new AbortController() };
    this.jobs.set(id, job); this.emit('job', job); setImmediate(() => this.run(job)); return job;
  }
  async run(job) {
    if (job.state === 'Cancelled') return;
    job.state = 'Running'; job.updatedAt = new Date().toISOString(); this.emit('job', job);
    try { job.result = await scanSite({ ...job.input, signal: job.controller.signal, onProgress: (progress) => this.emit('progress', { job, progress }) }); if (job.state !== 'Cancelled') job.state = 'Completed'; } catch (error) { if (job.state !== 'Cancelled') { job.error = error.message; job.state = 'Failed'; } }
    job.updatedAt = new Date().toISOString(); this.emit('job', job);
  }
  cancel(id) { const job = this.jobs.get(id); if (!job || ['Completed', 'Failed', 'Cancelled'].includes(job.state)) return false; job.controller.abort(); job.state = 'Cancelled'; job.updatedAt = new Date().toISOString(); this.emit('job', job); return true; }
  get(id) { return this.jobs.get(id) || null; }
  list() { return [...this.jobs.values()].map((job) => ({ ...job, controller: undefined, input: undefined, result: job.result ? { state: job.result.state, stats: job.result.stats, findings: job.result.findings?.length || 0 } : null })); }
}
module.exports = { JobManager };
