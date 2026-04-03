// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — IOC Engine
// Bloom filter for fast negative lookups + hash table for confirmed matches
// ═══════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto';
import type { IOC, IOCType, IOCStatus, Severity, TLPLevel } from './signal-types.js';

// ── Bloom Filter ──
// For 1M IOCs at 0.01% FP rate: ~2.4 MB memory, O(1) lookups

export class BloomFilter {
  private bits: Uint32Array;
  private size: number;
  private hashCount: number;
  private insertCount = 0;

  constructor(expectedItems: number, fpRate = 0.0001) {
    this.size = Math.ceil((-expectedItems * Math.log(fpRate)) / (Math.LN2 * Math.LN2));
    this.hashCount = Math.ceil((this.size / expectedItems) * Math.LN2);
    this.bits = new Uint32Array(Math.ceil(this.size / 32));
  }

  private hashes(value: string): number[] {
    const h1 = parseInt(createHash('sha256').update(value).digest('hex').slice(0, 8), 16);
    const h2 = parseInt(createHash('sha256').update(value + '\x00').digest('hex').slice(0, 8), 16);
    const result: number[] = [];
    for (let i = 0; i < this.hashCount; i++) {
      result.push(Math.abs((h1 + i * h2) % this.size));
    }
    return result;
  }

  add(value: string): void {
    for (const pos of this.hashes(value)) {
      this.bits[Math.floor(pos / 32)] |= 1 << (pos % 32);
    }
    this.insertCount++;
  }

  mightContain(value: string): boolean {
    for (const pos of this.hashes(value)) {
      if ((this.bits[Math.floor(pos / 32)] & (1 << (pos % 32))) === 0) return false;
    }
    return true;
  }

  get count(): number { return this.insertCount; }
  get sizeBytes(): number { return this.bits.byteLength; }
  get sizeMB(): number { return this.bits.byteLength / (1024 * 1024); }

  clear(): void {
    this.bits.fill(0);
    this.insertCount = 0;
  }
}

// ── IOC Engine ──

export class IOCEngine {
  private iocs = new Map<string, IOC>();          // ioc_id → IOC
  private valueIndex = new Map<string, string>();  // normalized(type:value) → ioc_id
  private bloom: BloomFilter;
  private insertsSinceRebuild = 0;
  private readonly rebuildThreshold = 10_000;

  constructor(expectedCapacity = 1_000_000) {
    this.bloom = new BloomFilter(expectedCapacity);
  }

  private normalizeKey(type: IOCType, value: string): string {
    let norm = value.trim().toLowerCase();
    if (type === 'domain') norm = norm.replace(/^www\./, '');
    if (type === 'url') try { norm = new URL(norm).href; } catch { /* keep as-is */ }
    if (type === 'md5' || type === 'sha1' || type === 'sha256') norm = norm.toLowerCase();
    if (type === 'email') norm = norm.toLowerCase();
    return `${type}:${norm}`;
  }

  add(ioc: IOC): boolean {
    const key = this.normalizeKey(ioc.type, ioc.value);
    const existing = this.valueIndex.get(key);
    if (existing) {
      // Merge: update last_seen, take higher confidence, add source
      const ex = this.iocs.get(existing)!;
      ex.last_seen = ioc.last_seen > ex.last_seen ? ioc.last_seen : ex.last_seen;
      ex.confidence = Math.max(ex.confidence, ioc.confidence);
      if (ioc.severity === 'critical' || (ioc.severity === 'high' && ex.severity !== 'critical')) {
        ex.severity = ioc.severity;
      }
      for (const tag of ioc.tags) { if (!ex.tags.includes(tag)) ex.tags.push(tag); }
      for (const aid of ioc.context.actor_ids) { if (!ex.context.actor_ids.includes(aid)) ex.context.actor_ids.push(aid); }
      for (const cid of ioc.context.campaign_ids) { if (!ex.context.campaign_ids.includes(cid)) ex.context.campaign_ids.push(cid); }
      return false; // duplicate merged
    }

    this.iocs.set(ioc.ioc_id, ioc);
    this.valueIndex.set(key, ioc.ioc_id);
    this.bloom.add(key);

    this.insertsSinceRebuild++;
    if (this.insertsSinceRebuild >= this.rebuildThreshold) this.rebuildBloom();

    return true; // new IOC
  }

  remove(iocId: string): boolean {
    const ioc = this.iocs.get(iocId);
    if (!ioc) return false;
    const key = this.normalizeKey(ioc.type, ioc.value);
    this.iocs.delete(iocId);
    this.valueIndex.delete(key);
    // Bloom filter doesn't support removal — will rebuild on next threshold
    return true;
  }

  get(iocId: string): IOC | undefined {
    return this.iocs.get(iocId);
  }

  updateStatus(iocId: string, status: IOCStatus): boolean {
    const ioc = this.iocs.get(iocId);
    if (!ioc) return false;
    ioc.status = status;
    return true;
  }

  // Fast path: bloom filter check, then hash table confirm
  match(type: IOCType, value: string): IOC | null {
    const key = this.normalizeKey(type, value);
    if (!this.bloom.mightContain(key)) return null; // fast negative — ~99.99% of checks end here
    const iocId = this.valueIndex.get(key);
    if (!iocId) return null; // bloom false positive
    const ioc = this.iocs.get(iocId);
    if (!ioc || ioc.status !== 'active') return null;
    ioc.hit_count++;
    ioc.last_hit_at = new Date().toISOString();
    return ioc;
  }

  // Search IOCs by value (partial match for domains/IPs)
  search(query: string, filters?: { type?: IOCType; severity?: Severity; status?: IOCStatus }): IOC[] {
    const q = query.toLowerCase();
    const results: IOC[] = [];
    for (const ioc of this.iocs.values()) {
      if (filters?.type && ioc.type !== filters.type) continue;
      if (filters?.severity && ioc.severity !== filters.severity) continue;
      if (filters?.status && ioc.status !== filters.status) continue;
      if (ioc.value.toLowerCase().includes(q)) results.push(ioc);
    }
    return results;
  }

  // Paginated list
  list(cursor?: string, limit = 50, filters?: { type?: IOCType; severity?: Severity; status?: IOCStatus; feed_id?: string }): { items: IOC[]; next_cursor: string | null } {
    const all = Array.from(this.iocs.values());
    let filtered = all;
    if (filters?.type) filtered = filtered.filter(i => i.type === filters.type);
    if (filters?.severity) filtered = filtered.filter(i => i.severity === filters.severity);
    if (filters?.status) filtered = filtered.filter(i => i.status === filters.status);
    if (filters?.feed_id) filtered = filtered.filter(i => i.source_feed_id === filters.feed_id);

    let startIdx = 0;
    if (cursor) {
      const idx = filtered.findIndex(i => i.ioc_id === cursor);
      if (idx >= 0) startIdx = idx + 1;
    }

    const page = filtered.slice(startIdx, startIdx + limit);
    const nextCursor = page.length === limit ? page[page.length - 1].ioc_id : null;
    return { items: page, next_cursor: nextCursor };
  }

  // Bulk import
  bulkAdd(iocs: IOC[]): { added: number; merged: number } {
    let added = 0, merged = 0;
    for (const ioc of iocs) {
      if (this.add(ioc)) added++; else merged++;
    }
    return { added, merged };
  }

  // Export all active IOCs
  exportAll(format: 'json' | 'csv' = 'json'): string {
    const active = Array.from(this.iocs.values()).filter(i => i.status === 'active');
    if (format === 'csv') {
      const header = 'type,value,severity,confidence,tlp,first_seen,last_seen,tags';
      const rows = active.map(i => `${i.type},${i.value},${i.severity},${i.confidence},${i.tlp},${i.first_seen},${i.last_seen},"${i.tags.join(';')}"`);
      return [header, ...rows].join('\n');
    }
    return JSON.stringify(active, null, 2);
  }

  private rebuildBloom(): void {
    const newBloom = new BloomFilter(Math.max(this.iocs.size * 2, 100_000));
    for (const ioc of this.iocs.values()) {
      newBloom.add(this.normalizeKey(ioc.type, ioc.value));
    }
    this.bloom = newBloom;
    this.insertsSinceRebuild = 0;
  }

  get size(): number { return this.iocs.size; }
  get activeCount(): number { return Array.from(this.iocs.values()).filter(i => i.status === 'active').length; }
  get bloomSizeMB(): number { return this.bloom.sizeMB; }
}
