// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Feed Manager
// Manages IOC feed ingestion, polling, parsing, and deduplication
// ═══════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto';
import type { Feed, FeedPollEvent, IOC, FeedFormat, FeedStatus, TLPLevel, IOCType, Severity } from './signal-types.js';
import type { IOCEngine } from './ioc-engine.js';

export class FeedManager {
  private feeds = new Map<string, Feed>();
  private pollHistory = new Map<string, FeedPollEvent[]>(); // feed_id → history
  private pollTimers = new Map<string, ReturnType<typeof setInterval>>();
  private iocEngine: IOCEngine;

  constructor(iocEngine: IOCEngine) {
    this.iocEngine = iocEngine;
  }

  addFeed(feed: Feed): void {
    this.feeds.set(feed.feed_id, feed);
    this.pollHistory.set(feed.feed_id, []);
  }

  updateFeed(feedId: string, updates: Partial<Feed>): Feed | null {
    const feed = this.feeds.get(feedId);
    if (!feed) return null;
    Object.assign(feed, updates);
    return feed;
  }

  removeFeed(feedId: string): boolean {
    const timer = this.pollTimers.get(feedId);
    if (timer) clearInterval(timer);
    this.pollTimers.delete(feedId);
    this.pollHistory.delete(feedId);
    return this.feeds.delete(feedId);
  }

  getFeed(feedId: string): Feed | undefined {
    return this.feeds.get(feedId);
  }

  listFeeds(): Feed[] {
    return Array.from(this.feeds.values());
  }

  getFeedHistory(feedId: string): FeedPollEvent[] {
    return this.pollHistory.get(feedId) ?? [];
  }

  // Trigger immediate poll (in demo mode, generates synthetic IOCs)
  async pollFeed(feedId: string): Promise<FeedPollEvent> {
    const feed = this.feeds.get(feedId);
    if (!feed) throw new Error(`Feed ${feedId} not found`);

    const startTime = Date.now();
    const event: FeedPollEvent = {
      feed_id: feedId,
      polled_at: new Date().toISOString(),
      new_iocs: 0,
      updated_iocs: 0,
      dedup_skipped: 0,
      duration_ms: 0,
      error: null,
    };

    try {
      // In demo mode, generate synthetic IOCs based on feed type
      const newIOCs = this.generateDemoIOCs(feed);
      const result = this.iocEngine.bulkAdd(newIOCs);
      event.new_iocs = result.added;
      event.updated_iocs = result.merged;
      event.dedup_skipped = result.merged;

      feed.ioc_count += result.added;
      feed.dedup_count += result.merged;
      feed.last_poll_at = event.polled_at;
      feed.status = 'active';
      feed.last_error = null;
    } catch (err) {
      feed.error_count++;
      feed.last_error = (err as Error).message;
      feed.status = 'error';
      event.error = (err as Error).message;
    }

    event.duration_ms = Date.now() - startTime;
    const history = this.pollHistory.get(feedId);
    if (history) {
      history.push(event);
      if (history.length > 100) history.shift(); // cap history
    }

    return event;
  }

  // Start automatic polling for all enabled feeds
  startPolling(): void {
    for (const feed of this.feeds.values()) {
      if (feed.enabled && !this.pollTimers.has(feed.feed_id)) {
        const timer = setInterval(() => {
          this.pollFeed(feed.feed_id).catch(() => { /* logged in pollFeed */ });
        }, feed.poll_interval_minutes * 60 * 1000);
        this.pollTimers.set(feed.feed_id, timer);
      }
    }
  }

  stopPolling(): void {
    for (const [id, timer] of this.pollTimers) {
      clearInterval(timer);
    }
    this.pollTimers.clear();
  }

  // Generate synthetic IOCs for demo mode
  private generateDemoIOCs(feed: Feed): IOC[] {
    const iocs: IOC[] = [];
    const count = Math.floor(Math.random() * 5) + 1; // 1-5 new IOCs per poll

    for (let i = 0; i < count; i++) {
      const type = this.randomIOCType();
      iocs.push({
        ioc_id: `ioc-${randomUUID().slice(0, 8)}`,
        type,
        value: this.randomIOCValue(type),
        source_feed_id: feed.feed_id,
        first_seen: new Date(Date.now() - Math.random() * 7 * 86400000).toISOString(),
        last_seen: new Date().toISOString(),
        expiration: new Date(Date.now() + 30 * 86400000).toISOString(),
        confidence: Math.floor(Math.random() * 40) + 60,
        severity: (['critical', 'high', 'medium', 'low'] as Severity[])[Math.floor(Math.random() * 4)],
        status: 'active',
        tlp: feed.tlp_default,
        tags: [feed.provider.toLowerCase().replace(/\s/g, '-')],
        context: { actor_ids: [], campaign_ids: [], malware_families: [], cve_ids: [] },
        stix_id: `indicator--${randomUUID()}`,
        kill_chain_phases: [],
        hit_count: 0,
        last_hit_at: null,
        enrichments: {},
      });
    }

    return iocs;
  }

  private randomIOCType(): IOCType {
    const types: IOCType[] = ['ipv4', 'domain', 'url', 'sha256', 'email'];
    return types[Math.floor(Math.random() * types.length)];
  }

  private randomIOCValue(type: IOCType): string {
    switch (type) {
      case 'ipv4': return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      case 'domain': return `${['malware', 'c2', 'phish', 'evil'][Math.floor(Math.random() * 4)]}-${Math.random().toString(36).slice(2, 8)}.${['xyz', 'top', 'ru', 'cn'][Math.floor(Math.random() * 4)]}`;
      case 'url': return `https://${this.randomIOCValue('domain')}/payload/${Math.random().toString(36).slice(2, 8)}`;
      case 'sha256': return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      case 'email': return `${['admin', 'support', 'billing'][Math.floor(Math.random() * 3)]}@${this.randomIOCValue('domain')}`;
      default: return `unknown-${randomUUID().slice(0, 8)}`;
    }
  }

  get feedCount(): number { return this.feeds.size; }
  get activeFeeds(): number { return Array.from(this.feeds.values()).filter(f => f.status === 'active').length; }
  get errorFeeds(): number { return Array.from(this.feeds.values()).filter(f => f.status === 'error').length; }
}
