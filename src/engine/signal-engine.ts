// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Signal Engine (Orchestrator)
// Initializes and coordinates all sub-engines
// ═══════════════════════════════════════════════════════════════

import type { SignalStats, LicenseTier, Campaign } from './signal-types.js';
import { IOCEngine } from './ioc-engine.js';
import { FeedManager } from './feed-manager.js';
import { ActorProfiler } from './actor-profiler.js';
import { StixEngine } from './stix-engine.js';
import { DarkWebMonitor } from './darkweb-monitor.js';
import { EnrichmentEngine } from './enrichment-engine.js';

export class SignalEngine {
  readonly ioc: IOCEngine;
  readonly feeds: FeedManager;
  readonly actors: ActorProfiler;
  readonly stix: StixEngine;
  readonly darkweb: DarkWebMonitor;
  readonly enrichment: EnrichmentEngine;

  private _campaigns = new Map<string, Campaign>();
  private licenseTier: LicenseTier = 'advanced'; // demo default

  constructor() {
    this.ioc = new IOCEngine();
    this.feeds = new FeedManager(this.ioc);
    this.actors = new ActorProfiler();
    this.stix = new StixEngine();
    this.darkweb = new DarkWebMonitor();
    this.enrichment = new EnrichmentEngine(this.ioc, this.actors);
  }

  // ── Campaign Management ──

  addCampaign(campaign: Campaign): void {
    this._campaigns.set(campaign.campaign_id, campaign);
    this.enrichment.setCampaigns(this._campaigns);
  }

  getCampaign(campaignId: string): Campaign | undefined {
    return this._campaigns.get(campaignId);
  }

  updateCampaign(campaignId: string, updates: Partial<Campaign>): Campaign | null {
    const campaign = this._campaigns.get(campaignId);
    if (!campaign) return null;
    Object.assign(campaign, updates);
    return campaign;
  }

  listCampaigns(): Campaign[] {
    return Array.from(this._campaigns.values());
  }

  getCampaignTimeline(campaignId: string): Campaign['timeline'] {
    return this._campaigns.get(campaignId)?.timeline ?? [];
  }

  // ── License ──

  setLicenseTier(tier: LicenseTier): void {
    this.licenseTier = tier;
  }

  getLicenseTier(): LicenseTier {
    return this.licenseTier;
  }

  isFeatureAvailable(feature: 'actors' | 'campaigns' | 'stix' | 'darkweb' | 'enrichment_full'): boolean {
    switch (feature) {
      case 'actors':
      case 'campaigns':
        return this.licenseTier === 'standard' || this.licenseTier === 'advanced';
      case 'stix':
      case 'darkweb':
      case 'enrichment_full':
        return this.licenseTier === 'advanced';
    }
  }

  // ── Stats ──

  getStats(): SignalStats {
    return {
      total_iocs: this.ioc.size,
      active_iocs: this.ioc.activeCount,
      feeds_active: this.feeds.activeFeeds,
      feeds_error: this.feeds.errorFeeds,
      ioc_hits_24h: this.enrichment.hits24h,
      actors_tracked: this.actors.count,
      active_campaigns: Array.from(this._campaigns.values()).filter(c => c.status === 'active').length,
      darkweb_mentions_7d: this.darkweb.recentMentions(7).length,
      enriched_alerts_24h: this.enrichment.alertCount,
      stix_objects_shared: this.stix.totalObjects,
      avg_match_latency_ms: this.enrichment.avgLatencyMs,
      bloom_filter_size_mb: this.ioc.bloomSizeMB,
    };
  }

  // ── Lifecycle ──

  start(): void {
    this.feeds.startPolling();
  }

  stop(): void {
    this.feeds.stopPolling();
  }
}
