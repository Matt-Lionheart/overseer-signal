// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Enrichment Engine
// Matches OSEF events against IOC database, enriches with threat context
// ═══════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto';
import type { IOC, EnrichedAlert, ThreatActor, Campaign } from './signal-types.js';
import type { IOCEngine } from './ioc-engine.js';
import type { ActorProfiler } from './actor-profiler.js';

interface OSEFEvent {
  event_id: string;
  event_type: string;
  pillar: string;
  network?: { source_ip?: string; destination_ip?: string; source_port?: number; destination_port?: number; protocol?: string };
  identity?: { username?: string; email?: string };
  pillar_data?: Record<string, unknown>;
  tags?: string[];
}

export class EnrichmentEngine {
  private iocEngine: IOCEngine;
  private actorProfiler: ActorProfiler;
  private alerts = new Map<string, EnrichedAlert>();
  private matchCount24h = 0;
  private totalLatencyMs = 0;
  private matchOps = 0;

  // Campaigns are passed in for context assembly
  private campaigns = new Map<string, Campaign>();

  constructor(iocEngine: IOCEngine, actorProfiler: ActorProfiler) {
    this.iocEngine = iocEngine;
    this.actorProfiler = actorProfiler;
  }

  setCampaigns(campaigns: Map<string, Campaign>): void {
    this.campaigns = campaigns;
  }

  // Process an OSEF event: extract observables, check against IOCs
  processEvent(event: OSEFEvent): EnrichedAlert | null {
    const start = Date.now();
    const observables = this.extractObservables(event);

    for (const { type, value } of observables) {
      const matched = this.iocEngine.match(type, value);
      if (matched) {
        const alert = this.buildAlert(event, matched);
        this.alerts.set(alert.alert_id, alert);
        this.matchCount24h++;
        this.totalLatencyMs += Date.now() - start;
        this.matchOps++;
        return alert;
      }
    }

    this.totalLatencyMs += Date.now() - start;
    this.matchOps++;
    return null;
  }

  private extractObservables(event: OSEFEvent): Array<{ type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256' | 'email'; value: string }> {
    const observables: Array<{ type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256' | 'email'; value: string }> = [];

    // Network observables
    if (event.network?.source_ip) observables.push({ type: 'ipv4', value: event.network.source_ip });
    if (event.network?.destination_ip) observables.push({ type: 'ipv4', value: event.network.destination_ip });

    // Identity observables
    if (event.identity?.email) observables.push({ type: 'email', value: event.identity.email });

    // Pillar data observables
    if (event.pillar_data) {
      const data = event.pillar_data;
      if (typeof data['url'] === 'string') observables.push({ type: 'url', value: data['url'] });
      if (typeof data['domain'] === 'string') observables.push({ type: 'domain', value: data['domain'] });
      if (typeof data['hostname'] === 'string') observables.push({ type: 'domain', value: data['hostname'] });
      if (typeof data['file_hash'] === 'string') observables.push({ type: 'sha256', value: data['file_hash'] });
      if (typeof data['sha256'] === 'string') observables.push({ type: 'sha256', value: data['sha256'] });
      if (typeof data['email'] === 'string') observables.push({ type: 'email', value: data['email'] });
      if (typeof data['source_ip'] === 'string') observables.push({ type: 'ipv4', value: data['source_ip'] });
      if (typeof data['dest_ip'] === 'string') observables.push({ type: 'ipv4', value: data['dest_ip'] });
    }

    return observables;
  }

  private buildAlert(event: OSEFEvent, matchedIOC: IOC): EnrichedAlert {
    // Assemble threat context from linked actors and campaigns
    const actors: ThreatActor[] = [];
    for (const actorId of matchedIOC.context.actor_ids) {
      const actor = this.actorProfiler.get(actorId);
      if (actor) actors.push(actor);
    }

    const campaigns: Campaign[] = [];
    for (const campId of matchedIOC.context.campaign_ids) {
      const camp = this.campaigns.get(campId);
      if (camp) campaigns.push(camp);
    }

    // Find related IOCs (same actor or campaign)
    const relatedIOCIds = new Set<string>();
    for (const actor of actors) {
      for (const iocId of actor.associated_iocs) {
        if (iocId !== matchedIOC.ioc_id) relatedIOCIds.add(iocId);
      }
    }
    const relatedIOCs: IOC[] = [];
    for (const iocId of relatedIOCIds) {
      const ioc = this.iocEngine.get(iocId);
      if (ioc) relatedIOCs.push(ioc);
      if (relatedIOCs.length >= 10) break; // cap related IOCs
    }

    const killChainPosition = matchedIOC.kill_chain_phases.length > 0
      ? matchedIOC.kill_chain_phases[matchedIOC.kill_chain_phases.length - 1]
      : 'unknown';

    const recommendedActions = this.getRecommendedActions(matchedIOC, actors);

    return {
      alert_id: `alert-${randomUUID().slice(0, 12)}`,
      original_event_id: event.event_id,
      original_event_type: event.event_type,
      matched_ioc: matchedIOC,
      threat_context: {
        actors,
        campaigns,
        related_iocs: relatedIOCs,
        kill_chain_position: killChainPosition,
      },
      match_confidence: matchedIOC.confidence,
      auto_enriched_at: new Date().toISOString(),
      recommended_actions: recommendedActions,
      correlation_id: `corr-${randomUUID().slice(0, 8)}`,
      pillar: event.pillar,
    };
  }

  private getRecommendedActions(ioc: IOC, actors: ThreatActor[]): string[] {
    const actions: string[] = [];

    if (ioc.type === 'ipv4' || ioc.type === 'ipv6' || ioc.type === 'cidr') {
      actions.push('Block IP at network perimeter firewall');
      actions.push('Check for lateral movement from this source');
    }
    if (ioc.type === 'domain' || ioc.type === 'url') {
      actions.push('Add domain to DNS sinkhole / blocklist');
      actions.push('Check proxy logs for historical connections');
    }
    if (ioc.type === 'sha256' || ioc.type === 'md5' || ioc.type === 'sha1') {
      actions.push('Quarantine matching files on endpoints');
      actions.push('Run full endpoint scan on affected hosts');
    }
    if (ioc.type === 'email') {
      actions.push('Block sender in email gateway');
      actions.push('Search mailboxes for prior messages from sender');
    }

    if (actors.length > 0) {
      const actor = actors[0];
      actions.push(`Review ${actor.name} TTP profile for additional indicators`);
      if (actor.actor_type === 'nation-state') {
        actions.push('Escalate to SOC Tier 3 — nation-state threat actor');
      }
    }

    if (ioc.severity === 'critical') {
      actions.push('Initiate incident response procedure');
    }

    return actions;
  }

  // ── Query ──

  getAlert(alertId: string): EnrichedAlert | undefined {
    return this.alerts.get(alertId);
  }

  listAlerts(cursor?: string, limit = 50): { items: EnrichedAlert[]; next_cursor: string | null } {
    const all = Array.from(this.alerts.values())
      .sort((a, b) => b.auto_enriched_at.localeCompare(a.auto_enriched_at));

    let startIdx = 0;
    if (cursor) {
      const idx = all.findIndex(a => a.alert_id === cursor);
      if (idx >= 0) startIdx = idx + 1;
    }

    const page = all.slice(startIdx, startIdx + limit);
    const nextCursor = page.length === limit ? page[page.length - 1].alert_id : null;
    return { items: page, next_cursor: nextCursor };
  }

  getAlertStats(): { total: number; by_pillar: Record<string, number>; by_severity: Record<string, number>; top_ioc_types: Record<string, number> } {
    const byPillar: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const topTypes: Record<string, number> = {};

    for (const alert of this.alerts.values()) {
      byPillar[alert.pillar] = (byPillar[alert.pillar] ?? 0) + 1;
      bySeverity[alert.matched_ioc.severity] = (bySeverity[alert.matched_ioc.severity] ?? 0) + 1;
      topTypes[alert.matched_ioc.type] = (topTypes[alert.matched_ioc.type] ?? 0) + 1;
    }

    return { total: this.alerts.size, by_pillar: byPillar, by_severity: bySeverity, top_ioc_types: topTypes };
  }

  get alertCount(): number { return this.alerts.size; }
  get hits24h(): number { return this.matchCount24h; }
  get avgLatencyMs(): number { return this.matchOps > 0 ? Math.round(this.totalLatencyMs / this.matchOps) : 0; }

  // Add a pre-built alert (for demo seeding)
  addAlert(alert: EnrichedAlert): void {
    this.alerts.set(alert.alert_id, alert);
    this.matchCount24h++;
  }
}
