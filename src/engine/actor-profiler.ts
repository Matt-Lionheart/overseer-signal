// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Threat Actor Profiler
// Tracks adversary groups, TTPs, attribution, and campaigns
// ═══════════════════════════════════════════════════════════════

import type { ThreatActor, MitreTTP, Severity } from './signal-types.js';

export class ActorProfiler {
  private actors = new Map<string, ThreatActor>();

  add(actor: ThreatActor): void {
    this.actors.set(actor.actor_id, actor);
  }

  get(actorId: string): ThreatActor | undefined {
    return this.actors.get(actorId);
  }

  update(actorId: string, updates: Partial<ThreatActor>): ThreatActor | null {
    const actor = this.actors.get(actorId);
    if (!actor) return null;
    Object.assign(actor, updates);
    return actor;
  }

  remove(actorId: string): boolean {
    return this.actors.delete(actorId);
  }

  list(): ThreatActor[] {
    return Array.from(this.actors.values());
  }

  // Get all IOC IDs linked to an actor
  getActorIOCs(actorId: string): string[] {
    return this.actors.get(actorId)?.associated_iocs ?? [];
  }

  // Get actor activity timeline (campaigns + TTPs sorted by date)
  getTimeline(actorId: string): { date: string; event: string; detail: string }[] {
    const actor = this.actors.get(actorId);
    if (!actor) return [];

    const events: { date: string; event: string; detail: string }[] = [
      { date: actor.first_observed, event: 'First observed', detail: `${actor.name} first tracked` },
    ];

    for (const ttp of actor.ttps) {
      events.push({
        date: actor.last_activity,
        event: 'TTP observed',
        detail: `${ttp.technique_id} — ${ttp.technique_name}: ${ttp.usage_description}`,
      });
    }

    events.push({ date: actor.last_activity, event: 'Last activity', detail: `Most recent activity recorded` });

    return events.sort((a, b) => a.date.localeCompare(b.date));
  }

  // Link an IOC to an actor
  linkIOC(actorId: string, iocId: string): boolean {
    const actor = this.actors.get(actorId);
    if (!actor) return false;
    if (!actor.associated_iocs.includes(iocId)) {
      actor.associated_iocs.push(iocId);
    }
    return true;
  }

  // Link a campaign to an actor
  linkCampaign(actorId: string, campaignId: string): boolean {
    const actor = this.actors.get(actorId);
    if (!actor) return false;
    if (!actor.associated_campaigns.includes(campaignId)) {
      actor.associated_campaigns.push(campaignId);
    }
    return true;
  }

  // MITRE ATT&CK TTP heatmap: tactic → technique count
  getTTPHeatmap(actorId: string): Map<string, number> {
    const actor = this.actors.get(actorId);
    if (!actor) return new Map();
    const heatmap = new Map<string, number>();
    for (const ttp of actor.ttps) {
      heatmap.set(ttp.tactic_name, (heatmap.get(ttp.tactic_name) ?? 0) + 1);
    }
    return heatmap;
  }

  // Find actors targeting a specific sector
  findBySector(sector: string): ThreatActor[] {
    return Array.from(this.actors.values()).filter(a =>
      a.targeted_sectors.some(s => s.toLowerCase().includes(sector.toLowerCase()))
    );
  }

  // Find actors by risk level
  findByRisk(level: Severity): ThreatActor[] {
    return Array.from(this.actors.values()).filter(a => a.risk_level === level);
  }

  get count(): number { return this.actors.size; }
}
