// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — STIX 2.1 / TAXII 2.1 Engine
// Converts internal types to/from STIX objects, manages TAXII collections
// ═══════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto';
import type { IOC, ThreatActor, Campaign, StixObject, StixBundle, TaxiiCollection } from './signal-types.js';

export class StixEngine {
  private collections = new Map<string, TaxiiCollection>();
  private collectionObjects = new Map<string, StixObject[]>(); // collection_id → objects

  constructor() {
    // Default collection
    this.createCollection({
      collection_id: 'col-default',
      title: 'OVERSEER Threat Intelligence',
      description: 'Primary threat intelligence collection from S.I.G.N.A.L. platform',
      can_read: true,
      can_write: true,
      media_types: ['application/stix+json;version=2.1'],
      object_count: 0,
      last_updated: new Date().toISOString(),
    });
  }

  // ── STIX Object Conversion ──

  iocToStix(ioc: IOC): StixObject[] {
    const objects: StixObject[] = [];
    const now = new Date().toISOString();

    // Create the SCO (STIX Cyber Observable)
    let scoType: string;
    let scoProps: Record<string, unknown> = {};

    switch (ioc.type) {
      case 'ipv4':
        scoType = 'ipv4-addr';
        scoProps = { value: ioc.value };
        break;
      case 'ipv6':
        scoType = 'ipv6-addr';
        scoProps = { value: ioc.value };
        break;
      case 'domain':
        scoType = 'domain-name';
        scoProps = { value: ioc.value };
        break;
      case 'url':
        scoType = 'url';
        scoProps = { value: ioc.value };
        break;
      case 'md5':
      case 'sha1':
      case 'sha256':
        scoType = 'file';
        scoProps = { hashes: { [ioc.type.toUpperCase()]: ioc.value } };
        break;
      case 'email':
        scoType = 'email-addr';
        scoProps = { value: ioc.value };
        break;
      default:
        scoType = 'artifact';
        scoProps = { payload_bin: ioc.value };
    }

    const scoId = `${scoType}--${randomUUID()}`;
    objects.push({
      id: scoId,
      type: scoType,
      spec_version: '2.1',
      created: ioc.first_seen,
      modified: ioc.last_seen,
      ...scoProps,
    });

    // Create the Indicator SDO
    const pattern = this.buildPattern(ioc);
    objects.push({
      id: ioc.stix_id || `indicator--${randomUUID()}`,
      type: 'indicator',
      spec_version: '2.1',
      created: ioc.first_seen,
      modified: ioc.last_seen,
      name: `${ioc.type.toUpperCase()} IOC: ${ioc.value}`,
      description: `Indicator from feed ${ioc.source_feed_id}. Confidence: ${ioc.confidence}%`,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: ioc.first_seen,
      valid_until: ioc.expiration || undefined,
      confidence: ioc.confidence,
      labels: ioc.tags,
      object_marking_refs: [this.tlpToMarking(ioc.tlp)],
      kill_chain_phases: ioc.kill_chain_phases.map(p => ({
        kill_chain_name: 'mitre-attack',
        phase_name: p,
      })),
    });

    return objects;
  }

  actorToStix(actor: ThreatActor): StixObject {
    return {
      id: actor.stix_id || `threat-actor--${randomUUID()}`,
      type: 'threat-actor',
      spec_version: '2.1',
      created: actor.first_observed,
      modified: actor.last_activity,
      name: actor.name,
      description: actor.description,
      aliases: actor.aliases,
      threat_actor_types: [actor.actor_type === 'nation-state' ? 'nation-state' : actor.actor_type],
      roles: ['agent'],
      sophistication: actor.actor_type === 'nation-state' ? 'expert' : 'intermediate',
      resource_level: actor.actor_type === 'nation-state' ? 'government' : 'organization',
      primary_motivation: actor.actor_type === 'criminal' ? 'personal-gain' : 'ideology',
      goals: actor.targeted_sectors.map(s => `Target ${s} sector`),
      labels: [actor.risk_level, actor.attribution_confidence],
    };
  }

  campaignToStix(campaign: Campaign): StixObject {
    return {
      id: campaign.stix_id || `campaign--${randomUUID()}`,
      type: 'campaign',
      spec_version: '2.1',
      created: campaign.first_activity,
      modified: campaign.last_activity,
      name: campaign.name,
      description: campaign.description,
      first_seen: campaign.first_activity,
      last_seen: campaign.last_activity,
      objective: campaign.kill_chain_phase,
      labels: campaign.targeted_sectors,
    };
  }

  // ── STIX Bundle ──

  createBundle(objects: StixObject[]): StixBundle {
    return {
      type: 'bundle',
      id: `bundle--${randomUUID()}`,
      objects,
    };
  }

  importBundle(bundle: StixBundle, collectionId: string): { imported: number; errors: number } {
    const collection = this.collections.get(collectionId);
    if (!collection) return { imported: 0, errors: 1 };

    const objects = this.collectionObjects.get(collectionId) ?? [];
    let imported = 0;

    for (const obj of bundle.objects) {
      if (obj.type && obj.id && obj.spec_version === '2.1') {
        objects.push(obj);
        imported++;
      }
    }

    this.collectionObjects.set(collectionId, objects);
    collection.object_count = objects.length;
    collection.last_updated = new Date().toISOString();

    return { imported, errors: bundle.objects.length - imported };
  }

  exportBundle(collectionId: string): StixBundle | null {
    const objects = this.collectionObjects.get(collectionId);
    if (!objects) return null;
    return this.createBundle(objects);
  }

  // ── TAXII 2.1 Collections ──

  createCollection(collection: TaxiiCollection): void {
    this.collections.set(collection.collection_id, collection);
    this.collectionObjects.set(collection.collection_id, []);
  }

  getCollection(collectionId: string): TaxiiCollection | undefined {
    return this.collections.get(collectionId);
  }

  listCollections(): TaxiiCollection[] {
    return Array.from(this.collections.values());
  }

  getCollectionObjects(collectionId: string, cursor?: string, limit = 50): { objects: StixObject[]; next_cursor: string | null } {
    const objects = this.collectionObjects.get(collectionId) ?? [];
    let startIdx = 0;
    if (cursor) {
      const idx = objects.findIndex(o => o.id === cursor);
      if (idx >= 0) startIdx = idx + 1;
    }
    const page = objects.slice(startIdx, startIdx + limit);
    const nextCursor = page.length === limit ? page[page.length - 1].id : null;
    return { objects: page, next_cursor: nextCursor };
  }

  addToCollection(collectionId: string, objects: StixObject[]): number {
    const collection = this.collections.get(collectionId);
    if (!collection) return 0;
    const existing = this.collectionObjects.get(collectionId) ?? [];
    existing.push(...objects);
    this.collectionObjects.set(collectionId, existing);
    collection.object_count = existing.length;
    collection.last_updated = new Date().toISOString();
    return objects.length;
  }

  // TAXII 2.1 Discovery response
  getDiscovery(): object {
    return {
      title: 'S.I.G.N.A.L. TAXII Server',
      description: 'OVERSEER Threat Intelligence Platform — TAXII 2.1 API',
      contact: 'security@acellc.ai',
      default: '/signal/taxii/',
      api_roots: ['/signal/taxii/'],
    };
  }

  // ── Helpers ──

  private buildPattern(ioc: IOC): string {
    switch (ioc.type) {
      case 'ipv4': return `[ipv4-addr:value = '${ioc.value}']`;
      case 'ipv6': return `[ipv6-addr:value = '${ioc.value}']`;
      case 'domain': return `[domain-name:value = '${ioc.value}']`;
      case 'url': return `[url:value = '${ioc.value}']`;
      case 'md5': return `[file:hashes.MD5 = '${ioc.value}']`;
      case 'sha1': return `[file:hashes.'SHA-1' = '${ioc.value}']`;
      case 'sha256': return `[file:hashes.'SHA-256' = '${ioc.value}']`;
      case 'email': return `[email-addr:value = '${ioc.value}']`;
      case 'cve': return `[vulnerability:name = '${ioc.value}']`;
      case 'cidr': return `[ipv4-addr:value = '${ioc.value}']`;
      default: return `[artifact:payload_bin = '${ioc.value}']`;
    }
  }

  private tlpToMarking(tlp: string): string {
    const map: Record<string, string> = {
      'TLP:RED': 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
      'TLP:AMBER+STRICT': 'marking-definition--826578e1-40a3-4b46-a8d0-ad56a0667b5a',
      'TLP:AMBER': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
      'TLP:GREEN': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
      'TLP:CLEAR': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    };
    return map[tlp] || map['TLP:CLEAR'];
  }

  get totalObjects(): number {
    let count = 0;
    for (const objects of this.collectionObjects.values()) count += objects.length;
    return count;
  }
}
