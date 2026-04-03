// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — REST API
// 45 endpoints: feeds, IOCs, actors, campaigns, STIX/TAXII, dark web, alerts
// ═══════════════════════════════════════════════════════════════

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { SignalEngine } from '../engine/signal-engine.js';
import { LICENSE_TIERS } from '../engine/signal-types.js';
import type { Feed, IOC, ThreatActor, Campaign, DarkWebMention, WatchlistEntry, StixBundle } from '../engine/signal-types.js';

type RouteHandler = (req: IncomingMessage, res: ServerResponse, params: Record<string, string>) => Promise<void>;

export function createRouter(engine: SignalEngine): (req: IncomingMessage, res: ServerResponse) => void {
  const routes: Array<{ method: string; pattern: RegExp; handler: RouteHandler }> = [];

  function route(method: string, path: string, handler: RouteHandler): void {
    const paramNames: string[] = [];
    const regexStr = path.replace(/:(\w+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    });
    const pattern = new RegExp(`^${regexStr}$`);
    routes.push({
      method,
      pattern,
      handler: async (req, res, params) => {
        // Extract named params
        const match = req.url?.match(pattern);
        if (match) {
          paramNames.forEach((name, i) => { params[name] = match[i + 1]; });
        }
        await handler(req, res, params);
      },
    });
  }

  // ── Helpers ──

  function json(res: ServerResponse, data: unknown, status = 200): void {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(data));
  }

  async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => { body += chunk; if (body.length > 1_048_576) reject(new Error('Body too large')); });
      req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
      req.on('error', reject);
    });
  }

  function getQuery(req: IncomingMessage): URLSearchParams {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    return url.searchParams;
  }

  function tierGate(tier: 'standard' | 'advanced', res: ServerResponse): boolean {
    const current = engine.getLicenseTier();
    const levels = { base: 0, standard: 1, advanced: 2 };
    if (levels[current] < levels[tier]) {
      json(res, { error: `This feature requires ${tier} tier license`, current_tier: current }, 403);
      return false;
    }
    return true;
  }

  // ═══════════════════════════════════════════════════
  // Health & Status (3 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/health', async (_req, res) => {
    json(res, {
      status: 'ok',
      module: 'signal',
      version: '0.1.0',
      iocs: engine.ioc.size,
      feeds: engine.feeds.feedCount,
      actors: engine.actors.count,
      uptime: process.uptime(),
    });
  });

  route('GET', '/signal/license', async (_req, res) => {
    const tier = engine.getLicenseTier();
    const tierConfig = LICENSE_TIERS[tier];
    json(res, {
      sku: `overseer-signal-${tier}`,
      tier,
      status: 'active',
      features: tierConfig.features,
      max_feeds: tierConfig.max_feeds === Infinity ? 'unlimited' : tierConfig.max_feeds,
      days_remaining: 365,
    });
  });

  route('GET', '/signal/stats', async (_req, res) => {
    json(res, engine.getStats());
  });

  // ═══════════════════════════════════════════════════
  // Feeds — base tier (7 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/feeds', async (_req, res) => {
    json(res, engine.feeds.listFeeds());
  });

  route('GET', '/signal/feeds/:feedId', async (_req, res, params) => {
    const feed = engine.feeds.getFeed(params.feedId);
    if (!feed) return json(res, { error: 'Feed not found' }, 404);
    json(res, feed);
  });

  route('POST', '/signal/feeds', async (req, res) => {
    const body = await readBody(req) as unknown as Feed;
    engine.feeds.addFeed(body);
    json(res, body, 201);
  });

  route('PUT', '/signal/feeds/:feedId', async (req, res, params) => {
    const body = await readBody(req);
    const updated = engine.feeds.updateFeed(params.feedId, body as Partial<Feed>);
    if (!updated) return json(res, { error: 'Feed not found' }, 404);
    json(res, updated);
  });

  route('DELETE', '/signal/feeds/:feedId', async (_req, res, params) => {
    if (!engine.feeds.removeFeed(params.feedId)) return json(res, { error: 'Feed not found' }, 404);
    json(res, { deleted: true });
  });

  route('POST', '/signal/feeds/:feedId/poll', async (_req, res, params) => {
    try {
      const event = await engine.feeds.pollFeed(params.feedId);
      json(res, event);
    } catch (err) {
      json(res, { error: (err as Error).message }, 404);
    }
  });

  route('GET', '/signal/feeds/:feedId/history', async (_req, res, params) => {
    json(res, engine.feeds.getFeedHistory(params.feedId));
  });

  // ═══════════════════════════════════════════════════
  // IOCs — base tier (9 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/iocs', async (req, res) => {
    const q = getQuery(req);
    const result = engine.ioc.list(
      q.get('cursor') || undefined,
      parseInt(q.get('limit') || '50'),
      {
        type: q.get('type') as IOC['type'] | undefined,
        severity: q.get('severity') as IOC['severity'] | undefined,
        status: q.get('status') as IOC['status'] | undefined,
        feed_id: q.get('feed_id') || undefined,
      }
    );
    json(res, result);
  });

  route('GET', '/signal/iocs/:iocId', async (_req, res, params) => {
    const ioc = engine.ioc.get(params.iocId);
    if (!ioc) return json(res, { error: 'IOC not found' }, 404);
    json(res, ioc);
  });

  route('POST', '/signal/iocs', async (req, res) => {
    const body = await readBody(req) as unknown as IOC;
    engine.ioc.add(body);
    json(res, body, 201);
  });

  route('PUT', '/signal/iocs/:iocId', async (req, res, params) => {
    const body = await readBody(req);
    if (body.status) engine.ioc.updateStatus(params.iocId, body.status as IOC['status']);
    const ioc = engine.ioc.get(params.iocId);
    if (!ioc) return json(res, { error: 'IOC not found' }, 404);
    json(res, ioc);
  });

  route('DELETE', '/signal/iocs/:iocId', async (_req, res, params) => {
    if (!engine.ioc.remove(params.iocId)) return json(res, { error: 'IOC not found' }, 404);
    json(res, { deleted: true });
  });

  route('POST', '/signal/iocs/search', async (req, res) => {
    const body = await readBody(req);
    const results = engine.ioc.search(
      (body.query as string) || '',
      { type: body.type as IOC['type'] | undefined, severity: body.severity as IOC['severity'] | undefined, status: body.status as IOC['status'] | undefined }
    );
    json(res, { results, count: results.length });
  });

  route('GET', '/signal/iocs/:iocId/hits', async (_req, res, params) => {
    const ioc = engine.ioc.get(params.iocId);
    if (!ioc) return json(res, { error: 'IOC not found' }, 404);
    json(res, { ioc_id: params.iocId, hit_count: ioc.hit_count, last_hit_at: ioc.last_hit_at });
  });

  route('POST', '/signal/iocs/bulk', async (req, res) => {
    const body = await readBody(req);
    const iocs = (body.iocs as IOC[]) || [];
    const result = engine.ioc.bulkAdd(iocs);
    json(res, result);
  });

  route('GET', '/signal/iocs/export', async (req, res) => {
    const q = getQuery(req);
    const format = (q.get('format') || 'json') as 'json' | 'csv';
    const data = engine.ioc.exportAll(format);
    const contentType = format === 'csv' ? 'text/csv' : 'application/json';
    res.writeHead(200, { 'Content-Type': contentType, 'Access-Control-Allow-Origin': '*' });
    res.end(data);
  });

  // ═══════════════════════════════════════════════════
  // Threat Actors — standard tier (6 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/actors', async (_req, res) => {
    if (!tierGate('standard', res)) return;
    json(res, engine.actors.list());
  });

  route('GET', '/signal/actors/:actorId', async (_req, res, params) => {
    if (!tierGate('standard', res)) return;
    const actor = engine.actors.get(params.actorId);
    if (!actor) return json(res, { error: 'Actor not found' }, 404);
    json(res, actor);
  });

  route('POST', '/signal/actors', async (req, res) => {
    if (!tierGate('standard', res)) return;
    const body = await readBody(req) as unknown as ThreatActor;
    engine.actors.add(body);
    json(res, body, 201);
  });

  route('PUT', '/signal/actors/:actorId', async (req, res, params) => {
    if (!tierGate('standard', res)) return;
    const body = await readBody(req);
    const updated = engine.actors.update(params.actorId, body as Partial<ThreatActor>);
    if (!updated) return json(res, { error: 'Actor not found' }, 404);
    json(res, updated);
  });

  route('GET', '/signal/actors/:actorId/iocs', async (_req, res, params) => {
    if (!tierGate('standard', res)) return;
    const iocIds = engine.actors.getActorIOCs(params.actorId);
    const iocs = iocIds.map(id => engine.ioc.get(id)).filter(Boolean);
    json(res, iocs);
  });

  route('GET', '/signal/actors/:actorId/timeline', async (_req, res, params) => {
    if (!tierGate('standard', res)) return;
    json(res, engine.actors.getTimeline(params.actorId));
  });

  // ═══════════════════════════════════════════════════
  // Campaigns — standard tier (5 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/campaigns', async (_req, res) => {
    if (!tierGate('standard', res)) return;
    json(res, engine.listCampaigns());
  });

  route('GET', '/signal/campaigns/:campaignId', async (_req, res, params) => {
    if (!tierGate('standard', res)) return;
    const campaign = engine.getCampaign(params.campaignId);
    if (!campaign) return json(res, { error: 'Campaign not found' }, 404);
    json(res, campaign);
  });

  route('POST', '/signal/campaigns', async (req, res) => {
    if (!tierGate('standard', res)) return;
    const body = await readBody(req) as unknown as Campaign;
    engine.addCampaign(body);
    json(res, body, 201);
  });

  route('PUT', '/signal/campaigns/:campaignId', async (req, res, params) => {
    if (!tierGate('standard', res)) return;
    const body = await readBody(req);
    const updated = engine.updateCampaign(params.campaignId, body as Partial<Campaign>);
    if (!updated) return json(res, { error: 'Campaign not found' }, 404);
    json(res, updated);
  });

  route('GET', '/signal/campaigns/:campaignId/timeline', async (_req, res, params) => {
    if (!tierGate('standard', res)) return;
    json(res, engine.getCampaignTimeline(params.campaignId));
  });

  // ═══════════════════════════════════════════════════
  // STIX/TAXII — advanced tier (6 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/taxii/discovery', async (_req, res) => {
    if (!tierGate('advanced', res)) return;
    res.writeHead(200, { 'Content-Type': 'application/taxii+json;version=2.1', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(engine.stix.getDiscovery()));
  });

  route('GET', '/signal/taxii/collections', async (_req, res) => {
    if (!tierGate('advanced', res)) return;
    json(res, { collections: engine.stix.listCollections() });
  });

  route('GET', '/signal/taxii/collections/:collectionId/objects', async (req, res, params) => {
    if (!tierGate('advanced', res)) return;
    const q = getQuery(req);
    const result = engine.stix.getCollectionObjects(
      params.collectionId,
      q.get('cursor') || undefined,
      parseInt(q.get('limit') || '50')
    );
    res.writeHead(200, { 'Content-Type': 'application/stix+json;version=2.1', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(result));
  });

  route('POST', '/signal/taxii/collections/:collectionId/objects', async (req, res, params) => {
    if (!tierGate('advanced', res)) return;
    const body = await readBody(req);
    const objects = (body.objects as any[]) || [];
    const count = engine.stix.addToCollection(params.collectionId, objects);
    json(res, { added: count });
  });

  route('POST', '/signal/stix/import', async (req, res) => {
    if (!tierGate('advanced', res)) return;
    const body = await readBody(req) as unknown as StixBundle & { collection_id?: string };
    const collectionId = body.collection_id || 'col-default';
    const result = engine.stix.importBundle(body, collectionId);
    json(res, result);
  });

  route('GET', '/signal/stix/export', async (req, res) => {
    if (!tierGate('advanced', res)) return;
    const q = getQuery(req);
    const collectionId = q.get('collection_id') || 'col-default';
    const bundle = engine.stix.exportBundle(collectionId);
    if (!bundle) return json(res, { error: 'Collection not found' }, 404);
    res.writeHead(200, { 'Content-Type': 'application/stix+json;version=2.1', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(bundle));
  });

  // ═══════════════════════════════════════════════════
  // Dark Web — advanced tier (6 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/darkweb/mentions', async (req, res) => {
    if (!tierGate('advanced', res)) return;
    const q = getQuery(req);
    const mentions = engine.darkweb.listMentions({
      type: q.get('type') as DarkWebMention['type'] | undefined,
      severity: q.get('severity') as DarkWebMention['severity'] | undefined,
      status: q.get('status') as DarkWebMention['status'] | undefined,
    });
    json(res, mentions);
  });

  route('GET', '/signal/darkweb/mentions/:mentionId', async (_req, res, params) => {
    if (!tierGate('advanced', res)) return;
    const mention = engine.darkweb.getMention(params.mentionId);
    if (!mention) return json(res, { error: 'Mention not found' }, 404);
    json(res, mention);
  });

  route('PUT', '/signal/darkweb/mentions/:mentionId', async (req, res, params) => {
    if (!tierGate('advanced', res)) return;
    const body = await readBody(req);
    if (!engine.darkweb.updateMentionStatus(params.mentionId, body.status as DarkWebMention['status'])) {
      return json(res, { error: 'Mention not found' }, 404);
    }
    json(res, engine.darkweb.getMention(params.mentionId));
  });

  route('GET', '/signal/darkweb/watchlist', async (_req, res) => {
    if (!tierGate('advanced', res)) return;
    json(res, engine.darkweb.getWatchlist());
  });

  route('POST', '/signal/darkweb/watchlist', async (req, res) => {
    if (!tierGate('advanced', res)) return;
    const body = await readBody(req) as unknown as WatchlistEntry;
    engine.darkweb.addToWatchlist(body);
    json(res, body, 201);
  });

  route('DELETE', '/signal/darkweb/watchlist/:entryId', async (_req, res, params) => {
    if (!tierGate('advanced', res)) return;
    if (!engine.darkweb.removeFromWatchlist(params.entryId)) return json(res, { error: 'Entry not found' }, 404);
    json(res, { deleted: true });
  });

  // ═══════════════════════════════════════════════════
  // Enriched Alerts — advanced tier (3 endpoints)
  // ═══════════════════════════════════════════════════

  route('GET', '/signal/alerts', async (req, res) => {
    if (!tierGate('advanced', res)) return;
    const q = getQuery(req);
    const result = engine.enrichment.listAlerts(
      q.get('cursor') || undefined,
      parseInt(q.get('limit') || '50')
    );
    json(res, result);
  });

  route('GET', '/signal/alerts/:alertId', async (_req, res, params) => {
    if (!tierGate('advanced', res)) return;
    const alert = engine.enrichment.getAlert(params.alertId);
    if (!alert) return json(res, { error: 'Alert not found' }, 404);
    json(res, alert);
  });

  route('GET', '/signal/alerts/stats', async (_req, res) => {
    if (!tierGate('advanced', res)) return;
    json(res, engine.enrichment.getAlertStats());
  });

  // ── Router ──

  return (req: IncomingMessage, res: ServerResponse) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      });
      return res.end();
    }

    const url = req.url?.split('?')[0] || '/';
    const method = req.method || 'GET';

    for (const r of routes) {
      if (r.method === method && r.pattern.test(url)) {
        r.handler(req, res, {}).catch(err => {
          console.error(`[SIGNAL] ${method} ${url} error:`, err);
          json(res, { error: 'Internal server error' }, 500);
        });
        return;
      }
    }

    json(res, { error: 'Not found', path: url }, 404);
  };
}
