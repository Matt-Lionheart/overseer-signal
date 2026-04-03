// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Type Definitions
// Strategic Intelligence Gathering, Notification, and Alert Logistics
// ═══════════════════════════════════════════════════════════════

// ── IOC Types ──

export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email' | 'cve' | 'cidr';
export type IOCStatus = 'active' | 'expired' | 'revoked' | 'whitelisted';
export type TLPLevel = 'TLP:RED' | 'TLP:AMBER+STRICT' | 'TLP:AMBER' | 'TLP:GREEN' | 'TLP:CLEAR';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface IOC {
  ioc_id: string;
  type: IOCType;
  value: string;
  source_feed_id: string;
  first_seen: string;
  last_seen: string;
  expiration: string | null;
  confidence: number;           // 0-100
  severity: Severity;
  status: IOCStatus;
  tlp: TLPLevel;
  tags: string[];
  context: {
    actor_ids: string[];
    campaign_ids: string[];
    malware_families: string[];
    cve_ids: string[];
  };
  stix_id: string;
  kill_chain_phases: string[];
  hit_count: number;
  last_hit_at: string | null;
  enrichments: Record<string, unknown>;
}

// ── Feed Types ──

export type FeedFormat = 'stix_taxii' | 'csv' | 'json' | 'txt_flat' | 'misp';
export type FeedStatus = 'active' | 'paused' | 'error' | 'initializing';
export type FeedAuthType = 'none' | 'api_key' | 'basic' | 'oauth2' | 'certificate';

export interface Feed {
  feed_id: string;
  name: string;
  provider: string;
  url: string;
  format: FeedFormat;
  poll_interval_minutes: number;
  status: FeedStatus;
  last_poll_at: string | null;
  next_poll_at: string | null;
  ioc_count: number;
  error_count: number;
  last_error: string | null;
  dedup_count: number;
  tlp_default: TLPLevel;
  enabled: boolean;
  license_tier: 'base' | 'standard' | 'advanced';
  auth_type: FeedAuthType;
  category: 'osint' | 'commercial' | 'government' | 'internal';
}

export interface FeedPollEvent {
  feed_id: string;
  polled_at: string;
  new_iocs: number;
  updated_iocs: number;
  dedup_skipped: number;
  duration_ms: number;
  error: string | null;
}

// ── Threat Actor Types ──

export type AttributionConfidence = 'confirmed' | 'likely' | 'possible' | 'suspected' | 'unattributed';
export type ActorType = 'nation-state' | 'criminal' | 'hacktivist' | 'insider' | 'unknown';

export interface MitreTTP {
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  sub_technique_id?: string;
  sub_technique_name?: string;
  usage_description: string;
}

export interface ThreatActor {
  actor_id: string;
  name: string;
  aliases: string[];
  description: string;
  actor_type: ActorType;
  origin_country: string | null;
  attribution_confidence: AttributionConfidence;
  first_observed: string;
  last_activity: string;
  targeted_sectors: string[];
  targeted_regions: string[];
  ttps: MitreTTP[];
  associated_campaigns: string[];
  associated_iocs: string[];
  risk_level: Severity;
  stix_id: string;
  references: { url: string; title: string; source: string }[];
}

// ── Campaign Types ──

export type CampaignStatus = 'active' | 'historical' | 'developing';

export interface CampaignEvent {
  timestamp: string;
  event_type: string;
  description: string;
  ioc_ids: string[];
  mitre_technique_id: string;
}

export interface Campaign {
  campaign_id: string;
  name: string;
  description: string;
  status: CampaignStatus;
  actor_ids: string[];
  ioc_ids: string[];
  ttp_ids: string[];
  kill_chain_phase: string;
  first_activity: string;
  last_activity: string;
  targeted_sectors: string[];
  affected_asset_count: number;
  confidence: number;
  stix_id: string;
  timeline: CampaignEvent[];
}

// ── STIX/TAXII Types ──

export interface StixObject {
  id: string;
  type: string;
  spec_version: '2.1';
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

export interface TaxiiCollection {
  collection_id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
  object_count: number;
  last_updated: string;
}

// ── Dark Web Types ──

export type MentionType = 'credential_leak' | 'brand_mention' | 'domain_mention' | 'executive_mention' |
  'data_sale' | 'vulnerability_discussion' | 'ransomware_listing';
export type MentionStatus = 'new' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved';

export interface DarkWebMention {
  mention_id: string;
  type: MentionType;
  source_platform: string;
  source_url_hash: string;
  discovered_at: string;
  content_snippet: string;
  matched_keywords: string[];
  matched_assets: string[];
  severity: Severity;
  status: MentionStatus;
  credential_count?: number;
  affected_domains?: string[];
  actor_attribution?: string;
}

export interface WatchlistEntry {
  entry_id: string;
  type: 'domain' | 'email' | 'brand' | 'executive' | 'keyword';
  value: string;
  added_at: string;
  enabled: boolean;
}

// ── Enriched Alert Types ──

export interface EnrichedAlert {
  alert_id: string;
  original_event_id: string;
  original_event_type: string;
  matched_ioc: IOC;
  threat_context: {
    actors: ThreatActor[];
    campaigns: Campaign[];
    related_iocs: IOC[];
    kill_chain_position: string;
  };
  match_confidence: number;
  auto_enriched_at: string;
  recommended_actions: string[];
  correlation_id: string;
  pillar: string;
}

// ── License Types ──

export type LicenseTier = 'base' | 'standard' | 'advanced';

export interface SignalLicense {
  sku: string;
  tier: LicenseTier;
  status: 'active' | 'expired' | 'not_licensed';
  license_key: string;
  days_remaining: number | null;
  features: string[];
  max_feeds: number;
}

export const LICENSE_TIERS: Record<LicenseTier, { features: string[]; max_feeds: number }> = {
  base: {
    max_feeds: 10,
    features: [
      'OSINT Feed Ingestion (Free)',
      'CISA AIS Government Feed (Free)',
      'IOC Database',
      'IOC Matching Engine',
      'Bloom Filter Lookups',
      'Basic IOC Search',
      'CSV Export',
      'IOC-Only Enrichment',
      'Feed Health Monitoring',
      'IOC Lifecycle Management',
      'Manual IOC Entry',
      'Bulk IOC Import',
      'Internal Honeypot Feed',
      'REST API',
    ],
  },
  standard: {
    max_feeds: Infinity,
    features: [
      'All Base Features',
      'Commercial Feed Add-Ons (CrowdStrike, Mandiant)',
      'Unlimited Feeds',
      'Threat Actor Profiling',
      'MITRE ATT&CK TTP Mapping',
      'Campaign Tracking',
      'Campaign Timeline',
      'Kill Chain Mapping',
      'Actor-IOC Correlation',
      'Full Enrichment with Actor Context',
      'Actor Activity Timeline',
      'Campaign-IOC Linkage',
      'Attribution Confidence Scoring',
      'Sector Targeting Analysis',
      'TTP Coverage Heatmap',
      'Advanced Search Filters',
      'Paginated API',
      'Webhook Notifications',
      'OSEF Event Integration',
      'Audit Trail',
      'REST API',
    ],
  },
  advanced: {
    max_feeds: Infinity,
    features: [
      'All Standard Features',
      'STIX 2.1 Object Model',
      'TAXII 2.1 Server',
      'STIX Bundle Import/Export',
      'Partner Collection Sharing',
      'ISAC Integration',
      'Dark Web Monitoring',
      'Credential Leak Detection',
      'Brand Impersonation Alerts',
      'Executive Mention Tracking',
      'Custom Feed Parsers',
      'Streaming STIX Export',
      'TLP Enforcement',
      'Multi-Tenant Intelligence',
      'REST API',
    ],
  },
};

// ── Stats Aggregate ──

export interface SignalStats {
  total_iocs: number;
  active_iocs: number;
  feeds_active: number;
  feeds_error: number;
  ioc_hits_24h: number;
  actors_tracked: number;
  active_campaigns: number;
  darkweb_mentions_7d: number;
  enriched_alerts_24h: number;
  stix_objects_shared: number;
  avg_match_latency_ms: number;
  bloom_filter_size_mb: number;
}
