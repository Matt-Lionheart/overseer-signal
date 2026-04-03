// ═══════════════════════════════════════════════════════════════
//   ███████╗██╗ ██████╗ ███╗   ██╗ █████╗ ██╗
//   ██╔════╝██║██╔════╝ ████╗  ██║██╔══██╗██║
//   ███████╗██║██║  ███╗██╔██╗ ██║███████║██║
//   ╚════██║██║██║   ██║██║╚██╗██║██╔══██║██║
//   ███████║██║╚██████╔╝██║ ╚████║██║  ██║███████╗
//   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
//
//   Strategic Intelligence Gathering, Notification, and Alert Logistics
//   Threat Intelligence Platform — OVERSEER Licensed Module
//   Port 7077 | v0.1.0
// ═══════════════════════════════════════════════════════════════

import { createServer } from 'node:http';
import { SignalEngine } from './engine/signal-engine.js';
import { createRouter } from './api/signal-api.js';
import type { Feed, IOC, ThreatActor, Campaign, DarkWebMention, WatchlistEntry, EnrichedAlert } from './engine/signal-types.js';

const PORT = parseInt(process.env.SIGNAL_PORT || process.env.PORT || '7077');

// ── Initialize Engine ──
const engine = new SignalEngine();

// ── Seed Demo Data ──
seedDemoData(engine);

// ── Start Server ──
const router = createRouter(engine);
const server = createServer(router);

server.listen(PORT, () => {
  const stats = engine.getStats();
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  S.I.G.N.A.L. — Threat Intelligence Platform v0.1.0        ║
║  Strategic Intelligence Gathering, Notification, and        ║
║  Alert Logistics                                            ║
╠══════════════════════════════════════════════════════════════╣
║  Port:       ${String(PORT).padEnd(46)}║
║  Feeds:      ${String(stats.feeds_active).padEnd(46)}║
║  IOCs:       ${String(stats.total_iocs).padEnd(46)}║
║  Actors:     ${String(stats.actors_tracked).padEnd(46)}║
║  Campaigns:  ${String(stats.active_campaigns).padEnd(46)}║
║  Dark Web:   ${String(stats.darkweb_mentions_7d + ' mentions').padEnd(46)}║
║  Alerts:     ${String(stats.enriched_alerts_24h).padEnd(46)}║
║  Bloom:      ${String(stats.bloom_filter_size_mb.toFixed(2) + ' MB').padEnd(46)}║
║  License:    ${String(engine.getLicenseTier() + ' tier').padEnd(46)}║
╠══════════════════════════════════════════════════════════════╣
║  Health:     http://localhost:${PORT}/signal/health${' '.repeat(Math.max(0, 25 - String(PORT).length))}║
║  TAXII:      http://localhost:${PORT}/signal/taxii/discovery${' '.repeat(Math.max(0, 16 - String(PORT).length))}║
╚══════════════════════════════════════════════════════════════╝
  `);
});

// ═══════════════════════════════════════════════════════════════
// Demo Data
// ═══════════════════════════════════════════════════════════════

function seedDemoData(engine: SignalEngine): void {
  // ── 8 Feeds ──
  const feeds: Feed[] = [
    { feed_id: 'feed-otx', name: 'AlienVault OTX', provider: 'AlienVault', url: 'https://otx.alienvault.com/api/v1/pulses/subscribed', format: 'json', poll_interval_minutes: 60, status: 'active', last_poll_at: new Date(Date.now() - 1800000).toISOString(), next_poll_at: new Date(Date.now() + 1800000).toISOString(), ioc_count: 12847, error_count: 0, last_error: null, dedup_count: 2341, tlp_default: 'TLP:GREEN', enabled: true, license_tier: 'base', auth_type: 'api_key', category: 'osint' },
    { feed_id: 'feed-urlhaus', name: 'Abuse.ch URLhaus', provider: 'Abuse.ch', url: 'https://urlhaus-api.abuse.ch/v1/', format: 'csv', poll_interval_minutes: 30, status: 'active', last_poll_at: new Date(Date.now() - 900000).toISOString(), next_poll_at: new Date(Date.now() + 900000).toISOString(), ioc_count: 45231, error_count: 0, last_error: null, dedup_count: 8102, tlp_default: 'TLP:GREEN', enabled: true, license_tier: 'base', auth_type: 'none', category: 'osint' },
    { feed_id: 'feed-cisa', name: 'CISA AIS', provider: 'CISA', url: 'https://ais.cisa.gov/taxii2/collections/', format: 'stix_taxii', poll_interval_minutes: 120, status: 'active', last_poll_at: new Date(Date.now() - 3600000).toISOString(), next_poll_at: new Date(Date.now() + 3600000).toISOString(), ioc_count: 3412, error_count: 0, last_error: null, dedup_count: 456, tlp_default: 'TLP:AMBER', enabled: true, license_tier: 'standard', auth_type: 'certificate', category: 'government' },
    { feed_id: 'feed-crowdstrike', name: 'CrowdStrike Falcon Intelligence', provider: 'CrowdStrike', url: 'https://api.crowdstrike.com/intel/combined/indicators/v1', format: 'json', poll_interval_minutes: 15, status: 'active', last_poll_at: new Date(Date.now() - 600000).toISOString(), next_poll_at: new Date(Date.now() + 300000).toISOString(), ioc_count: 89102, error_count: 0, last_error: null, dedup_count: 15430, tlp_default: 'TLP:AMBER', enabled: true, license_tier: 'standard', auth_type: 'oauth2', category: 'commercial' },
    { feed_id: 'feed-mandiant', name: 'Mandiant Advantage', provider: 'Mandiant', url: 'https://api.intelligence.mandiant.com/v4/indicator', format: 'json', poll_interval_minutes: 30, status: 'active', last_poll_at: new Date(Date.now() - 1200000).toISOString(), next_poll_at: new Date(Date.now() + 600000).toISOString(), ioc_count: 67445, error_count: 0, last_error: null, dedup_count: 11203, tlp_default: 'TLP:AMBER', enabled: true, license_tier: 'standard', auth_type: 'api_key', category: 'commercial' },
    { feed_id: 'feed-misp', name: 'MISP Community', provider: 'MISP Project', url: 'https://misp.community/feeds/', format: 'misp', poll_interval_minutes: 60, status: 'active', last_poll_at: new Date(Date.now() - 2400000).toISOString(), next_poll_at: new Date(Date.now() + 1200000).toISOString(), ioc_count: 8923, error_count: 1, last_error: null, dedup_count: 1578, tlp_default: 'TLP:GREEN', enabled: true, license_tier: 'base', auth_type: 'api_key', category: 'osint' },
    { feed_id: 'feed-shadowserver', name: 'Shadowserver Foundation', provider: 'Shadowserver', url: 'https://api.shadowserver.org/reports/', format: 'csv', poll_interval_minutes: 360, status: 'active', last_poll_at: new Date(Date.now() - 7200000).toISOString(), next_poll_at: new Date(Date.now() + 14400000).toISOString(), ioc_count: 156000, error_count: 0, last_error: null, dedup_count: 23100, tlp_default: 'TLP:GREEN', enabled: true, license_tier: 'base', auth_type: 'api_key', category: 'osint' },
    { feed_id: 'feed-honeypot', name: 'Internal Honeypot Feed', provider: 'ACE Internal', url: 'internal://honeypot-collector', format: 'json', poll_interval_minutes: 5, status: 'active', last_poll_at: new Date(Date.now() - 180000).toISOString(), next_poll_at: new Date(Date.now() + 120000).toISOString(), ioc_count: 1247, error_count: 0, last_error: null, dedup_count: 89, tlp_default: 'TLP:RED', enabled: true, license_tier: 'base', auth_type: 'none', category: 'internal' },
  ];
  for (const f of feeds) engine.feeds.addFeed(f);

  // ── 6 Threat Actors ──
  const actors: ThreatActor[] = [
    {
      actor_id: 'actor-apt29', name: 'APT29', aliases: ['Cozy Bear', 'The Dukes', 'Midnight Blizzard', 'NOBELIUM'],
      description: 'Russian Foreign Intelligence Service (SVR) cyber espionage group. Highly sophisticated operations targeting government, diplomatic, and policy organizations. Known for SolarWinds supply chain compromise and Microsoft 365 credential attacks.',
      actor_type: 'nation-state', origin_country: 'Russia', attribution_confidence: 'confirmed',
      first_observed: '2008-01-01T00:00:00Z', last_activity: '2026-03-28T14:22:00Z',
      targeted_sectors: ['Government', 'Defense', 'Think Tanks', 'Diplomacy', 'Technology'],
      targeted_regions: ['North America', 'Europe', 'NATO countries'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', usage_description: 'Crafted phishing emails with malicious HTML attachments targeting government personnel' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', usage_description: 'Obfuscated PowerShell scripts for payload delivery and C2 communication' },
        { tactic_id: 'TA0011', tactic_name: 'Command and Control', technique_id: 'T1071.001', technique_name: 'Web Protocols', usage_description: 'HTTPS-based C2 channels using legitimate cloud services as proxies' },
        { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', technique_id: 'T1027', technique_name: 'Obfuscated Files', usage_description: 'Multi-layer encryption and steganography in C2 communications' },
        { tactic_id: 'TA0007', tactic_name: 'Discovery', technique_id: 'T1083', technique_name: 'File and Directory Discovery', usage_description: 'Systematic enumeration of sensitive document repositories' },
      ],
      associated_campaigns: ['camp-midnight'], associated_iocs: ['ioc-001', 'ioc-002', 'ioc-003', 'ioc-009', 'ioc-015'],
      risk_level: 'critical', stix_id: 'threat-actor--6d179234-61cf-40db-bb3b-0dc20a5c8b3d',
      references: [
        { url: 'https://attack.mitre.org/groups/G0016/', title: 'MITRE ATT&CK: APT29', source: 'MITRE' },
        { url: 'https://www.mandiant.com/resources/blog/apt29-wineloader', title: 'APT29 WINELOADER Campaign', source: 'Mandiant' },
      ],
    },
    {
      actor_id: 'actor-apt41', name: 'APT41', aliases: ['Wicked Panda', 'Double Dragon', 'BARIUM', 'Winnti Group'],
      description: 'Chinese state-sponsored group that also conducts financially motivated intrusions. Dual-hat operations: espionage for MSS and cybercrime for personal gain. Known for targeting healthcare, telecoms, and technology sectors.',
      actor_type: 'nation-state', origin_country: 'China', attribution_confidence: 'confirmed',
      first_observed: '2012-06-01T00:00:00Z', last_activity: '2026-03-15T09:45:00Z',
      targeted_sectors: ['Technology', 'Healthcare', 'Telecommunications', 'Gaming', 'Finance'],
      targeted_regions: ['Global', 'Asia-Pacific', 'North America'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', usage_description: 'Exploits in Citrix, Cisco, Zoho ManageEngine for initial access' },
        { tactic_id: 'TA0003', tactic_name: 'Persistence', technique_id: 'T1505.003', technique_name: 'Web Shell', usage_description: 'BEHINDER and China Chopper web shells for persistent access' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.003', technique_name: 'Windows Command Shell', usage_description: 'cmd.exe execution for reconnaissance and lateral movement' },
        { tactic_id: 'TA0007', tactic_name: 'Discovery', technique_id: 'T1046', technique_name: 'Network Service Discovery', usage_description: 'Internal network scanning to identify high-value targets' },
      ],
      associated_campaigns: ['camp-volt'], associated_iocs: ['ioc-004', 'ioc-005', 'ioc-010', 'ioc-016'],
      risk_level: 'critical', stix_id: 'threat-actor--9c888b84-a5a4-4043-b15b-9e4bcf25c581',
      references: [
        { url: 'https://attack.mitre.org/groups/G0096/', title: 'MITRE ATT&CK: APT41', source: 'MITRE' },
      ],
    },
    {
      actor_id: 'actor-lazarus', name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'Zinc', 'Diamond Sleet', 'Labyrinth Chollima'],
      description: 'North Korean state-sponsored group under RGB. Primary objectives: revenue generation through cryptocurrency theft and financial fraud, plus espionage against defense and aerospace. Responsible for WannaCry, Bangladesh Bank heist, and multiple crypto exchange breaches.',
      actor_type: 'nation-state', origin_country: 'North Korea', attribution_confidence: 'confirmed',
      first_observed: '2009-01-01T00:00:00Z', last_activity: '2026-03-20T11:30:00Z',
      targeted_sectors: ['Financial Services', 'Cryptocurrency', 'Defense', 'Aerospace', 'Media'],
      targeted_regions: ['Global', 'South Korea', 'Japan', 'United States'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1566.002', technique_name: 'Spearphishing Link', usage_description: 'LinkedIn-based social engineering targeting crypto developers' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', usage_description: 'PowerShell loaders for multi-stage payload delivery' },
        { tactic_id: 'TA0011', tactic_name: 'Command and Control', technique_id: 'T1071.004', technique_name: 'DNS', usage_description: 'DNS tunneling for covert C2 communication' },
        { tactic_id: 'TA0040', tactic_name: 'Impact', technique_id: 'T1486', technique_name: 'Data Encrypted for Impact', usage_description: 'WannaCry ransomware deployment for destructive impact and revenue' },
      ],
      associated_campaigns: [], associated_iocs: ['ioc-006', 'ioc-011', 'ioc-017', 'ioc-021'],
      risk_level: 'critical', stix_id: 'threat-actor--68391641-859f-4a9a-9a1e-3e5cf71ec376',
      references: [
        { url: 'https://attack.mitre.org/groups/G0032/', title: 'MITRE ATT&CK: Lazarus Group', source: 'MITRE' },
      ],
    },
    {
      actor_id: 'actor-fin7', name: 'FIN7', aliases: ['Carbanak', 'Carbon Spider', 'Sangria Tempest'],
      description: 'Financially motivated cybercrime group known for targeting retail, restaurant, and hospitality sectors. Evolved from POS malware to ransomware-as-a-service operations. Members have been indicted by US DOJ.',
      actor_type: 'criminal', origin_country: 'Russia', attribution_confidence: 'likely',
      first_observed: '2013-01-01T00:00:00Z', last_activity: '2026-02-28T16:10:00Z',
      targeted_sectors: ['Retail', 'Hospitality', 'Financial Services', 'Food & Beverage'],
      targeted_regions: ['North America', 'Europe'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', usage_description: 'Malicious documents disguised as SEC complaints or delivery notifications' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', usage_description: 'GRIFFON and HALFBAKED PowerShell backdoors' },
        { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', technique_id: 'T1055', technique_name: 'Process Injection', usage_description: 'DLL injection into legitimate processes to evade EDR' },
        { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', technique_id: 'T1021.001', technique_name: 'Remote Desktop Protocol', usage_description: 'RDP for lateral movement using stolen credentials' },
      ],
      associated_campaigns: [], associated_iocs: ['ioc-007', 'ioc-012', 'ioc-018'],
      risk_level: 'high', stix_id: 'threat-actor--3753cc21-2dae-4dfb-b080-7d9e7f4f08b0',
      references: [
        { url: 'https://attack.mitre.org/groups/G0046/', title: 'MITRE ATT&CK: FIN7', source: 'MITRE' },
      ],
    },
    {
      actor_id: 'actor-sandworm', name: 'Sandworm', aliases: ['Voodoo Bear', 'Seashell Blizzard', 'IRIDIUM', 'TeleBots'],
      description: 'Russian GRU Unit 74455. Focused on destructive cyberattacks against critical infrastructure. Responsible for NotPetya, Ukraine power grid attacks, and Olympic Destroyer. Considered one of the most dangerous APT groups globally.',
      actor_type: 'nation-state', origin_country: 'Russia', attribution_confidence: 'confirmed',
      first_observed: '2009-01-01T00:00:00Z', last_activity: '2026-03-10T08:15:00Z',
      targeted_sectors: ['Energy', 'Government', 'Critical Infrastructure', 'Transportation', 'Media'],
      targeted_regions: ['Ukraine', 'Europe', 'Global'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', usage_description: 'Exploitation of Exim, Fortinet, and Zimbra vulnerabilities' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', usage_description: 'PowerShell-based Industroyer and CaddyWiper payloads' },
        { tactic_id: 'TA0040', tactic_name: 'Impact', technique_id: 'T1489', technique_name: 'Service Stop', usage_description: 'Shutting down industrial control systems in power grid attacks' },
        { tactic_id: 'TA0040', tactic_name: 'Impact', technique_id: 'T1561.002', technique_name: 'Disk Structure Wipe', usage_description: 'NotPetya and HermeticWiper disk wiping operations' },
      ],
      associated_campaigns: [], associated_iocs: ['ioc-008', 'ioc-013', 'ioc-019'],
      risk_level: 'critical', stix_id: 'threat-actor--381fcf73-60f6-4ab2-9991-6af3cbc35192',
      references: [
        { url: 'https://attack.mitre.org/groups/G0034/', title: 'MITRE ATT&CK: Sandworm Team', source: 'MITRE' },
      ],
    },
    {
      actor_id: 'actor-unc3886', name: 'UNC3886', aliases: [],
      description: 'Suspected China-nexus espionage group targeting networking equipment and virtualization platforms. Known for exploiting zero-days in VMware and Fortinet products. Uses novel rootkits (REPTILE, MEDUSA) on ESXi hypervisors.',
      actor_type: 'nation-state', origin_country: 'China', attribution_confidence: 'suspected',
      first_observed: '2021-06-01T00:00:00Z', last_activity: '2026-03-25T13:00:00Z',
      targeted_sectors: ['Technology', 'Telecommunications', 'Government', 'Defense'],
      targeted_regions: ['Asia-Pacific', 'North America'],
      ttps: [
        { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', usage_description: 'Zero-day exploitation of VMware vCenter and Fortinet FortiOS' },
        { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.006', technique_name: 'Python', usage_description: 'Python-based backdoors deployed on ESXi hypervisors' },
        { tactic_id: 'TA0003', tactic_name: 'Persistence', technique_id: 'T1554', technique_name: 'Compromise Client Software Binary', usage_description: 'Trojanized vCenter binaries for persistent hypervisor access' },
        { tactic_id: 'TA0006', tactic_name: 'Credential Access', technique_id: 'T1556', technique_name: 'Modify Authentication Process', usage_description: 'SSH backdoor via modified PAM modules on ESXi hosts' },
      ],
      associated_campaigns: [], associated_iocs: ['ioc-014', 'ioc-020'],
      risk_level: 'high', stix_id: 'threat-actor--a47b4f9c-5e2b-4d93-8b3f-7c1a6e8d4f2a',
      references: [
        { url: 'https://www.mandiant.com/resources/blog/vmware-esxi-zero-day-bypass', title: 'UNC3886 VMware ESXi Zero-Day', source: 'Mandiant' },
      ],
    },
  ];
  for (const a of actors) engine.actors.add(a);

  // ── 30 IOCs ──
  const iocs: IOC[] = [
    // 8 IPs
    { ioc_id: 'ioc-001', type: 'ipv4', value: '185.220.101.34', source_feed_id: 'feed-crowdstrike', first_seen: '2026-03-01T00:00:00Z', last_seen: '2026-03-28T14:22:00Z', expiration: '2026-06-01T00:00:00Z', confidence: 95, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['apt29', 'c2', 'cobalt-strike'], context: { actor_ids: ['actor-apt29'], campaign_ids: ['camp-midnight'], malware_families: ['Cobalt Strike'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000001', kill_chain_phases: ['command-and-control'], hit_count: 12, last_hit_at: '2026-03-28T10:15:00Z', enrichments: {} },
    { ioc_id: 'ioc-002', type: 'ipv4', value: '91.219.236.178', source_feed_id: 'feed-mandiant', first_seen: '2026-02-15T00:00:00Z', last_seen: '2026-03-25T09:30:00Z', expiration: '2026-05-15T00:00:00Z', confidence: 90, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['apt29', 'exfiltration'], context: { actor_ids: ['actor-apt29'], campaign_ids: ['camp-midnight'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000002', kill_chain_phases: ['exfiltration'], hit_count: 3, last_hit_at: '2026-03-20T16:42:00Z', enrichments: {} },
    { ioc_id: 'ioc-003', type: 'ipv4', value: '45.77.65.211', source_feed_id: 'feed-otx', first_seen: '2026-03-10T00:00:00Z', last_seen: '2026-03-27T20:00:00Z', expiration: '2026-04-10T00:00:00Z', confidence: 85, severity: 'high', status: 'active', tlp: 'TLP:GREEN', tags: ['scanning', 'reconnaissance'], context: { actor_ids: ['actor-apt29'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000003', kill_chain_phases: ['reconnaissance'], hit_count: 47, last_hit_at: '2026-03-28T12:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-004', type: 'ipv4', value: '103.224.182.244', source_feed_id: 'feed-crowdstrike', first_seen: '2026-01-20T00:00:00Z', last_seen: '2026-03-15T09:45:00Z', expiration: '2026-06-20T00:00:00Z', confidence: 92, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['apt41', 'web-shell', 'behinder'], context: { actor_ids: ['actor-apt41'], campaign_ids: ['camp-volt'], malware_families: ['BEHINDER'], cve_ids: ['CVE-2024-3400'] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000004', kill_chain_phases: ['initial-access'], hit_count: 6, last_hit_at: '2026-03-10T08:20:00Z', enrichments: {} },
    { ioc_id: 'ioc-005', type: 'ipv4', value: '202.61.136.12', source_feed_id: 'feed-cisa', first_seen: '2026-02-01T00:00:00Z', last_seen: '2026-03-20T15:00:00Z', expiration: '2026-08-01T00:00:00Z', confidence: 88, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['apt41', 'living-off-land'], context: { actor_ids: ['actor-apt41'], campaign_ids: ['camp-volt'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000005', kill_chain_phases: ['command-and-control'], hit_count: 2, last_hit_at: '2026-03-18T11:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-006', type: 'ipv4', value: '175.45.176.99', source_feed_id: 'feed-mandiant', first_seen: '2026-03-05T00:00:00Z', last_seen: '2026-03-20T11:30:00Z', expiration: '2026-09-05T00:00:00Z', confidence: 80, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['lazarus', 'crypto-theft'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: ['AppleJeus'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000006', kill_chain_phases: ['initial-access', 'command-and-control'], hit_count: 0, last_hit_at: null, enrichments: {} },
    { ioc_id: 'ioc-007', type: 'ipv4', value: '194.36.189.7', source_feed_id: 'feed-urlhaus', first_seen: '2026-02-20T00:00:00Z', last_seen: '2026-03-25T08:00:00Z', expiration: '2026-05-20T00:00:00Z', confidence: 75, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['fin7', 'carbanak'], context: { actor_ids: ['actor-fin7'], campaign_ids: [], malware_families: ['GRIFFON'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000007', kill_chain_phases: ['command-and-control'], hit_count: 1, last_hit_at: '2026-03-22T14:30:00Z', enrichments: {} },
    { ioc_id: 'ioc-008', type: 'ipv4', value: '77.83.247.54', source_feed_id: 'feed-cisa', first_seen: '2026-01-15T00:00:00Z', last_seen: '2026-03-10T08:15:00Z', expiration: '2026-07-15T00:00:00Z', confidence: 93, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['sandworm', 'destructive', 'wiper'], context: { actor_ids: ['actor-sandworm'], campaign_ids: [], malware_families: ['CaddyWiper'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0001-0001-0001-000000000008', kill_chain_phases: ['delivery', 'installation'], hit_count: 0, last_hit_at: null, enrichments: {} },
    // 6 domains
    { ioc_id: 'ioc-009', type: 'domain', value: 'microsoftonline-auth.com', source_feed_id: 'feed-crowdstrike', first_seen: '2026-03-15T00:00:00Z', last_seen: '2026-03-28T12:00:00Z', expiration: '2026-06-15T00:00:00Z', confidence: 97, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['apt29', 'phishing', 'credential-harvest'], context: { actor_ids: ['actor-apt29'], campaign_ids: ['camp-midnight'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000001', kill_chain_phases: ['weaponization', 'delivery'], hit_count: 28, last_hit_at: '2026-03-28T11:45:00Z', enrichments: {} },
    { ioc_id: 'ioc-010', type: 'domain', value: 'updates-check-service.net', source_feed_id: 'feed-mandiant', first_seen: '2026-02-10T00:00:00Z', last_seen: '2026-03-15T09:45:00Z', expiration: '2026-05-10T00:00:00Z', confidence: 88, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['apt41', 'c2-domain'], context: { actor_ids: ['actor-apt41'], campaign_ids: ['camp-volt'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000002', kill_chain_phases: ['command-and-control'], hit_count: 5, last_hit_at: '2026-03-12T09:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-011', type: 'domain', value: 'blockchain-verify.io', source_feed_id: 'feed-otx', first_seen: '2026-03-08T00:00:00Z', last_seen: '2026-03-20T11:30:00Z', expiration: '2026-04-08T00:00:00Z', confidence: 82, severity: 'high', status: 'active', tlp: 'TLP:GREEN', tags: ['lazarus', 'crypto-phishing'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000003', kill_chain_phases: ['delivery'], hit_count: 15, last_hit_at: '2026-03-19T16:20:00Z', enrichments: {} },
    { ioc_id: 'ioc-012', type: 'domain', value: 'secure-payment-portal.com', source_feed_id: 'feed-urlhaus', first_seen: '2026-02-25T00:00:00Z', last_seen: '2026-03-18T10:00:00Z', expiration: '2026-05-25T00:00:00Z', confidence: 78, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['fin7', 'pos-malware'], context: { actor_ids: ['actor-fin7'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000004', kill_chain_phases: ['delivery'], hit_count: 3, last_hit_at: '2026-03-15T12:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-013', type: 'domain', value: 'ua-gov-portal.xyz', source_feed_id: 'feed-cisa', first_seen: '2026-01-20T00:00:00Z', last_seen: '2026-03-10T08:15:00Z', expiration: '2026-07-20T00:00:00Z', confidence: 91, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['sandworm', 'destructive'], context: { actor_ids: ['actor-sandworm'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000005', kill_chain_phases: ['delivery'], hit_count: 0, last_hit_at: null, enrichments: {} },
    { ioc_id: 'ioc-014', type: 'domain', value: 'vmware-updates-cdn.com', source_feed_id: 'feed-mandiant', first_seen: '2026-03-01T00:00:00Z', last_seen: '2026-03-25T13:00:00Z', expiration: '2026-06-01T00:00:00Z', confidence: 86, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['unc3886', 'zero-day'], context: { actor_ids: ['actor-unc3886'], campaign_ids: [], malware_families: ['REPTILE'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0002-0001-0001-000000000006', kill_chain_phases: ['delivery', 'installation'], hit_count: 1, last_hit_at: '2026-03-24T10:00:00Z', enrichments: {} },
    // 4 URLs
    { ioc_id: 'ioc-015', type: 'url', value: 'https://microsoftonline-auth.com/oauth2/authorize?client_id=stolen', source_feed_id: 'feed-crowdstrike', first_seen: '2026-03-20T00:00:00Z', last_seen: '2026-03-28T14:22:00Z', expiration: '2026-04-20T00:00:00Z', confidence: 98, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['apt29', 'credential-harvest', 'oauth-abuse'], context: { actor_ids: ['actor-apt29'], campaign_ids: ['camp-midnight'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0003-0001-0001-000000000001', kill_chain_phases: ['delivery', 'exploitation'], hit_count: 8, last_hit_at: '2026-03-28T09:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-016', type: 'url', value: 'https://updates-check-service.net/api/v2/download?payload=enc', source_feed_id: 'feed-mandiant', first_seen: '2026-02-15T00:00:00Z', last_seen: '2026-03-15T09:45:00Z', expiration: '2026-05-15T00:00:00Z', confidence: 85, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['apt41', 'malware-delivery'], context: { actor_ids: ['actor-apt41'], campaign_ids: ['camp-volt'], malware_families: ['ShadowPad'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0003-0001-0001-000000000002', kill_chain_phases: ['delivery'], hit_count: 2, last_hit_at: '2026-03-10T14:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-017', type: 'url', value: 'https://blockchain-verify.io/wallet/connect?ref=airdrop', source_feed_id: 'feed-otx', first_seen: '2026-03-10T00:00:00Z', last_seen: '2026-03-20T11:30:00Z', expiration: '2026-04-10T00:00:00Z', confidence: 80, severity: 'high', status: 'active', tlp: 'TLP:GREEN', tags: ['lazarus', 'crypto-drain'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0003-0001-0001-000000000003', kill_chain_phases: ['delivery'], hit_count: 22, last_hit_at: '2026-03-19T18:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-018', type: 'url', value: 'https://secure-payment-portal.com/checkout/process.php', source_feed_id: 'feed-urlhaus', first_seen: '2026-02-28T00:00:00Z', last_seen: '2026-03-18T10:00:00Z', expiration: '2026-05-28T00:00:00Z', confidence: 72, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['fin7', 'skimmer'], context: { actor_ids: ['actor-fin7'], campaign_ids: [], malware_families: ['Magecart'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0003-0001-0001-000000000004', kill_chain_phases: ['actions-on-objectives'], hit_count: 0, last_hit_at: null, enrichments: {} },
    // 6 SHA256 hashes
    { ioc_id: 'ioc-019', type: 'sha256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', source_feed_id: 'feed-cisa', first_seen: '2026-01-25T00:00:00Z', last_seen: '2026-03-10T08:15:00Z', expiration: null, confidence: 100, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['sandworm', 'caddywiper'], context: { actor_ids: ['actor-sandworm'], campaign_ids: [], malware_families: ['CaddyWiper'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000001', kill_chain_phases: ['installation', 'actions-on-objectives'], hit_count: 0, last_hit_at: null, enrichments: {} },
    { ioc_id: 'ioc-020', type: 'sha256', value: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', source_feed_id: 'feed-mandiant', first_seen: '2026-03-05T00:00:00Z', last_seen: '2026-03-25T13:00:00Z', expiration: null, confidence: 89, severity: 'high', status: 'active', tlp: 'TLP:AMBER', tags: ['unc3886', 'reptile-rootkit'], context: { actor_ids: ['actor-unc3886'], campaign_ids: [], malware_families: ['REPTILE'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000002', kill_chain_phases: ['installation'], hit_count: 1, last_hit_at: '2026-03-24T09:30:00Z', enrichments: {} },
    { ioc_id: 'ioc-021', type: 'sha256', value: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592', source_feed_id: 'feed-crowdstrike', first_seen: '2026-03-12T00:00:00Z', last_seen: '2026-03-20T11:30:00Z', expiration: null, confidence: 94, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['lazarus', 'applejeus'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: ['AppleJeus'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000003', kill_chain_phases: ['delivery', 'installation'], hit_count: 4, last_hit_at: '2026-03-19T14:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-022', type: 'sha256', value: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', source_feed_id: 'feed-urlhaus', first_seen: '2026-03-01T00:00:00Z', last_seen: '2026-03-28T06:00:00Z', expiration: null, confidence: 76, severity: 'high', status: 'active', tlp: 'TLP:GREEN', tags: ['ransomware', 'lockbit'], context: { actor_ids: [], campaign_ids: ['camp-lockbit'], malware_families: ['LockBit 4.0'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000004', kill_chain_phases: ['installation', 'actions-on-objectives'], hit_count: 7, last_hit_at: '2026-03-27T22:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-023', type: 'sha256', value: '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce', source_feed_id: 'feed-misp', first_seen: '2026-02-18T00:00:00Z', last_seen: '2026-03-22T10:00:00Z', expiration: null, confidence: 70, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['infostealer', 'raccoon'], context: { actor_ids: [], campaign_ids: [], malware_families: ['Raccoon Stealer'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000005', kill_chain_phases: ['installation'], hit_count: 2, last_hit_at: '2026-03-20T08:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-024', type: 'sha256', value: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d', source_feed_id: 'feed-shadowserver', first_seen: '2026-03-18T00:00:00Z', last_seen: '2026-03-28T04:00:00Z', expiration: null, confidence: 65, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['botnet', 'mirai-variant'], context: { actor_ids: [], campaign_ids: [], malware_families: ['Mirai'], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0004-0001-0001-000000000006', kill_chain_phases: ['installation'], hit_count: 31, last_hit_at: '2026-03-28T03:45:00Z', enrichments: {} },
    // 3 emails
    { ioc_id: 'ioc-025', type: 'email', value: 'it-helpdesk@microsoftonline-auth.com', source_feed_id: 'feed-crowdstrike', first_seen: '2026-03-20T00:00:00Z', last_seen: '2026-03-28T14:22:00Z', expiration: '2026-04-20T00:00:00Z', confidence: 96, severity: 'critical', status: 'active', tlp: 'TLP:AMBER', tags: ['apt29', 'phishing-sender'], context: { actor_ids: ['actor-apt29'], campaign_ids: ['camp-midnight'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0005-0001-0001-000000000001', kill_chain_phases: ['delivery'], hit_count: 14, last_hit_at: '2026-03-28T08:30:00Z', enrichments: {} },
    { ioc_id: 'ioc-026', type: 'email', value: 'support@blockchain-verify.io', source_feed_id: 'feed-otx', first_seen: '2026-03-10T00:00:00Z', last_seen: '2026-03-20T11:30:00Z', expiration: '2026-04-10T00:00:00Z', confidence: 82, severity: 'high', status: 'active', tlp: 'TLP:GREEN', tags: ['lazarus', 'social-engineering'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0005-0001-0001-000000000002', kill_chain_phases: ['delivery'], hit_count: 6, last_hit_at: '2026-03-18T10:00:00Z', enrichments: {} },
    { ioc_id: 'ioc-027', type: 'email', value: 'billing@secure-payment-portal.com', source_feed_id: 'feed-urlhaus', first_seen: '2026-02-28T00:00:00Z', last_seen: '2026-03-15T10:00:00Z', expiration: '2026-05-28T00:00:00Z', confidence: 70, severity: 'medium', status: 'active', tlp: 'TLP:GREEN', tags: ['fin7', 'social-engineering'], context: { actor_ids: ['actor-fin7'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0005-0001-0001-000000000003', kill_chain_phases: ['delivery'], hit_count: 1, last_hit_at: '2026-03-12T14:00:00Z', enrichments: {} },
    // 3 CVEs
    { ioc_id: 'ioc-028', type: 'cve', value: 'CVE-2024-21338', source_feed_id: 'feed-cisa', first_seen: '2024-02-13T00:00:00Z', last_seen: '2026-03-28T00:00:00Z', expiration: null, confidence: 100, severity: 'critical', status: 'active', tlp: 'TLP:GREEN', tags: ['kev', 'windows-kernel', 'privilege-escalation'], context: { actor_ids: ['actor-lazarus'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0006-0001-0001-000000000001', kill_chain_phases: ['exploitation'], hit_count: 0, last_hit_at: null, enrichments: {} },
    { ioc_id: 'ioc-029', type: 'cve', value: 'CVE-2024-3400', source_feed_id: 'feed-cisa', first_seen: '2024-04-12T00:00:00Z', last_seen: '2026-03-28T00:00:00Z', expiration: null, confidence: 100, severity: 'critical', status: 'active', tlp: 'TLP:GREEN', tags: ['kev', 'palo-alto', 'pan-os', 'command-injection'], context: { actor_ids: ['actor-apt41', 'actor-unc3886'], campaign_ids: ['camp-volt'], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0006-0001-0001-000000000002', kill_chain_phases: ['exploitation'], hit_count: 0, last_hit_at: null, enrichments: {} },
    { ioc_id: 'ioc-030', type: 'cve', value: 'CVE-2023-46805', source_feed_id: 'feed-cisa', first_seen: '2024-01-10T00:00:00Z', last_seen: '2026-03-28T00:00:00Z', expiration: null, confidence: 100, severity: 'critical', status: 'active', tlp: 'TLP:GREEN', tags: ['kev', 'ivanti', 'connect-secure', 'auth-bypass'], context: { actor_ids: ['actor-unc3886'], campaign_ids: [], malware_families: [], cve_ids: [] }, stix_id: 'indicator--a1b2c3d4-0006-0001-0001-000000000003', kill_chain_phases: ['initial-access'], hit_count: 0, last_hit_at: null, enrichments: {} },
  ];
  for (const i of iocs) engine.ioc.add(i);

  // ── 3 Campaigns ──
  const campaigns: Campaign[] = [
    {
      campaign_id: 'camp-midnight', name: 'Operation Midnight Blizzard', description: 'APT29 campaign targeting government email systems via device code phishing and OAuth application abuse. Focus on Microsoft 365 tenants of NATO government organizations.',
      status: 'active', actor_ids: ['actor-apt29'], ioc_ids: ['ioc-001', 'ioc-002', 'ioc-009', 'ioc-015', 'ioc-025'], ttp_ids: ['T1566.001', 'T1059.001', 'T1071.001'], kill_chain_phase: 'exploitation',
      first_activity: '2026-01-15T00:00:00Z', last_activity: '2026-03-28T14:22:00Z', targeted_sectors: ['Government', 'Defense', 'Diplomacy'], affected_asset_count: 47, confidence: 92,
      stix_id: 'campaign--b1c2d3e4-0001-0001-0001-000000000001',
      timeline: [
        { timestamp: '2026-01-15T08:00:00Z', event_type: 'Initial phishing wave', description: 'First phishing emails sent to 200+ government employees using device code phishing technique', ioc_ids: ['ioc-025', 'ioc-009'], mitre_technique_id: 'T1566.001' },
        { timestamp: '2026-02-01T10:00:00Z', event_type: 'OAuth app registration', description: 'Malicious OAuth applications registered in compromised tenants for persistent access', ioc_ids: ['ioc-015'], mitre_technique_id: 'T1550.001' },
        { timestamp: '2026-02-15T14:00:00Z', event_type: 'C2 infrastructure expanded', description: 'New C2 servers deployed for data exfiltration from compromised mailboxes', ioc_ids: ['ioc-001', 'ioc-002'], mitre_technique_id: 'T1071.001' },
        { timestamp: '2026-03-15T09:00:00Z', event_type: 'Second phishing wave', description: 'Expanded targeting to include additional government agencies and think tanks', ioc_ids: ['ioc-025', 'ioc-009'], mitre_technique_id: 'T1566.001' },
        { timestamp: '2026-03-28T14:22:00Z', event_type: 'Active exfiltration detected', description: 'Ongoing data exfiltration from 12 compromised mailboxes detected by OSEF event correlation', ioc_ids: ['ioc-001'], mitre_technique_id: 'T1048' },
      ],
    },
    {
      campaign_id: 'camp-volt', name: 'Volt Typhoon Infrastructure Pre-positioning', description: 'Chinese state-sponsored campaign pre-positioning access in critical infrastructure networks. Living-off-the-land techniques to avoid detection. Focus on telecommunications and energy sectors.',
      status: 'active', actor_ids: ['actor-apt41'], ioc_ids: ['ioc-004', 'ioc-005', 'ioc-010', 'ioc-016', 'ioc-029'], ttp_ids: ['T1190', 'T1505.003', 'T1059.003'], kill_chain_phase: 'installation',
      first_activity: '2025-06-01T00:00:00Z', last_activity: '2026-03-15T09:45:00Z', targeted_sectors: ['Critical Infrastructure', 'Telecommunications', 'Energy'], affected_asset_count: 23, confidence: 85,
      stix_id: 'campaign--b1c2d3e4-0001-0001-0001-000000000002',
      timeline: [
        { timestamp: '2025-06-01T00:00:00Z', event_type: 'Initial exploitation', description: 'Exploitation of Palo Alto PAN-OS CVE-2024-3400 on perimeter firewalls', ioc_ids: ['ioc-029'], mitre_technique_id: 'T1190' },
        { timestamp: '2025-09-15T00:00:00Z', event_type: 'Web shell deployment', description: 'BEHINDER web shells installed on compromised web servers', ioc_ids: ['ioc-004'], mitre_technique_id: 'T1505.003' },
        { timestamp: '2026-01-20T00:00:00Z', event_type: 'C2 infrastructure rotation', description: 'New C2 domains and IPs deployed to maintain persistence', ioc_ids: ['ioc-005', 'ioc-010'], mitre_technique_id: 'T1071.001' },
        { timestamp: '2026-03-15T09:45:00Z', event_type: 'Lateral movement detected', description: 'Living-off-the-land techniques used to move to OT-adjacent network segments', ioc_ids: ['ioc-005'], mitre_technique_id: 'T1059.003' },
      ],
    },
    {
      campaign_id: 'camp-lockbit', name: 'LockBit 4.0 Affiliate Campaign', description: 'Multi-actor ransomware campaign using LockBit 4.0 affiliate program. Targeting healthcare and financial sectors with double extortion (encryption + data theft).',
      status: 'active', actor_ids: [], ioc_ids: ['ioc-022'], ttp_ids: ['T1486', 'T1490', 'T1567'], kill_chain_phase: 'actions-on-objectives',
      first_activity: '2026-02-01T00:00:00Z', last_activity: '2026-03-28T06:00:00Z', targeted_sectors: ['Healthcare', 'Financial Services'], affected_asset_count: 156, confidence: 78,
      stix_id: 'campaign--b1c2d3e4-0001-0001-0001-000000000003',
      timeline: [
        { timestamp: '2026-02-01T00:00:00Z', event_type: 'Campaign launch', description: 'LockBit 4.0 affiliate program launches with updated encryption and new data leak site', ioc_ids: [], mitre_technique_id: 'T1486' },
        { timestamp: '2026-02-15T00:00:00Z', event_type: 'Healthcare targeting begins', description: 'Multiple hospital systems targeted via VPN credential stuffing', ioc_ids: ['ioc-022'], mitre_technique_id: 'T1110.004' },
        { timestamp: '2026-03-10T00:00:00Z', event_type: 'Data leak site posts', description: '12 victim organizations posted to LockBit data leak site', ioc_ids: [], mitre_technique_id: 'T1567' },
        { timestamp: '2026-03-28T06:00:00Z', event_type: 'New variant detected', description: 'Updated ransomware binary with improved evasion capabilities', ioc_ids: ['ioc-022'], mitre_technique_id: 'T1486' },
      ],
    },
  ];
  for (const c of campaigns) engine.addCampaign(c);

  // ── 8 Dark Web Mentions ──
  const mentions: DarkWebMention[] = [
    { mention_id: 'dw-001', type: 'credential_leak', source_platform: 'BreachForums', source_url_hash: 'a1b2c3d4e5f6', discovered_at: '2026-03-25T02:30:00Z', content_snippet: '[FRESH] 1,247 email:password combos from acellc.ai domain — scraped from infostealer logs — verified 03/2026', matched_keywords: ['acellc.ai'], matched_assets: ['acellc.ai'], severity: 'critical', status: 'investigating', credential_count: 1247, affected_domains: ['acellc.ai', 'mail.acellc.ai'] },
    { mention_id: 'dw-002', type: 'credential_leak', source_platform: 'Telegram', source_url_hash: 'b2c3d4e5f6a7', discovered_at: '2026-03-20T18:45:00Z', content_snippet: 'Combo list update — includes corporate credentials from .gov and .mil adjacent contractors', matched_keywords: ['contractor', 'credentials'], matched_assets: ['acellc.ai'], severity: 'high', status: 'confirmed', credential_count: 89, affected_domains: ['acellc.ai'] },
    { mention_id: 'dw-003', type: 'brand_mention', source_platform: 'Dark0de Reborn', source_url_hash: 'c3d4e5f6a7b8', discovered_at: '2026-03-22T11:00:00Z', content_snippet: 'Selling phishing kit for ACE LLC / OVERSEER — clone login page + credential harvester + admin panel', matched_keywords: ['ACE', 'OVERSEER', 'phishing'], matched_assets: ['overseer.acellc.ai'], severity: 'high', status: 'new' },
    { mention_id: 'dw-004', type: 'executive_mention', source_platform: 'XSS.is', source_url_hash: 'd4e5f6a7b8c9', discovered_at: '2026-03-18T06:15:00Z', content_snippet: 'Looking for social media profiles and personal emails for cybersecurity company executives — targeting list includes defense contractors', matched_keywords: ['cybersecurity', 'executives', 'defense'], matched_assets: [], severity: 'medium', status: 'investigating', actor_attribution: 'Unknown' },
    { mention_id: 'dw-005', type: 'domain_mention', source_platform: 'Exploit.in', source_url_hash: 'e5f6a7b8c9d0', discovered_at: '2026-03-15T23:00:00Z', content_snippet: 'Discussion: bypassing zero-trust appliance vendors — thread mentions OVERSEER sensor hub architecture', matched_keywords: ['OVERSEER', 'zero-trust', 'sensor'], matched_assets: ['overseer.acellc.ai'], severity: 'medium', status: 'new' },
    { mention_id: 'dw-006', type: 'domain_mention', source_platform: 'RaidForums Revival', source_url_hash: 'f6a7b8c9d0e1', discovered_at: '2026-03-12T14:20:00Z', content_snippet: 'Subdomain enum results for acellc.ai — api.acellc.ai, portal.acellc.ai, staging.acellc.ai — scanning for exposed endpoints', matched_keywords: ['acellc.ai', 'subdomain'], matched_assets: ['api.acellc.ai', 'portal.acellc.ai', 'staging.acellc.ai'], severity: 'high', status: 'confirmed' },
    { mention_id: 'dw-007', type: 'data_sale', source_platform: 'BreachForums', source_url_hash: 'a7b8c9d0e1f2', discovered_at: '2026-03-08T09:30:00Z', content_snippet: '[WTS] Database dump from small cybersecurity consultancy — 15K client records with contact details and project info', matched_keywords: ['cybersecurity', 'database', 'client'], matched_assets: [], severity: 'medium', status: 'false_positive' },
    { mention_id: 'dw-008', type: 'vulnerability_discussion', source_platform: 'Telegram', source_url_hash: 'b8c9d0e1f2a3', discovered_at: '2026-03-27T20:00:00Z', content_snippet: '0-day in Fortinet SSL VPN — pre-auth RCE — working on stable exploit — will sell to highest bidder after 72h', matched_keywords: ['Fortinet', 'VPN', '0-day'], matched_assets: [], severity: 'critical', status: 'new' },
  ];
  for (const m of mentions) engine.darkweb.addMention(m);

  // Watchlist entries
  const watchlist: WatchlistEntry[] = [
    { entry_id: 'wl-001', type: 'domain', value: 'acellc.ai', added_at: '2026-01-01T00:00:00Z', enabled: true },
    { entry_id: 'wl-002', type: 'domain', value: 'overseer.acellc.ai', added_at: '2026-01-01T00:00:00Z', enabled: true },
    { entry_id: 'wl-003', type: 'brand', value: 'OVERSEER', added_at: '2026-01-01T00:00:00Z', enabled: true },
    { entry_id: 'wl-004', type: 'brand', value: 'ACE LLC', added_at: '2026-01-01T00:00:00Z', enabled: true },
    { entry_id: 'wl-005', type: 'keyword', value: 'advanced cybersecurity experts', added_at: '2026-01-15T00:00:00Z', enabled: true },
    { entry_id: 'wl-006', type: 'email', value: '@acellc.ai', added_at: '2026-01-01T00:00:00Z', enabled: true },
  ];
  for (const w of watchlist) engine.darkweb.addToWatchlist(w);

  // ── 5 Enriched Alerts (pre-seeded) ──
  const alerts: EnrichedAlert[] = [
    {
      alert_id: 'alert-demo-001', original_event_id: 'osef-net-8847291', original_event_type: 'network.connection',
      matched_ioc: iocs[0], // APT29 C2 IP
      threat_context: { actors: [actors[0]], campaigns: [campaigns[0]], related_iocs: [iocs[1], iocs[8]], kill_chain_position: 'command-and-control' },
      match_confidence: 95, auto_enriched_at: '2026-03-28T10:15:00Z',
      recommended_actions: ['Block IP 185.220.101.34 at network perimeter', 'Check for lateral movement', 'Review APT29 TTP profile', 'Escalate to SOC Tier 3 — nation-state actor', 'Initiate incident response procedure'],
      correlation_id: 'corr-a1b2c3d4', pillar: 'networks',
    },
    {
      alert_id: 'alert-demo-002', original_event_id: 'osef-id-3312847', original_event_type: 'identity.credential_stuffing',
      matched_ioc: iocs[24], // Phishing sender email
      threat_context: { actors: [actors[0]], campaigns: [campaigns[0]], related_iocs: [iocs[14]], kill_chain_position: 'delivery' },
      match_confidence: 96, auto_enriched_at: '2026-03-28T08:30:00Z',
      recommended_actions: ['Block sender in email gateway', 'Search mailboxes for prior messages', 'Review APT29 TTP profile', 'Escalate to SOC Tier 3 — nation-state actor'],
      correlation_id: 'corr-b2c3d4e5', pillar: 'identity',
    },
    {
      alert_id: 'alert-demo-003', original_event_id: 'osef-dev-5591023', original_event_type: 'device.malware_detected',
      matched_ioc: iocs[20], // Lazarus AppleJeus hash
      threat_context: { actors: [actors[2]], campaigns: [], related_iocs: [iocs[5], iocs[10]], kill_chain_position: 'installation' },
      match_confidence: 94, auto_enriched_at: '2026-03-19T14:00:00Z',
      recommended_actions: ['Quarantine matching files on endpoints', 'Run full endpoint scan', 'Review Lazarus Group TTP profile', 'Escalate to SOC Tier 3 — nation-state actor', 'Initiate incident response procedure'],
      correlation_id: 'corr-c3d4e5f6', pillar: 'devices',
    },
    {
      alert_id: 'alert-demo-004', original_event_id: 'osef-net-7723156', original_event_type: 'network.dns_query',
      matched_ioc: iocs[10], // Lazarus crypto-phishing domain
      threat_context: { actors: [actors[2]], campaigns: [], related_iocs: [iocs[16]], kill_chain_position: 'delivery' },
      match_confidence: 82, auto_enriched_at: '2026-03-19T16:20:00Z',
      recommended_actions: ['Add domain blockchain-verify.io to DNS sinkhole', 'Check proxy logs for historical connections', 'Review Lazarus Group TTP profile'],
      correlation_id: 'corr-d4e5f6a7', pillar: 'networks',
    },
    {
      alert_id: 'alert-demo-005', original_event_id: 'osef-app-9912483', original_event_type: 'application.url_access',
      matched_ioc: iocs[15], // APT41 malware delivery URL
      threat_context: { actors: [actors[1]], campaigns: [campaigns[1]], related_iocs: [iocs[3], iocs[9]], kill_chain_position: 'delivery' },
      match_confidence: 85, auto_enriched_at: '2026-03-10T14:00:00Z',
      recommended_actions: ['Add domain updates-check-service.net to DNS sinkhole', 'Check proxy logs', 'Review APT41 TTP profile', 'Escalate to SOC Tier 3 — nation-state actor'],
      correlation_id: 'corr-e5f6a7b8', pillar: 'applications',
    },
  ];
  for (const a of alerts) engine.enrichment.addAlert(a);

  // Seed some STIX objects into the default collection
  const stixObjects = [];
  for (const ioc of iocs.slice(0, 10)) {
    stixObjects.push(...engine.stix.iocToStix(ioc));
  }
  for (const actor of actors) {
    stixObjects.push(engine.stix.actorToStix(actor));
  }
  for (const campaign of campaigns) {
    stixObjects.push(engine.stix.campaignToStix(campaign));
  }
  engine.stix.addToCollection('col-default', stixObjects);
}
