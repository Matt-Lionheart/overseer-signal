// ═══════════════════════════════════════════════════════════════
// S.I.G.N.A.L. — Dark Web Monitor
// Watchlist management, mention detection, credential leak tracking
// ═══════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto';
import type { DarkWebMention, WatchlistEntry, MentionType, MentionStatus, Severity } from './signal-types.js';

export class DarkWebMonitor {
  private mentions = new Map<string, DarkWebMention>();
  private watchlist = new Map<string, WatchlistEntry>();

  // ── Watchlist Management ──

  addToWatchlist(entry: WatchlistEntry): void {
    this.watchlist.set(entry.entry_id, entry);
  }

  removeFromWatchlist(entryId: string): boolean {
    return this.watchlist.delete(entryId);
  }

  getWatchlist(): WatchlistEntry[] {
    return Array.from(this.watchlist.values());
  }

  // ── Mention Management ──

  addMention(mention: DarkWebMention): void {
    this.mentions.set(mention.mention_id, mention);
  }

  getMention(mentionId: string): DarkWebMention | undefined {
    return this.mentions.get(mentionId);
  }

  updateMentionStatus(mentionId: string, status: MentionStatus): boolean {
    const mention = this.mentions.get(mentionId);
    if (!mention) return false;
    mention.status = status;
    return true;
  }

  listMentions(filters?: { type?: MentionType; severity?: Severity; status?: MentionStatus }): DarkWebMention[] {
    let results = Array.from(this.mentions.values());
    if (filters?.type) results = results.filter(m => m.type === filters.type);
    if (filters?.severity) results = results.filter(m => m.severity === filters.severity);
    if (filters?.status) results = results.filter(m => m.status === filters.status);
    return results.sort((a, b) => b.discovered_at.localeCompare(a.discovered_at));
  }

  // Mentions from last N days
  recentMentions(days: number): DarkWebMention[] {
    const cutoff = new Date(Date.now() - days * 86400000).toISOString();
    return Array.from(this.mentions.values())
      .filter(m => m.discovered_at >= cutoff)
      .sort((a, b) => b.discovered_at.localeCompare(a.discovered_at));
  }

  // Total credential count from all confirmed leaks
  get totalCredentialsExposed(): number {
    return Array.from(this.mentions.values())
      .filter(m => m.type === 'credential_leak' && m.status !== 'false_positive')
      .reduce((sum, m) => sum + (m.credential_count ?? 0), 0);
  }

  get mentionCount(): number { return this.mentions.size; }
  get watchlistCount(): number { return this.watchlist.size; }
}
