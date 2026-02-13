/**
 * Dashboard Generator - Produces clean JSON for CTI visualization
 * Output designed for public dashboard consumption
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { ProcessedData, LLMAnalysisResult, ThreatSeverity, ThreatCategory, DataSource, EvidenceLink, CorrelationSignal, ShodanScrapedData, XScrapedData } from '../types/index.js';
import { CTIAnalysis } from '../llm/cti-agents-v2.js';

// Frontend-optimized dashboard format with evidence and correlation
export interface PublicDashboard {
  meta: {
    version: string;
    generatedAt: string;
    validUntil: string;
  };
  status: {
    riskLevel: 'critical' | 'elevated' | 'moderate' | 'low';
    riskScore: number; // 0-100
    trend: 'increasing' | 'stable' | 'decreasing';
    confidenceLevel: number;
  };
  executive: {
    headline: string;
    summary: string;
    keyFindings: string[];
    recommendedActions: string[];
  };
  metrics: {
    totalSignals: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    categories: Array<{ name: string; count: number; percentage: number }>;
  };
  timeline: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    timestamp: string;
    sourceUrl?: string;
  }>;
  sources: Array<{
    name: string;
    signalCount: number;
    lastUpdate: string;
  }>;
  indicators: {
    cves: string[];
    domains: string[];
    ips: string[];
    keywords: string[];
  };
  // NEW: Cross-source correlation with evidence
  correlation?: {
    insight: string;
    pattern: 'infra-first' | 'social-first' | 'simultaneous' | 'insufficient-data';
    signals: Array<{
      id: string;
      label: string;
      infraCount: number;
      socialCount: number;
      timeDeltaHours: number | null;
      interpretation: string;
      evidence: {
        infrastructure: EvidenceLink[];
        social: EvidenceLink[];
      };
    }>;
  };
  // NEW: Infrastructure exposure summary
  infrastructure?: {
    totalHosts: number;
    exposedPorts: Array<{
      port: number;
      service: string;
      count: number;
      percentage: number;
    }>;
    topCountries: Array<{
      country: string;
      count: number;
    }>;
    vulnerableHosts: number;
    sampleHosts: Array<{
      ip: string;
      port: number;
      service: string;
      vulns: string[];
    }>;
  };
  // NEW: Social intelligence summary
  socialIntel?: {
    totalPosts: number;
    topTopics: Array<{
      topic: string;
      count: number;
      engagement: number;
    }>;
    recentPosts: Array<{
      excerpt: string;
      author: string;
      timestamp: string;
      engagement: number;
      url: string;
    }>;
    sentiment: 'alarming' | 'neutral' | 'informational';
  };
  // NEW: Multi-agent CTI analysis results
  ctiAnalysis?: {
    model: string;
    killChainPhase: string;
    threatLandscape: string;
    mitreAttack: Array<{
      tactic: string;
      techniques: string[];
      mitigations: string[];
    }>;
    keyFindings: Array<{
      finding: string;
      severity: string;
      evidence: string;
      recommendation: string;
    }>;
    ttps: Array<{
      technique: string;
      techniqueId: string;
      tactic: string;
      evidence: string;
      confidence: number;
    }>;
    temporalPatterns: Array<{
      pattern: string;
      description: string;
      timeframe: string;
      confidence: number;
      evidence: Array<{ source: string; excerpt: string; url: string }>;
    }>;
    crossSourceLinks: Array<{
      infraSignal: string;
      socialSignal: string;
      relationship: string;
      timeDelta: string;
      significance: string;
    }>;
    immediateActions: string[];
    strategicRecommendations: string[];
    sourcesAndReferences: Array<{
      source: string;
      url: string;
      relevance: string;
    }>;
  };
}

export class DashboardGenerator {
  private outputDir: string;
  private publicDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
    this.publicDir = process.env.CTI_PUBLIC_DIR || './eccentric-equator/public/data';
  }

  async generate(): Promise<PublicDashboard> {
    console.log('[Dashboard] Generating CTI dashboard...');
    
    const processedData = await this.loadJson<ProcessedData>('processed-data.json');
    const llmAnalysis = await this.loadJson<LLMAnalysisResult>('llm-analysis.json');
    // Load raw source data for detailed sections
    const shodanData = await this.loadJson<ShodanScrapedData>('shodan-data.json');
    const xData = await this.loadJson<XScrapedData>('x-data.json');
    // Load multi-agent CTI analysis if available
    const ctiAnalysis = await this.loadJson<CTIAnalysis>('cti-analysis.json');

    const dashboard = this.buildDashboard(processedData, llmAnalysis, shodanData, xData, ctiAnalysis);
    
    await this.saveDashboard(dashboard);
    console.log(`[Dashboard] Generated - Risk: ${dashboard.status.riskLevel}, Signals: ${dashboard.metrics.totalSignals}`);
    if (ctiAnalysis) {
      console.log(`[Dashboard] CTI Analysis: ${ctiAnalysis.analysis.keyFindings.length} findings, ${ctiAnalysis.extraction.ttps.length} TTPs`);
    }
    
    return dashboard;
  }

  private buildDashboard(
    data: ProcessedData | null, 
    llm: LLMAnalysisResult | null,
    shodanData?: ShodanScrapedData | null,
    xData?: XScrapedData | null,
    ctiAnalysis?: CTIAnalysis | null
  ): PublicDashboard {
    const now = new Date();
    const validUntil = new Date(now.getTime() + 6 * 60 * 60 * 1000); // 6 hours validity

    if (!data || data.threats.length === 0) {
      return this.buildEmptyDashboard(now, validUntil);
    }

    const { summary, threats, indicators } = data;
    const totalThreats = summary.totalThreats || threats.length;
    
    // Calculate risk metrics
    const criticalCount = summary.bySeverity?.[ThreatSeverity.CRITICAL] || 0;
    const highCount = summary.bySeverity?.[ThreatSeverity.HIGH] || 0;
    const mediumCount = summary.bySeverity?.[ThreatSeverity.MEDIUM] || 0;
    const lowCount = summary.bySeverity?.[ThreatSeverity.LOW] || 0;
    
    const riskScore = this.calculateRiskScore(criticalCount, highCount, mediumCount, lowCount);
    const riskLevel = this.determineRiskLevel(riskScore);

    // Build executive summary
    const executive = this.buildExecutiveSummary(data, llm, riskLevel);

    // Build category breakdown
    const categories = Object.entries(summary.byCategory || {})
      .filter(([_, count]) => count > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({
        name: this.formatCategory(name),
        count,
        percentage: Math.round((count / totalThreats) * 100)
      }));

    // Build sources list
    const sources = Object.entries(summary.bySource || {})
      .filter(([_, count]) => count > 0)
      .map(([name, count]) => ({
        name: this.formatSource(name),
        signalCount: count,
        lastUpdate: now.toISOString()
      }));

    // Spam patterns for filtering timeline
    const spamPatterns = [
      /quiz\s*time/i,
      /what\s+is\s+.*\?\s*[A-D]\)/i,
      /^\d+[A-Za-z]+\s+\w+\d+/i,
      /fusion\s*mix/i,
      /one-day\s*fusion/i,
    ];
    const isSpamTitle = (title: string) => spamPatterns.some(p => p.test(title));

    // Build timeline (top 8 threats, filtered for spam)
    const timeline = threats
      .filter(t => !isSpamTitle(t.title))
      .slice(0, 8)
      .map(t => ({
        id: t.id,
        title: this.sanitizeTitle(t.title),
        severity: t.severity,
        category: this.formatCategory(t.category),
        timestamp: t.timestamp
      }));

    // Extract indicators for display
    const displayIndicators = this.extractDisplayIndicators(indicators);

    // Calculate confidence based on data quality
    const confidenceLevel = this.calculateConfidence(data, llm);

    // Build correlation section with evidence
    const correlation = this.buildCorrelationSection(data);

    // Build infrastructure and social intel sections
    const infrastructure = this.buildInfrastructureSection(shodanData);
    const socialIntel = this.buildSocialIntelSection(xData);

    // Build CTI analysis section from multi-agent system
    const ctiAnalysisSection = this.buildCTIAnalysisSection(ctiAnalysis);

    // If CTI analysis is available, enhance executive summary
    const enhancedExecutive = ctiAnalysis 
      ? this.enhanceExecutiveWithCTI(executive, ctiAnalysis)
      : executive;

    // Use CTI analysis risk assessment if available, mapping CTI levels to dashboard levels
    const finalRiskScore = ctiAnalysis?.analysis.riskScore ?? riskScore;
    const ctiLevel = ctiAnalysis?.analysis.riskLevel;
    const mappedLevel = ctiLevel 
      ? { critical: 'critical', high: 'elevated', medium: 'moderate', low: 'low' }[ctiLevel] as 'critical' | 'elevated' | 'moderate' | 'low'
      : null;
    const finalRiskLevel = mappedLevel ?? riskLevel;

    return {
      meta: {
        version: '2.0.0',
        generatedAt: now.toISOString(),
        validUntil: validUntil.toISOString()
      },
      status: {
        riskLevel: finalRiskLevel,
        riskScore: finalRiskScore,
        trend: this.determineTrend(threats),
        confidenceLevel
      },
      executive: enhancedExecutive,
      metrics: {
        totalSignals: totalThreats,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        categories
      },
      timeline,
      sources,
      indicators: displayIndicators,
      correlation,
      infrastructure,
      socialIntel,
      ctiAnalysis: ctiAnalysisSection
    };
  }

  /**
   * Build CTI analysis section from analysis system v2 with temporal correlation
   */
  private buildCTIAnalysisSection(ctiAnalysis?: CTIAnalysis | null): PublicDashboard['ctiAnalysis'] | undefined {
    if (!ctiAnalysis) return undefined;

    // Group TTPs by tactic for MITRE mapping
    const tacticMap = new Map<string, string[]>();
    for (const ttp of ctiAnalysis.extraction.ttps) {
      const techniques = tacticMap.get(ttp.tactic) || [];
      techniques.push(`${ttp.id}: ${ttp.name}`);
      tacticMap.set(ttp.tactic, techniques);
    }

    // Build temporal patterns from correlation analysis
    type TemporalPattern = {
      pattern: string;
      description: string;
      timeframe: string;
      confidence: number;
      evidence: Array<{ source: string; excerpt: string; url: string }>;
    };
    const temporalPatterns: TemporalPattern[] = [];
    if (ctiAnalysis.correlation) {
      // Add main correlation narrative as pattern
      if (ctiAnalysis.correlation.narrative) {
        temporalPatterns.push({
          pattern: `${ctiAnalysis.correlation.pattern.toUpperCase()} correlation detected`,
          description: ctiAnalysis.correlation.narrative,
          timeframe: ctiAnalysis.correlation.timeWindow,
          confidence: ctiAnalysis.correlation.confidence / 100,
          evidence: ctiAnalysis.extraction.timelineEvents?.slice(0, 3).map(e => ({
            source: e.source === 'x.com' ? 'X.com' : 'Shodan',
            excerpt: e.description,
            url: ''
          })) || []
        });
      }
      
      // Add emerging threats as patterns
      for (const threat of ctiAnalysis.correlation.emergingThreats || []) {
        temporalPatterns.push({
          pattern: 'Emerging Threat',
          description: threat,
          timeframe: 'Active',
          confidence: 0.7,
          evidence: []
        });
      }
    }

    // Build cross-source links from correlation
    type CrossSourceLink = {
      infraSignal: string;
      socialSignal: string;
      relationship: string;
      timeDelta: string;
      significance: string;
    };
    const crossSourceLinks: CrossSourceLink[] = [];
    if (ctiAnalysis.correlation?.keyCorrelations) {
      for (const corr of ctiAnalysis.correlation.keyCorrelations) {
        crossSourceLinks.push({
          infraSignal: corr.infraEvent,
          socialSignal: corr.socialEvent,
          relationship: ctiAnalysis.correlation.pattern,
          timeDelta: corr.timeDelta,
          significance: corr.significance
        });
      }
    }
    
    // Fallback if no correlations found
    if (crossSourceLinks.length === 0 && ctiAnalysis.extraction.socialPosts.length > 0) {
      crossSourceLinks.push(...ctiAnalysis.extraction.socialPosts.slice(0, 3).map(p => ({
        infraSignal: ctiAnalysis.extraction.ips[0]?.service || 'Network exposure',
        socialSignal: `${p.author}: ${p.text.substring(0, 50)}...`,
        relationship: 'Concurrent activity',
        timeDelta: 'Within analysis window',
        significance: 'Temporal proximity detected'
      })));
    }

    // Transform v2 structure to dashboard format
    return {
      model: ctiAnalysis.model,
      killChainPhase: ctiAnalysis.analysis.killChainPhase,
      threatLandscape: ctiAnalysis.analysis.summary,
      mitreAttack: Array.from(tacticMap.entries()).map(([tactic, techniques]) => ({
        tactic,
        techniques,
        mitigations: ['Implement network segmentation', 'Enable logging and monitoring']
      })),
      keyFindings: ctiAnalysis.analysis.keyFindings.map((f, i) => ({
        finding: f,
        severity: i === 0 ? 'high' : 'medium',
        evidence: 'Based on collected intelligence data',
        recommendation: ctiAnalysis.analysis.recommendations[i] || 'Review and assess risk'
      })),
      ttps: ctiAnalysis.extraction.ttps.map(t => ({
        technique: t.name,
        techniqueId: t.id,
        tactic: t.tactic,
        evidence: t.evidence,
        confidence: 0.8
      })),
      temporalPatterns,
      crossSourceLinks,
      immediateActions: ctiAnalysis.analysis.recommendations.slice(0, 3),
      strategicRecommendations: ctiAnalysis.analysis.recommendations.slice(3),
      sourcesAndReferences: [
        ...ctiAnalysis.extraction.ips.slice(0, 3).map(ip => ({
          source: 'Shodan',
          url: ip.url,
          relevance: `${ip.service} on port ${ip.port}`
        })),
        ...ctiAnalysis.extraction.cves.slice(0, 3).map(cve => ({
          source: 'NVD',
          url: cve.url,
          relevance: `${cve.id} (${cve.severity})`
        }))
      ]
    };
  }

  /**
   * Clean LLM output from malformed markdown
   */
  private cleanLLMText(text: string): string {
    return text
      .replace(/\*\*([^*]+)\*\*/g, '$1')  // Remove **bold**
      .replace(/^\*([A-Z])/gm, '$1')       // Fix *Patch -> Patch at start
      .replace(/\*+$/gm, '')               // Remove trailing asterisks
      .replace(/#{2,}/g, '')               // Remove ### headers
      .replace(/\n{3,}/g, '\n\n')          // Normalize newlines
      .trim();
  }

  /**
   * Enhance executive summary with CTI analysis
   */
  private enhanceExecutiveWithCTI(
    executive: PublicDashboard['executive'], 
    ctiAnalysis: CTIAnalysis
  ): PublicDashboard['executive'] {
    const cleanFindings = ctiAnalysis.analysis.keyFindings.map(f => this.cleanLLMText(f));
    const cleanRecs = ctiAnalysis.analysis.recommendations.map(r => this.cleanLLMText(r));
    
    return {
      headline: `Threat Level: ${ctiAnalysis.analysis.riskLevel.toUpperCase()}`,
      summary: this.cleanLLMText(ctiAnalysis.analysis.summary || executive.summary),
      keyFindings: cleanFindings.length > 0 ? cleanFindings : executive.keyFindings,
      recommendedActions: cleanRecs.length > 0 ? cleanRecs.slice(0, 5) : executive.recommendedActions
    };
  }

  /**
   * Build infrastructure exposure section from Shodan data
   */
  private buildInfrastructureSection(shodanData?: ShodanScrapedData | null): PublicDashboard['infrastructure'] | undefined {
    if (!shodanData || shodanData.hosts.length === 0) return undefined;

    const hosts = shodanData.hosts;
    const totalHosts = hosts.length;

    // Count ports
    const portCounts = new Map<number, { service: string; count: number }>();
    for (const host of hosts) {
      const existing = portCounts.get(host.port);
      const service = host.product || this.getDefaultService(host.port);
      portCounts.set(host.port, {
        service,
        count: (existing?.count || 0) + 1
      });
    }

    const exposedPorts = Array.from(portCounts.entries())
      .map(([port, data]) => ({
        port,
        service: data.service,
        count: data.count,
        percentage: Math.round((data.count / totalHosts) * 100)
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Count countries
    const countryCounts = new Map<string, number>();
    for (const host of hosts) {
      if (host.country) {
        countryCounts.set(host.country, (countryCounts.get(host.country) || 0) + 1);
      }
    }

    const topCountries = Array.from(countryCounts.entries())
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Find vulnerable hosts
    const vulnerableHosts = hosts.filter(h => h.vulns && h.vulns.length > 0).length;

    // Sample hosts (masked IPs for privacy)
    const sampleHosts = hosts
      .filter(h => h.vulns && h.vulns.length > 0)
      .slice(0, 5)
      .map(h => ({
        ip: this.maskIp(h.ip),
        port: h.port,
        service: h.product || this.getDefaultService(h.port),
        vulns: (h.vulns || []).slice(0, 3)
      }));

    return {
      totalHosts,
      exposedPorts,
      topCountries,
      vulnerableHosts,
      sampleHosts
    };
  }

  /**
   * Build social intelligence section from X.com data
   */
  private buildSocialIntelSection(xData?: XScrapedData | null): PublicDashboard['socialIntel'] | undefined {
    if (!xData || xData.posts.length === 0) return undefined;

    // Spam patterns to filter out noise
    const spamPatterns = [
      /quiz\s*time/i,
      /what\s+is\s+.*\?\s*[A-D]\)/i,
      /^\d+[A-Za-z]+\s+\w+\d+/i,
      /fusion\s*mix/i,
      /one-day\s*fusion/i,
    ];
    
    const isSpam = (text: string) => spamPatterns.some(p => p.test(text));
    
    // Filter out spam posts
    const posts = xData.posts.filter(p => !isSpam(p.text));
    const totalPosts = posts.length;

    // Extract topics from hashtags and keywords
    const topicCounts = new Map<string, { count: number; engagement: number }>();
    const ctiKeywords = ['ransomware', 'cve', 'vulnerability', 'breach', 'malware', 'apt', 'exploit', 'attack'];

    for (const post of posts) {
      const engagement = post.metrics.likes + post.metrics.reposts;
      const text = post.text.toLowerCase();
      
      // Count hashtags as topics
      for (const hashtag of post.hashtags) {
        const topic = hashtag.toLowerCase();
        const existing = topicCounts.get(topic);
        topicCounts.set(topic, {
          count: (existing?.count || 0) + 1,
          engagement: (existing?.engagement || 0) + engagement
        });
      }

      // Count CTI keywords
      for (const keyword of ctiKeywords) {
        if (text.includes(keyword)) {
          const existing = topicCounts.get(keyword);
          topicCounts.set(keyword, {
            count: (existing?.count || 0) + 1,
            engagement: (existing?.engagement || 0) + engagement
          });
        }
      }
    }

    const topTopics = Array.from(topicCounts.entries())
      .map(([topic, data]) => ({ topic, count: data.count, engagement: data.engagement }))
      .sort((a, b) => b.engagement - a.engagement)
      .slice(0, 5);

    // Get recent posts with URLs
    const recentPosts = posts
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 5)
      .map(post => ({
        excerpt: post.text.substring(0, 120) + (post.text.length > 120 ? '...' : ''),
        author: `@${post.author.username}`,
        timestamp: post.timestamp,
        engagement: post.metrics.likes + post.metrics.reposts,
        url: post.id ? `https://x.com/${post.author.username}/status/${post.id}` : `https://x.com/search?q=${encodeURIComponent(post.text.substring(0, 30))}`
      }));

    // Determine sentiment based on content
    const alarmingKeywords = ['critical', 'urgent', 'zero-day', 'active exploitation', 'emergency'];
    const alarmingPosts = posts.filter(p => 
      alarmingKeywords.some(k => p.text.toLowerCase().includes(k))
    ).length;
    
    const sentiment = alarmingPosts > totalPosts * 0.3 ? 'alarming' : 
      alarmingPosts > 0 ? 'neutral' : 'informational';

    return {
      totalPosts,
      topTopics,
      recentPosts,
      sentiment
    };
  }

  private getDefaultService(port: number): string {
    const services: Record<number, string> = {
      22: 'SSH',
      23: 'Telnet',
      80: 'HTTP',
      443: 'HTTPS',
      445: 'SMB',
      3389: 'RDP',
      3306: 'MySQL',
      5432: 'PostgreSQL',
      6379: 'Redis',
      27017: 'MongoDB'
    };
    return services[port] || `Port ${port}`;
  }

  /**
   * Build correlation section with evidence links
   */
  private buildCorrelationSection(data: ProcessedData): PublicDashboard['correlation'] | undefined {
    const { correlation } = data;
    if (!correlation || correlation.signals.length === 0) {
      return undefined;
    }

    // Filter to only signals with cross-source correlation
    const correlatedSignals = correlation.signals.filter(s => {
      const hasInfra = s.sources.some(src => src.source === DataSource.SHODAN && src.count > 0);
      const hasSocial = s.sources.some(src => src.source === DataSource.X_COM && src.count > 0);
      return hasInfra && hasSocial;
    });

    if (correlatedSignals.length === 0) {
      return undefined;
    }

    // Build signals with evidence
    const signals = correlatedSignals.slice(0, 5).map(sig => {
      const infraSource = sig.sources.find(s => s.source === DataSource.SHODAN);
      const socialSource = sig.sources.find(s => s.source === DataSource.X_COM);

      return {
        id: sig.id,
        label: sig.label,
        infraCount: infraSource?.count || 0,
        socialCount: socialSource?.count || 0,
        timeDeltaHours: sig.temporalAnalysis?.timeDeltaHours ?? null,
        interpretation: this.generateInterpretation(sig),
        evidence: {
          infrastructure: this.buildInfraEvidence(infraSource, sig.label),
          social: this.buildSocialEvidence(socialSource, sig.label)
        }
      };
    });

    // Generate executive insight
    const insight = this.generateCorrelationInsight(correlatedSignals, correlation.dominantPattern);

    return {
      insight,
      pattern: correlation.dominantPattern,
      signals
    };
  }

  private generateInterpretation(sig: CorrelationSignal): string {
    const deltaHours = sig.temporalAnalysis?.timeDeltaHours;
    const pattern = sig.temporalAnalysis?.pattern;
    
    if (!deltaHours || deltaHours === 0) {
      return `${sig.label} activity detected simultaneously in infrastructure and social channels.`;
    }

    if (sig.temporalAnalysis?.infraPrecedesSocial) {
      if (pattern === 'scanning') {
        return `Infrastructure scanning of ${sig.label} detected ${Math.abs(deltaHours).toFixed(1)}h before social discussion, indicating reconnaissance activity.`;
      }
      return `${sig.label} infrastructure exposure detected ${Math.abs(deltaHours).toFixed(1)}h before social awareness emerged.`;
    } else {
      return `Social discussion of ${sig.label} preceded infrastructure detection by ${Math.abs(deltaHours).toFixed(1)}h, suggesting threat awareness before observable exposure.`;
    }
  }

  private generateCorrelationInsight(signals: CorrelationSignal[], pattern: string): string {
    const topSignals = signals.slice(0, 3).map(s => s.label);
    
    if (pattern === 'infra-first') {
      return `Infrastructure scanning activity detected across ${topSignals.join(', ')} services before corresponding social discussion. This pattern typically indicates active reconnaissance or early exploitation attempts.`;
    } else if (pattern === 'social-first') {
      return `Security discussions around ${topSignals.join(', ')} appeared in social channels before observable infrastructure activity. This could indicate emerging threats or coordinated awareness campaigns.`;
    } else if (pattern === 'simultaneous') {
      return `Concurrent activity detected across ${topSignals.join(', ')} in both infrastructure and social intelligence. This synchronized pattern may indicate an active campaign.`;
    }
    
    return `Cross-source correlation detected for ${topSignals.join(', ')}.`;
  }

  private buildInfraEvidence(source: CorrelationSignal['sources'][0] | undefined, label: string): EvidenceLink[] {
    if (!source || !source.sampleData) return [];
    
    return source.sampleData.slice(0, 3).map((sample, i) => ({
      source: DataSource.SHODAN,
      type: 'host' as const,
      title: `${label} host: ${this.maskIp(sample)}`,
      url: `https://www.shodan.io/host/${sample}`,
      timestamp: source.lastSeen,
      excerpt: `Exposed ${label} service detected`,
      metadata: { ip: sample }
    }));
  }

  private buildSocialEvidence(source: CorrelationSignal['sources'][0] | undefined, label: string): EvidenceLink[] {
    if (!source || !source.sampleData) return [];
    
    return source.sampleData.slice(0, 3).map((excerpt, i) => ({
      source: DataSource.X_COM,
      type: 'post' as const,
      title: `${label} discussion`,
      url: `https://x.com/search?q=${encodeURIComponent(label)}`,
      timestamp: source.lastSeen,
      excerpt: excerpt.substring(0, 100) + (excerpt.length > 100 ? '...' : '')
    }));
  }

  private maskIp(ip: string): string {
    // Partially mask IP for privacy in public dashboard
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
    return ip;
  }

  private buildEmptyDashboard(now: Date, validUntil: Date): PublicDashboard {
    return {
      meta: {
        version: '2.0.0',
        generatedAt: now.toISOString(),
        validUntil: validUntil.toISOString()
      },
      status: {
        riskLevel: 'low',
        riskScore: 0,
        trend: 'stable',
        confidenceLevel: 0
      },
      executive: {
        headline: 'No Active Threats Detected',
        summary: 'No significant threat activity was identified during this analysis period. Continue monitoring for emerging threats.',
        keyFindings: ['No critical vulnerabilities detected', 'No active campaigns identified'],
        recommendedActions: ['Maintain current security posture', 'Continue routine monitoring']
      },
      metrics: {
        totalSignals: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        categories: []
      },
      timeline: [],
      sources: [],
      indicators: { cves: [], domains: [], ips: [], keywords: [] }
    };
  }

  private buildExecutiveSummary(data: ProcessedData, llm: LLMAnalysisResult | null, riskLevel: string): PublicDashboard['executive'] {
    const { threats, summary, correlation } = data;
    
    // ALWAYS use English-only generated findings (LLM may respond in Spanish)
    const keyFindings = this.generateFindings(data, correlation);
    
    // Use LLM summary if available and meaningful
    if (llm?.executiveSummary && llm.executiveSummary.length > 20) {
      return {
        headline: this.generateHeadline(riskLevel, summary.totalThreats, correlation),
        summary: llm.executiveSummary,
        keyFindings,
        recommendedActions: this.generateActions(riskLevel, correlation)
      };
    }

    // Generate summary from data
    const topCategory = Object.entries(summary.byCategory || {})
      .sort((a, b) => b[1] - a[1])[0];
    
    const socialSignals = threats.filter(t => 
      t.sources?.includes(DataSource.X_COM)
    ).length;
    
    const techSignals = threats.filter(t => 
      t.sources?.includes(DataSource.SHODAN)
    ).length;

    let summaryText = '';
    
    // Include correlation context in summary
    const hasCorrelation = correlation?.summary.correlatedSignals > 0;
    
    if (socialSignals > 0 && techSignals > 0) {
      summaryText = `Analysis identified ${summary.totalThreats} threat signals across social and technical intelligence sources. `;
      if (topCategory) {
        summaryText += `${this.formatCategory(topCategory[0])} activity represents the dominant threat category (${topCategory[1]} signals). `;
      }
      if (hasCorrelation) {
        summaryText += `Cross-source correlation detected ${correlation.summary.correlatedSignals} signals appearing in both infrastructure and social channels. `;
      }
      summaryText += `Activity level: ${riskLevel === 'critical' || riskLevel === 'elevated' ? 'elevated' : 'baseline'}. `;
      summaryText += 'Assessment based on correlated multi-source intelligence.';
    } else if (socialSignals > 0) {
      summaryText = `Social intelligence analysis detected ${socialSignals} threat-related discussions. Claims and reports require verification against technical indicators. Exercise caution when acting on unconfirmed social signals.`;
    } else if (techSignals > 0) {
      summaryText = `Technical reconnaissance identified ${techSignals} infrastructure-related signals. Exposed services and vulnerabilities detected may indicate potential attack surface. Recommend validation and remediation prioritization.`;
    } else {
      summaryText = 'Insufficient data for comprehensive threat assessment. Additional intelligence sources recommended for improved coverage.';
    }

    return {
      headline: this.generateHeadline(riskLevel, summary.totalThreats, correlation),
      summary: summaryText,
      keyFindings,
      recommendedActions: this.generateActions(riskLevel, correlation)
    };
  }

  private generateHeadline(riskLevel: string, totalThreats: number, correlation?: ProcessedData['correlation']): string {
    // If we have cross-source correlation, highlight it
    if (correlation && correlation.summary && correlation.summary.correlatedSignals > 0) {
      const topSignal = correlation.signals.find(s => 
        s.sources.some(src => src.source === DataSource.SHODAN && src.count > 0) &&
        s.sources.some(src => src.source === DataSource.X_COM && src.count > 0)
      );
      if (topSignal && riskLevel === 'critical') {
        return `${topSignal.label} Activity Correlated Across Sources`;
      }
    }
    
    if (riskLevel === 'critical') {
      return 'Critical Threat Activity Detected';
    } else if (riskLevel === 'elevated') {
      return 'Elevated Threat Landscape';
    } else if (riskLevel === 'moderate') {
      return 'Moderate Security Signals Observed';
    }
    return 'Baseline Threat Activity';
  }

  private generateFindings(data: ProcessedData, correlation?: ProcessedData['correlation']): string[] {
    const findings: string[] = [];
    const { summary, indicators } = data;

    // Correlation findings first (most important)
    if (correlation && correlation.summary && correlation.summary.correlatedSignals > 0) {
      const correlatedSignals = correlation.signals.filter(s => 
        s.sources.some(src => src.source === DataSource.SHODAN && src.count > 0) &&
        s.sources.some(src => src.source === DataSource.X_COM && src.count > 0)
      );
      
      if (correlatedSignals.length > 0) {
        const labels = correlatedSignals.slice(0, 2).map(s => s.label).join(' and ');
        const pattern = correlation.dominantPattern;
        
        if (pattern === 'infra-first') {
          findings.push(`${labels} infrastructure activity detected before social discussion`);
        } else if (pattern === 'social-first') {
          findings.push(`${labels} social discussion preceded observable infrastructure exposure`);
        } else {
          findings.push(`Cross-source correlation detected for ${labels}`);
        }
      }
    }

    const cveCount = indicators?.filter(i => i.type === 'cve').length || 0;
    if (cveCount > 0) {
      findings.push(`${cveCount} CVE reference${cveCount > 1 ? 's' : ''} identified in collected intelligence`);
    }

    const criticalThreats = summary.bySeverity?.[ThreatSeverity.CRITICAL] || 0;
    if (criticalThreats > 0) {
      findings.push(`${criticalThreats} critical severity signal${criticalThreats > 1 ? 's' : ''} require immediate attention`);
    }

    const topCategory = Object.entries(summary.byCategory || {})
      .sort((a, b) => b[1] - a[1])[0];
    if (topCategory && findings.length < 4) {
      findings.push(`${this.formatCategory(topCategory[0])} represents primary threat vector`);
    }

    if (findings.length === 0) {
      findings.push('No high-priority findings at this time');
    }

    return findings.slice(0, 4);
  }

  private generateActions(riskLevel: string, correlation?: ProcessedData['correlation']): string[] {
    const actions: string[] = [];
    
    // Add correlation-based actions first
    if (correlation && correlation.summary && correlation.summary.correlatedSignals > 0) {
      const correlatedSignals = correlation.signals.filter(s => 
        s.sources.some(src => src.source === DataSource.SHODAN && src.count > 0) &&
        s.sources.some(src => src.source === DataSource.X_COM && src.count > 0)
      );
      
      if (correlatedSignals.length > 0) {
        const topSignal = correlatedSignals[0];
        if (correlation.dominantPattern === 'infra-first') {
          actions.push(`Verify ${topSignal.label} exposure and assess potential reconnaissance activity`);
        } else if (correlation.dominantPattern === 'social-first') {
          actions.push(`Monitor ${topSignal.label} services for emerging exploitation attempts`);
        }
      }
    }
    
    if (riskLevel === 'critical') {
      actions.push(...[
        'Initiate incident response procedures',
        'Review and patch critical vulnerabilities immediately',
        'Increase monitoring on affected systems',
        'Brief security leadership on current threat status'
      ]);
    } else if (riskLevel === 'elevated') {
      actions.push(...[
        'Prioritize vulnerability remediation for high-severity items',
        'Review access controls and network segmentation',
        'Increase threat hunting activities'
      ]);
    } else if (riskLevel === 'moderate') {
      actions.push(...[
        'Continue routine vulnerability management',
        'Monitor for escalation indicators',
        'Update threat intelligence feeds'
      ]);
    } else {
      actions.push(...[
        'Maintain standard security operations',
        'Continue periodic threat assessments'
      ]);
    }
    
    return actions.slice(0, 4);
  }

  private calculateRiskScore(critical: number, high: number, medium: number, low: number): number {
    const score = (critical * 40) + (high * 20) + (medium * 5) + (low * 1);
    return Math.min(100, Math.round(score));
  }

  private determineRiskLevel(score: number): 'critical' | 'elevated' | 'moderate' | 'low' {
    if (score >= 75) return 'critical';
    if (score >= 45) return 'elevated';
    if (score >= 15) return 'moderate';
    return 'low';
  }

  private determineTrend(threats: ProcessedData['threats']): 'increasing' | 'stable' | 'decreasing' {
    // Simple trend based on recent timestamp clustering
    const now = Date.now();
    const hourAgo = now - 3600000;
    const recentCount = threats.filter(t => new Date(t.timestamp).getTime() > hourAgo).length;
    
    if (recentCount > threats.length * 0.5) return 'increasing';
    if (recentCount < threats.length * 0.2) return 'decreasing';
    return 'stable';
  }

  private calculateConfidence(data: ProcessedData, llm: LLMAnalysisResult | null): number {
    let confidence = 50; // Base confidence
    
    // More sources = higher confidence
    const sourceCount = Object.keys(data.summary.bySource || {}).length;
    confidence += sourceCount * 10;
    
    // More data points = higher confidence
    if (data.threats.length >= 10) confidence += 15;
    else if (data.threats.length >= 5) confidence += 10;
    
    // LLM analysis adds confidence
    if (llm?.executiveSummary) confidence += 10;
    
    return Math.min(95, confidence); // Cap at 95%
  }

  private extractDisplayIndicators(indicators: ProcessedData['indicators']): PublicDashboard['indicators'] {
    return {
      cves: indicators
        ?.filter(i => i.type === 'cve')
        .slice(0, 10)
        .map(i => i.value) || [],
      domains: indicators
        ?.filter(i => i.type === 'domain')
        .slice(0, 5)
        .map(i => i.value) || [],
      ips: indicators
        ?.filter(i => i.type === 'ip')
        .slice(0, 5)
        .map(i => i.value) || [],
      keywords: indicators
        ?.filter(i => i.type === 'keyword')
        .slice(0, 8)
        .map(i => i.value) || []
    };
  }

  private formatCategory(cat: string): string {
    const map: Record<string, string> = {
      'malware': 'Malware',
      'ransomware': 'Ransomware',
      'phishing': 'Phishing',
      'ddos': 'DDoS',
      'apt': 'APT',
      'vulnerability': 'Vulnerability',
      'data_breach': 'Data Breach',
      'supply_chain': 'Supply Chain',
      'social_engineering': 'Social Engineering',
      'infrastructure': 'Infrastructure',
      'other': 'Other'
    };
    return map[cat.toLowerCase()] || cat;
  }

  private formatSource(src: string): string {
    const map: Record<string, string> = {
      'x.com': 'Social Intelligence (X)',
      'shodan': 'Technical Reconnaissance',
      'misp': 'MISP Threat Sharing',
      'alienvault': 'AlienVault OTX',
      'virustotal': 'VirusTotal',
      'abuse.ch': 'abuse.ch'
    };
    return map[src.toLowerCase()] || src;
  }

  private sanitizeTitle(title: string): string {
    // Remove sensitive details, limit length
    return title
      .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[IP]')
      .substring(0, 80);
  }

  private async loadJson<T>(filename: string): Promise<T | null> {
    try {
      const raw = await fs.readFile(path.join(this.outputDir, filename), 'utf-8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  private async saveDashboard(dashboard: PublicDashboard): Promise<void> {
    // Save to output directory
    await fs.mkdir(this.outputDir, { recursive: true });
    await fs.writeFile(
      path.join(this.outputDir, 'cti-dashboard.json'),
      JSON.stringify(dashboard, null, 2)
    );
    
    // Also save to public directory for web access
    await fs.mkdir(this.publicDir, { recursive: true });
    await fs.writeFile(
      path.join(this.publicDir, 'cti-dashboard.json'),
      JSON.stringify(dashboard, null, 2)
    );
    
    console.log(`[Dashboard] Saved to ${this.publicDir}/cti-dashboard.json`);
  }
}

export default DashboardGenerator;
