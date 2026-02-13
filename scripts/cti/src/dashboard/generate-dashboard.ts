/**
 * Dashboard Generator - Produces clean JSON for CTI visualization
 * Output designed for public dashboard consumption
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { ProcessedData, LLMAnalysisResult, ThreatSeverity, ThreatCategory, DataSource } from '../types/index.js';

// Frontend-optimized dashboard format
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

    const dashboard = this.buildDashboard(processedData, llmAnalysis);
    
    await this.saveDashboard(dashboard);
    console.log(`[Dashboard] Generated - Risk: ${dashboard.status.riskLevel}, Signals: ${dashboard.metrics.totalSignals}`);
    
    return dashboard;
  }

  private buildDashboard(data: ProcessedData | null, llm: LLMAnalysisResult | null): PublicDashboard {
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

    // Build timeline (top 8 threats)
    const timeline = threats.slice(0, 8).map(t => ({
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

    return {
      meta: {
        version: '2.0.0',
        generatedAt: now.toISOString(),
        validUntil: validUntil.toISOString()
      },
      status: {
        riskLevel,
        riskScore,
        trend: this.determineTrend(threats),
        confidenceLevel
      },
      executive,
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
      indicators: displayIndicators
    };
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
    const { threats, summary } = data;
    
    // Use LLM summary if available and meaningful
    if (llm?.executiveSummary && llm.executiveSummary.length > 20) {
      return {
        headline: this.generateHeadline(riskLevel, summary.totalThreats),
        summary: llm.executiveSummary,
        keyFindings: llm.recommendations?.slice(0, 3) || this.generateFindings(data),
        recommendedActions: this.generateActions(riskLevel)
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
    
    if (socialSignals > 0 && techSignals > 0) {
      summaryText = `Analysis identified ${summary.totalThreats} threat signals across social and technical intelligence sources. `;
      if (topCategory) {
        summaryText += `${this.formatCategory(topCategory[0])} activity represents the dominant threat category (${topCategory[1]} signals). `;
      }
      summaryText += `Social discussion and infrastructure observations indicate ${riskLevel === 'critical' || riskLevel === 'elevated' ? 'elevated' : 'baseline'} activity levels. `;
      summaryText += 'Assessment based on correlated multi-source intelligence.';
    } else if (socialSignals > 0) {
      summaryText = `Social intelligence analysis detected ${socialSignals} threat-related discussions. Claims and reports require verification against technical indicators. Exercise caution when acting on unconfirmed social signals.`;
    } else if (techSignals > 0) {
      summaryText = `Technical reconnaissance identified ${techSignals} infrastructure-related signals. Exposed services and vulnerabilities detected may indicate potential attack surface. Recommend validation and remediation prioritization.`;
    } else {
      summaryText = 'Insufficient data for comprehensive threat assessment. Additional intelligence sources recommended for improved coverage.';
    }

    return {
      headline: this.generateHeadline(riskLevel, summary.totalThreats),
      summary: summaryText,
      keyFindings: this.generateFindings(data),
      recommendedActions: this.generateActions(riskLevel)
    };
  }

  private generateHeadline(riskLevel: string, totalThreats: number): string {
    if (riskLevel === 'critical') {
      return 'Critical Threat Activity Detected';
    } else if (riskLevel === 'elevated') {
      return 'Elevated Threat Landscape';
    } else if (riskLevel === 'moderate') {
      return 'Moderate Security Signals Observed';
    }
    return 'Baseline Threat Activity';
  }

  private generateFindings(data: ProcessedData): string[] {
    const findings: string[] = [];
    const { summary, threats, indicators } = data;

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
    if (topCategory) {
      findings.push(`${this.formatCategory(topCategory[0])} represents primary threat vector`);
    }

    if (findings.length === 0) {
      findings.push('No high-priority findings at this time');
    }

    return findings.slice(0, 4);
  }

  private generateActions(riskLevel: string): string[] {
    if (riskLevel === 'critical') {
      return [
        'Initiate incident response procedures',
        'Review and patch critical vulnerabilities immediately',
        'Increase monitoring on affected systems',
        'Brief security leadership on current threat status'
      ];
    } else if (riskLevel === 'elevated') {
      return [
        'Prioritize vulnerability remediation for high-severity items',
        'Review access controls and network segmentation',
        'Increase threat hunting activities'
      ];
    } else if (riskLevel === 'moderate') {
      return [
        'Continue routine vulnerability management',
        'Monitor for escalation indicators',
        'Update threat intelligence feeds'
      ];
    }
    return [
      'Maintain standard security operations',
      'Continue periodic threat assessments'
    ];
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
