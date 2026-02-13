/**
 * CTI Analysis System v2 - Efficient Threat Intelligence Analysis
 * 
 * Architecture (optimized):
 * 1. EXTRACTION - Done in code from processed data (fast, reliable)
 * 2. LLM ANALYSIS - Single prompt for narrative analysis (one call)
 * 3. STRUCTURING - Parse text response into sections (no JSON parsing)
 * 
 * Standards: MITRE ATT&CK, Cyber Kill Chain, STIX terminology
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { 
  ProcessedData, 
  ShodanScrapedData, 
  XScrapedData,
  ThreatSeverity 
} from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const CTI_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:3b';
const REQUEST_TIMEOUT = parseInt(process.env.CTI_REQUEST_TIMEOUT || '300000', 10); // 5 min

// MITRE technique mapping (common techniques by keyword)
const MITRE_MAPPINGS: Record<string, { id: string; name: string; tactic: string }> = {
  'ssh': { id: 'T1021.004', name: 'Remote Services: SSH', tactic: 'Lateral Movement' },
  'rdp': { id: 'T1021.001', name: 'Remote Services: RDP', tactic: 'Lateral Movement' },
  'smb': { id: 'T1021.002', name: 'Remote Services: SMB', tactic: 'Lateral Movement' },
  'port 22': { id: 'T1021.004', name: 'Remote Services: SSH', tactic: 'Lateral Movement' },
  'port 3389': { id: 'T1021.001', name: 'Remote Services: RDP', tactic: 'Lateral Movement' },
  'port 445': { id: 'T1021.002', name: 'Remote Services: SMB', tactic: 'Lateral Movement' },
  'brute': { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  'credential': { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  'phishing': { id: 'T1566', name: 'Phishing', tactic: 'Initial Access' },
  'malware': { id: 'T1204', name: 'User Execution', tactic: 'Execution' },
  'ransomware': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  'c2': { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  'exfil': { id: 'T1041', name: 'Exfiltration Over C2', tactic: 'Exfiltration' },
  'scan': { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  'vuln': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  'cve': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
};

export interface CTIAnalysis {
  timestamp: string;
  model: string;
  
  // Extracted from data (code-based)
  extraction: {
    ips: Array<{ value: string; port: number; service: string; url: string; timestamp?: string }>;
    cves: Array<{ id: string; severity: string; url: string; firstSeen?: string }>;
    ttps: Array<{ id: string; name: string; tactic: string; evidence: string }>;
    socialPosts: Array<{ author: string; text: string; url: string; engagement: number; timestamp: string }>;
    timelineEvents: Array<{ timestamp: string; source: 'shodan' | 'x.com' | 'cve'; description: string }>;
  };
  
  // LLM-generated analysis
  analysis: {
    summary: string;
    keyFindings: string[];
    riskLevel: 'critical' | 'high' | 'medium' | 'low';
    riskScore: number;
    recommendations: string[];
    killChainPhase: string;
  };
  
  // Temporal correlation analysis (LLM-generated)
  correlation: {
    narrative: string;
    pattern: 'infra-first' | 'social-first' | 'simultaneous' | 'isolated';
    timeWindow: string;
    keyCorrelations: Array<{
      socialEvent: string;
      infraEvent: string;
      timeDelta: string;
      significance: string;
    }>;
    emergingThreats: string[];
    confidence: number;
  };
}

export class CTIAgentSystem {
  private outputDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Main analysis pipeline
   */
  async analyze(): Promise<CTIAnalysis> {
    console.log(`[CTI-Agents] Starting analysis with ${CTI_MODEL}`);
    console.log(`[CTI-Agents] Ollama: ${OLLAMA_HOST}, Timeout: ${REQUEST_TIMEOUT/1000}s`);
    
    // Load data
    console.log('[CTI-Agents] Loading data...');
    const processed = await this.loadJson<ProcessedData>('processed-data.json');
    const shodan = await this.loadJson<ShodanScrapedData>('shodan-data.json');
    const xData = await this.loadJson<XScrapedData>('x-data.json');
    
    console.log(`[CTI-Agents] Loaded: ${shodan?.hosts?.length || 0} hosts, ${xData?.posts?.length || 0} posts, ${processed?.threats?.length || 0} threats`);

    // STEP 1: Code-based extraction (fast, reliable)
    console.log('[CTI-Agents] Extracting indicators...');
    const extraction = this.extractIndicators(processed, shodan, xData);
    console.log(`[CTI-Agents] Extracted: ${extraction.ips.length} IPs, ${extraction.cves.length} CVEs, ${extraction.ttps.length} TTPs`);
    
    // STEP 2: Build temporal context for LLM
    const context = this.buildTemporalContext(extraction, processed, shodan, xData);
    console.log(`[CTI-Agents] Temporal context: ${context.length} chars`);
    
    // STEP 3: LLM call for narrative + temporal correlation analysis
    console.log('[CTI-Agents] Running LLM analysis with temporal correlation...');
    const { analysis: llmAnalysis, correlation } = await this.runLLMAnalysis(context);
    
    const result: CTIAnalysis = {
      timestamp: new Date().toISOString(),
      model: CTI_MODEL,
      extraction,
      analysis: llmAnalysis,
      correlation
    };

    await this.saveResult(result);
    return result;
  }

  /**
   * Code-based indicator extraction (no LLM needed)
   */
  private extractIndicators(
    processed: ProcessedData | null,
    shodan: ShodanScrapedData | null,
    xData: XScrapedData | null
  ): CTIAnalysis['extraction'] {
    const ips: CTIAnalysis['extraction']['ips'] = [];
    const cves: CTIAnalysis['extraction']['cves'] = [];
    const ttps: CTIAnalysis['extraction']['ttps'] = [];
    const socialPosts: CTIAnalysis['extraction']['socialPosts'] = [];
    const socialContextText = (xData?.posts || []).map(p => p.text).join(' ').toLowerCase();
    
    // Extract from Shodan
    if (shodan?.hosts) {
      const seenIps = new Set<string>();
      for (const host of shodan.hosts.slice(0, 20)) { // Top 20
        if (!seenIps.has(host.ip)) {
          seenIps.add(host.ip);
          ips.push({
            value: host.ip,
            port: host.port,
            service: host.product || this.portToService(host.port),
            url: `https://www.shodan.io/host/${host.ip}`
          });
        }
        
        // Extract CVEs
        if (host.vulns) {
          for (const cve of host.vulns) {
            if (!cves.find(c => c.id === cve)) {
              cves.push({
                id: cve,
                severity: this.guessCVESeverity(cve),
                url: `https://nvd.nist.gov/vuln/detail/${cve}`
              });
            }
          }
        }
      }
      
      // Map ports to TTPs ONLY when corroborated by social context
      const ports = new Set(shodan.hosts.map(h => h.port));
      const socialMentionsSSH = /(ssh|openssh|secure shell|ssh brute)/i.test(socialContextText);
      const socialMentionsRDP = /(rdp|remote desktop|bluekeep)/i.test(socialContextText);
      const socialMentionsSMB = /(smb|samba|eternalblue|wannacry|windows share)/i.test(socialContextText);

      if (ports.has(22) && socialMentionsSSH) {
        ttps.push({ ...MITRE_MAPPINGS['port 22'], evidence: 'SSH exposure corroborated by social discussion' });
      }
      if (ports.has(3389) && socialMentionsRDP) {
        ttps.push({ ...MITRE_MAPPINGS['port 3389'], evidence: 'RDP exposure corroborated by social discussion' });
      }
      if (ports.has(445) && socialMentionsSMB) {
        ttps.push({ ...MITRE_MAPPINGS['port 445'], evidence: 'SMB exposure corroborated by social discussion' });
      }
    }
    
    // Extract from X.com posts with timestamps
    if (xData?.posts) {
      const sortedPosts = [...xData.posts]
        .sort((a, b) => (b.metrics.likes + b.metrics.reposts) - (a.metrics.likes + a.metrics.reposts))
        .slice(0, 10);
      
      for (const post of sortedPosts) {
        socialPosts.push({
          author: `@${post.author.username}`,
          text: post.text.substring(0, 200),
          url: post.id ? `https://x.com/${post.author.username}/status/${post.id}` : '',
          engagement: post.metrics.likes + post.metrics.reposts,
          timestamp: post.timestamp
        });
        
        // Extract TTPs from post content
        const textLower = post.text.toLowerCase();
        for (const [keyword, mapping] of Object.entries(MITRE_MAPPINGS)) {
          if (textLower.includes(keyword) && !ttps.find(t => t.id === mapping.id)) {
            ttps.push({ ...mapping, evidence: `Mentioned in X.com post: "${post.text.substring(0, 50)}..."` });
          }
        }
      }
    }
    
    // Extract from processed indicators
    if (processed?.indicators) {
      for (const ioc of processed.indicators) {
        if (ioc.type === 'cve' && !cves.find(c => c.id === ioc.value)) {
          cves.push({
            id: ioc.value,
            severity: this.guessCVESeverity(ioc.value),
            url: `https://nvd.nist.gov/vuln/detail/${ioc.value}`
          });
        }
      }
    }
    
    // Build unified timeline of events
    const timelineEvents: CTIAnalysis['extraction']['timelineEvents'] = [];
    
    // Add social posts to timeline
    for (const post of socialPosts) {
      timelineEvents.push({
        timestamp: post.timestamp,
        source: 'x.com',
        description: `${post.author}: ${post.text.substring(0, 80)}...`
      });
    }
    
    // Add infrastructure events
    if (shodan?.hosts) {
      const hostsByTime = [...shodan.hosts]
        .filter(h => h.lastUpdate)
        .sort((a, b) => new Date(b.lastUpdate).getTime() - new Date(a.lastUpdate).getTime());
      
      for (const host of hostsByTime.slice(0, 5)) {
        timelineEvents.push({
          timestamp: host.lastUpdate,
          source: 'shodan',
          description: `Host ${host.ip}:${host.port} (${host.product || 'unknown service'}) - ${host.vulns?.length || 0} vulns`
        });
      }
    }
    
    // Sort timeline chronologically
    timelineEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    
    return { ips, cves, ttps, socialPosts, timelineEvents };
  }

  /**
   * Build temporal context for LLM with chronological timeline
   */
  private buildTemporalContext(
    extraction: CTIAnalysis['extraction'], 
    processed: ProcessedData | null,
    shodan: ShodanScrapedData | null,
    xData: XScrapedData | null
  ): string {
    const lines: string[] = [];
    const now = new Date();
    
    lines.push('=== CYBER THREAT INTELLIGENCE REPORT ===');
    lines.push(`Analysis Date: ${now.toISOString()}`);
    lines.push('');
    
    // === CHRONOLOGICAL TIMELINE (KEY FOR CORRELATION) ===
    lines.push('=== CHRONOLOGICAL EVENT TIMELINE ===');
    lines.push('(Analyze temporal relationships between events)');
    lines.push('');
    
    if (extraction.timelineEvents.length > 0) {
      for (const event of extraction.timelineEvents) {
        const eventDate = new Date(event.timestamp);
        const hoursAgo = Math.round((now.getTime() - eventDate.getTime()) / (1000 * 60 * 60));
        const sourceTag = event.source === 'x.com' ? '[SOCIAL]' : '[INFRA]';
        lines.push(`${eventDate.toISOString()} ${sourceTag} (${hoursAgo}h ago): ${event.description}`);
      }
    }
    
    // === INFRASTRUCTURE DATA WITH TIMESTAMPS ===
    lines.push('');
    lines.push('=== INFRASTRUCTURE EXPOSURE ===');
    if (shodan?.hosts && shodan.hosts.length > 0) {
      lines.push(`Total: ${shodan.hosts.length} hosts scanned`);
      
      // Group by timestamp windows
      const recentHosts = shodan.hosts.filter(h => {
        const hostDate = new Date(h.lastUpdate);
        return (now.getTime() - hostDate.getTime()) < 24 * 60 * 60 * 1000; // Last 24h
      });
      lines.push(`Recent (24h): ${recentHosts.length} hosts`);
      
      // Port summary
      const portCounts: Record<number, number> = {};
      shodan.hosts.forEach(h => portCounts[h.port] = (portCounts[h.port] || 0) + 1);
      lines.push('Exposed ports:');
      for (const [port, count] of Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        lines.push(`  - Port ${port}: ${count} hosts`);
      }
      
      // Vulnerabilities with dates
      const vulnCounts = new Map<string, number>();
      shodan.hosts.forEach(h => h.vulns?.forEach(v => vulnCounts.set(v, (vulnCounts.get(v) || 0) + 1)));
      if (vulnCounts.size > 0) {
        lines.push('Vulnerabilities found:');
        for (const [cve, count] of [...vulnCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
          lines.push(`  - ${cve}: ${count} hosts affected`);
        }
      }
    } else {
      lines.push('No infrastructure data available');
    }
    
    // === SOCIAL INTELLIGENCE WITH TIMESTAMPS ===
    lines.push('');
    lines.push('=== SOCIAL INTELLIGENCE (X.COM) ===');
    if (xData?.posts && xData.posts.length > 0) {
      lines.push(`Total: ${xData.posts.length} posts analyzed`);
      
      // Sort by time and show with timestamps
      const sortedPosts = [...xData.posts]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 8);
      
      lines.push('Recent discussions (sorted by time):');
      for (const post of sortedPosts) {
        const postDate = new Date(post.timestamp);
        const hoursAgo = Math.round((now.getTime() - postDate.getTime()) / (1000 * 60 * 60));
        lines.push(`  [${hoursAgo}h ago] @${post.author.username}: "${post.text.substring(0, 100)}..."`);
        lines.push(`    Engagement: ${post.metrics.likes} likes, ${post.metrics.reposts} reposts`);
      }
      
      // Trending topics
      const topics = new Map<string, number>();
      xData.posts.forEach(p => p.hashtags.forEach(h => topics.set(h, (topics.get(h) || 0) + 1)));
      if (topics.size > 0) {
        lines.push('Trending topics:');
        for (const [topic, count] of [...topics.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
          lines.push(`  - #${topic}: ${count} mentions`);
        }
      }
    } else {
      lines.push('No social data available');
    }
    
    // === MITRE TECHNIQUES ===
    if (extraction.ttps.length > 0) {
      lines.push('');
      lines.push('=== MITRE ATT&CK TECHNIQUES ===');
      for (const ttp of extraction.ttps) {
        lines.push(`  - ${ttp.id}: ${ttp.name} (${ttp.tactic})`);
        lines.push(`    Evidence: ${ttp.evidence}`);
      }
    }
    
    // === THREAT SUMMARY ===
    if (processed?.summary) {
      lines.push('');
      lines.push('=== THREAT SUMMARY ===');
      lines.push(`Total threats: ${processed.summary.totalThreats}`);
      lines.push(`  Critical: ${processed.summary.bySeverity?.critical || 0}`);
      lines.push(`  High: ${processed.summary.bySeverity?.high || 0}`);
      lines.push(`  Medium: ${processed.summary.bySeverity?.medium || 0}`);
      lines.push(`  Low: ${processed.summary.bySeverity?.low || 0}`);
    }
    
    return lines.join('\n');
  }

  /**
   * LLM analysis with temporal correlation
   */
  private async runLLMAnalysis(context: string): Promise<{ analysis: CTIAnalysis['analysis']; correlation: CTIAnalysis['correlation'] }> {
    const prompt = `You are a senior threat intelligence analyst specializing in temporal correlation analysis.

${context}

Analyze this intelligence data and produce a comprehensive assessment. Pay special attention to TEMPORAL CORRELATIONS between social media discussions and infrastructure exposure.

Write your analysis with these sections:

SUMMARY: Overview of the current threat landscape (2-3 sentences).

KEY FINDINGS: 3-5 bullet points of most critical findings.

TEMPORAL CORRELATION ANALYSIS:
Analyze the relationship between social media discussions and infrastructure findings:
- Did social discussions precede infrastructure exposure? Or vice versa?
- What is the time window between related events?
- Are there CVEs being discussed on social media that match infrastructure vulnerabilities?
- Which events appear causally related vs coincidental?

CORRELATION PATTERN: State one of: INFRA-FIRST (infrastructure exposure preceded social discussion), SOCIAL-FIRST (social discussion preceded infrastructure findings), SIMULTANEOUS (events occurred together), or ISOLATED (no clear correlation).

KEY CORRELATIONS: List specific correlations found:
- Social event: [what was discussed]
- Infra event: [what was found]  
- Time delta: [hours/days between]
- Significance: [why this matters]

EMERGING THREATS: List 2-3 threats that appear to be developing based on temporal patterns.

RISK LEVEL: CRITICAL/HIGH/MEDIUM/LOW with score 0-100.

RECOMMENDATIONS: 3-5 prioritized actions based on temporal urgency.

Be specific about timestamps and temporal relationships. Correlation analysis is the primary objective.`;

    try {
      const response = await this.callOllama(prompt);
      return this.parseTemporalResponse(response);
    } catch (err) {
      console.error('[CTI-Agents] LLM analysis failed:', err);
      return {
        analysis: this.fallbackAnalysis(context),
        correlation: this.fallbackCorrelation()
      };
    }
  }

  /**
   * Parse LLM response including temporal correlation
   */
  private parseTemporalResponse(text: string): { analysis: CTIAnalysis['analysis']; correlation: CTIAnalysis['correlation'] } {
    // Parse standard analysis sections
    const summaryMatch = text.match(/SUMMARY[:\s]*([^]*?)(?=KEY FINDINGS|TEMPORAL|$)/i);
    const findingsMatch = text.match(/KEY FINDINGS[:\s]*([^]*?)(?=TEMPORAL|RISK|RECOMMENDATIONS|$)/i);
    const riskMatch = text.match(/RISK\s*LEVEL[:\s]*([^]*?)(?=RECOMMENDATIONS|$)/i);
    const recsMatch = text.match(/RECOMMENDATIONS[:\s]*([^]*?)$/i);
    
    // Parse temporal correlation sections
    const correlationMatch = text.match(/TEMPORAL CORRELATION[^:]*:[:\s]*([^]*?)(?=CORRELATION PATTERN|KEY CORRELATIONS|$)/i);
    const patternMatch = text.match(/CORRELATION PATTERN[:\s]*([^]*?)(?=KEY CORRELATIONS|EMERGING|$)/i);
    const keyCorrelationsMatch = text.match(/KEY CORRELATIONS[:\s]*([^]*?)(?=EMERGING|RISK|$)/i);
    const emergingMatch = text.match(/EMERGING THREATS[:\s]*([^]*?)(?=RISK|$)/i);
    
    const parseBullets = (text: string): string[] => {
      const bullets = text.match(/[-•*]\s*(.+)/g) || [];
      return bullets.map(b => b.replace(/^[-•*]\s*/, '').trim()).filter(b => b.length > 0);
    };
    
    // Parse risk
    let riskLevel: 'critical' | 'high' | 'medium' | 'low' = 'medium';
    let riskScore = 50;
    if (riskMatch) {
      const riskText = riskMatch[1].toLowerCase();
      if (riskText.includes('critical')) { riskLevel = 'critical'; riskScore = 85; }
      else if (riskText.includes('high')) { riskLevel = 'high'; riskScore = 70; }
      else if (riskText.includes('low')) { riskLevel = 'low'; riskScore = 25; }
      const scoreMatch = riskText.match(/(\d+)/);
      if (scoreMatch) riskScore = Math.min(100, Math.max(0, parseInt(scoreMatch[1])));
    }
    
    // Parse correlation pattern
    let pattern: 'infra-first' | 'social-first' | 'simultaneous' | 'isolated' = 'isolated';
    if (patternMatch) {
      const patternText = patternMatch[1].toLowerCase();
      if (patternText.includes('infra-first') || patternText.includes('infrastructure first')) pattern = 'infra-first';
      else if (patternText.includes('social-first') || patternText.includes('social first')) pattern = 'social-first';
      else if (patternText.includes('simultaneous')) pattern = 'simultaneous';
    }
    
    // Parse key correlations
    const keyCorrelations: CTIAnalysis['correlation']['keyCorrelations'] = [];
    if (keyCorrelationsMatch) {
      const corrText = keyCorrelationsMatch[1];
      // Try to extract structured correlations
      const socialMatches = corrText.match(/social\s*event[:\s]*([^\n]+)/gi) || [];
      const infraMatches = corrText.match(/infra\s*event[:\s]*([^\n]+)/gi) || [];
      const deltaMatches = corrText.match(/time\s*delta[:\s]*([^\n]+)/gi) || [];
      const sigMatches = corrText.match(/significance[:\s]*([^\n]+)/gi) || [];
      
      for (let i = 0; i < Math.min(socialMatches.length, infraMatches.length); i++) {
        keyCorrelations.push({
          socialEvent: socialMatches[i]?.replace(/social\s*event[:\s]*/i, '').trim() || '',
          infraEvent: infraMatches[i]?.replace(/infra\s*event[:\s]*/i, '').trim() || '',
          timeDelta: deltaMatches[i]?.replace(/time\s*delta[:\s]*/i, '').trim() || 'Unknown',
          significance: sigMatches[i]?.replace(/significance[:\s]*/i, '').trim() || 'Requires investigation'
        });
      }
    }
    
    // Kill chain phase
    const allText = text.toLowerCase();
    let killChainPhase = 'Reconnaissance';
    if (allText.includes('exploit') || allText.includes('vulnerab')) killChainPhase = 'Exploitation';
    else if (allText.includes('malware') || allText.includes('payload')) killChainPhase = 'Delivery';
    else if (allText.includes('c2') || allText.includes('command')) killChainPhase = 'Command & Control';
    
    return {
      analysis: {
        summary: (summaryMatch?.[1] || 'Analysis completed.').trim(),
        keyFindings: parseBullets(findingsMatch?.[1] || ''),
        riskLevel,
        riskScore,
        recommendations: parseBullets(recsMatch?.[1] || ''),
        killChainPhase
      },
      correlation: {
        narrative: (correlationMatch?.[1] || '').trim(),
        pattern,
        timeWindow: this.extractTimeWindow(text),
        keyCorrelations,
        emergingThreats: parseBullets(emergingMatch?.[1] || ''),
        confidence: keyCorrelations.length > 0 ? 75 : 40
      }
    };
  }

  private extractTimeWindow(text: string): string {
    const windowMatch = text.match(/(\d+)\s*(hour|day|week)s?\s*(window|period|timeframe)/i);
    if (windowMatch) return `${windowMatch[1]} ${windowMatch[2]}(s)`;
    return '24-48 hours';
  }

  private fallbackCorrelation(): CTIAnalysis['correlation'] {
    return {
      narrative: 'Insufficient data for detailed temporal correlation analysis.',
      pattern: 'isolated',
      timeWindow: 'Unknown',
      keyCorrelations: [],
      emergingThreats: [],
      confidence: 20
    };
  }

  /**
   * Fallback analysis if LLM fails
   */
  private fallbackAnalysis(context: string): CTIAnalysis['analysis'] {
    const hasCritical = context.includes('Critical:') && !context.includes('Critical: 0');
    const hasVulns = context.includes('CVE-');
    
    return {
      summary: 'Automated threat intelligence analysis based on Shodan infrastructure scans and X.com social monitoring.',
      keyFindings: [
        hasVulns ? 'Known vulnerabilities detected in exposed infrastructure' : 'Infrastructure scan completed',
        'Remote access services (SSH/RDP/SMB) exposed to internet',
        'Social media monitoring active for threat indicators'
      ],
      riskLevel: hasCritical ? 'high' : 'medium',
      riskScore: hasCritical ? 70 : 50,
      recommendations: [
        'Review and restrict exposed remote access services',
        'Patch systems with known vulnerabilities',
        'Implement network segmentation',
        'Enable multi-factor authentication',
        'Monitor for indicators of compromise'
      ],
      killChainPhase: 'Reconnaissance'
    };
  }

  /**
   * Call Ollama with streaming
   */
  private async callOllama(prompt: string): Promise<string> {
    console.log(`[CTI-Agents] Prompt: ${prompt.length} chars`);
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    
    console.log('[CTI-Agents] Calling Ollama...');
    const startTime = Date.now();
    
    const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: CTI_MODEL,
        prompt,
        stream: true,
        options: { temperature: 0.3, num_predict: 800 }
      })
    });

    if (!res.ok) {
      clearTimeout(timeout);
      throw new Error(`HTTP ${res.status}`);
    }
    
    const reader = res.body?.getReader();
    if (!reader) throw new Error('No response body');
    
    const decoder = new TextDecoder();
    let fullResponse = '';
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const chunk = decoder.decode(value, { stream: true });
      for (const line of chunk.split('\n')) {
        if (!line.trim()) continue;
        try {
          const json = JSON.parse(line);
          if (json.response) fullResponse += json.response;
        } catch { /* skip */ }
      }
    }
    
    clearTimeout(timeout);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[CTI-Agents] Response: ${fullResponse.length} chars in ${elapsed}s`);
    
    return fullResponse;
  }

  // Helper methods
  private async loadJson<T>(filename: string): Promise<T | null> {
    try {
      const data = await fs.readFile(path.join(this.outputDir, filename), 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      return null;
    }
  }

  private async saveResult(result: CTIAnalysis): Promise<void> {
    await fs.mkdir(this.outputDir, { recursive: true });
    await fs.writeFile(
      path.join(this.outputDir, 'cti-analysis.json'),
      JSON.stringify(result, null, 2)
    );
    console.log('[CTI-Agents] Analysis saved to cti-analysis.json');
  }

  private portToService(port: number): string {
    const services: Record<number, string> = {
      22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
      445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL'
    };
    return services[port] || `Port ${port}`;
  }

  private guessCVESeverity(cve: string): string {
    // Heuristic based on CVE year (recent = potentially more relevant)
    const match = cve.match(/CVE-(\d{4})/);
    if (match) {
      const year = parseInt(match[1]);
      if (year >= 2024) return 'critical';
      if (year >= 2022) return 'high';
      if (year >= 2020) return 'medium';
    }
    return 'medium';
  }
}

export default CTIAgentSystem;
