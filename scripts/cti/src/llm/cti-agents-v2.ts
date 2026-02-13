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
    ips: Array<{ value: string; port: number; service: string; url: string }>;
    cves: Array<{ id: string; severity: string; url: string }>;
    ttps: Array<{ id: string; name: string; tactic: string; evidence: string }>;
    socialPosts: Array<{ author: string; text: string; url: string; engagement: number }>;
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
    
    // STEP 2: Build concise context for LLM
    const context = this.buildContext(extraction, processed);
    console.log(`[CTI-Agents] Context: ${context.length} chars`);
    
    // STEP 3: Single LLM call for narrative analysis
    console.log('[CTI-Agents] Running LLM analysis...');
    const llmAnalysis = await this.runLLMAnalysis(context);
    
    const result: CTIAnalysis = {
      timestamp: new Date().toISOString(),
      model: CTI_MODEL,
      extraction,
      analysis: llmAnalysis
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
      
      // Map ports to TTPs
      const ports = new Set(shodan.hosts.map(h => h.port));
      if (ports.has(22)) ttps.push({ ...MITRE_MAPPINGS['port 22'], evidence: 'SSH exposed on port 22' });
      if (ports.has(3389)) ttps.push({ ...MITRE_MAPPINGS['port 3389'], evidence: 'RDP exposed on port 3389' });
      if (ports.has(445)) ttps.push({ ...MITRE_MAPPINGS['port 445'], evidence: 'SMB exposed on port 445' });
    }
    
    // Extract from X.com posts
    if (xData?.posts) {
      const sortedPosts = [...xData.posts]
        .sort((a, b) => (b.metrics.likes + b.metrics.reposts) - (a.metrics.likes + a.metrics.reposts))
        .slice(0, 10);
      
      for (const post of sortedPosts) {
        socialPosts.push({
          author: `@${post.author.username}`,
          text: post.text.substring(0, 200),
          url: post.id ? `https://x.com/${post.author.username}/status/${post.id}` : '',
          engagement: post.metrics.likes + post.metrics.reposts
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
    
    return { ips, cves, ttps, socialPosts };
  }

  /**
   * Build concise context for LLM (just the facts)
   */
  private buildContext(extraction: CTIAnalysis['extraction'], processed: ProcessedData | null): string {
    const lines: string[] = [];
    
    lines.push('=== THREAT INTELLIGENCE SUMMARY ===');
    lines.push(`Date: ${new Date().toISOString().split('T')[0]}`);
    lines.push('');
    
    // Infrastructure findings
    if (extraction.ips.length > 0) {
      lines.push(`INFRASTRUCTURE: ${extraction.ips.length} exposed hosts detected`);
      const portCounts: Record<number, number> = {};
      extraction.ips.forEach(ip => portCounts[ip.port] = (portCounts[ip.port] || 0) + 1);
      for (const [port, count] of Object.entries(portCounts).slice(0, 5)) {
        lines.push(`  - Port ${port}: ${count} hosts`);
      }
    }
    
    // Vulnerabilities
    if (extraction.cves.length > 0) {
      lines.push(`\nVULNERABILITIES: ${extraction.cves.length} CVEs identified`);
      for (const cve of extraction.cves.slice(0, 5)) {
        lines.push(`  - ${cve.id} (${cve.severity})`);
      }
    }
    
    // TTPs
    if (extraction.ttps.length > 0) {
      lines.push(`\nTECHNIQUES (MITRE ATT&CK):`);
      for (const ttp of extraction.ttps) {
        lines.push(`  - ${ttp.id}: ${ttp.name} (${ttp.tactic})`);
      }
    }
    
    // Social intel
    if (extraction.socialPosts.length > 0) {
      lines.push(`\nSOCIAL INTELLIGENCE: ${extraction.socialPosts.length} relevant posts`);
      for (const post of extraction.socialPosts.slice(0, 3)) {
        lines.push(`  - ${post.author}: "${post.text.substring(0, 100)}..."`);
      }
    }
    
    // Threat summary
    if (processed?.summary) {
      lines.push(`\nTHREAT COUNTS: ${processed.summary.totalThreats} total`);
      lines.push(`  Critical: ${processed.summary.bySeverity?.critical || 0}`);
      lines.push(`  High: ${processed.summary.bySeverity?.high || 0}`);
      lines.push(`  Medium: ${processed.summary.bySeverity?.medium || 0}`);
    }
    
    return lines.join('\n');
  }

  /**
   * Single LLM call for narrative analysis
   */
  private async runLLMAnalysis(context: string): Promise<CTIAnalysis['analysis']> {
    const prompt = `You are a cybersecurity analyst. Analyze this threat intelligence and provide a brief assessment.

${context}

Write a SHORT analysis (max 500 words) with these sections:

SUMMARY: One paragraph overview of the threat landscape.

KEY FINDINGS: List 3-5 bullet points of the most important findings.

RISK LEVEL: State if risk is CRITICAL, HIGH, MEDIUM, or LOW with a score 0-100.

RECOMMENDATIONS: List 3-5 actionable security recommendations.

Be concise and factual. Base analysis only on the data provided.`;

    try {
      const response = await this.callOllama(prompt);
      return this.parseTextResponse(response);
    } catch (err) {
      console.error('[CTI-Agents] LLM analysis failed:', err);
      return this.fallbackAnalysis(context);
    }
  }

  /**
   * Parse text response into structured sections
   */
  private parseTextResponse(text: string): CTIAnalysis['analysis'] {
    // Extract sections by headers
    const summaryMatch = text.match(/SUMMARY[:\s]*([^]*?)(?=KEY FINDINGS|RISK|$)/i);
    const findingsMatch = text.match(/KEY FINDINGS[:\s]*([^]*?)(?=RISK|RECOMMENDATIONS|$)/i);
    const riskMatch = text.match(/RISK[:\s]*([^]*?)(?=RECOMMENDATIONS|$)/i);
    const recsMatch = text.match(/RECOMMENDATIONS[:\s]*([^]*?)$/i);
    
    // Parse bullet points
    const parseBullets = (text: string): string[] => {
      const bullets = text.match(/[-•*]\s*(.+)/g) || [];
      return bullets.map(b => b.replace(/^[-•*]\s*/, '').trim()).filter(b => b.length > 0);
    };
    
    // Parse risk level
    let riskLevel: 'critical' | 'high' | 'medium' | 'low' = 'medium';
    let riskScore = 50;
    if (riskMatch) {
      const riskText = riskMatch[1].toLowerCase();
      if (riskText.includes('critical')) { riskLevel = 'critical'; riskScore = 85; }
      else if (riskText.includes('high')) { riskLevel = 'high'; riskScore = 70; }
      else if (riskText.includes('low')) { riskLevel = 'low'; riskScore = 25; }
      
      // Try to extract score
      const scoreMatch = riskText.match(/(\d+)/);
      if (scoreMatch) riskScore = Math.min(100, Math.max(0, parseInt(scoreMatch[1])));
    }
    
    // Determine kill chain phase from content
    const allText = text.toLowerCase();
    let killChainPhase = 'Reconnaissance';
    if (allText.includes('exploit') || allText.includes('vulnerab')) killChainPhase = 'Exploitation';
    else if (allText.includes('malware') || allText.includes('payload')) killChainPhase = 'Delivery';
    else if (allText.includes('c2') || allText.includes('command')) killChainPhase = 'Command & Control';
    else if (allText.includes('exfil') || allText.includes('data theft')) killChainPhase = 'Actions on Objectives';
    
    return {
      summary: (summaryMatch?.[1] || 'Analysis completed based on available data.').trim(),
      keyFindings: parseBullets(findingsMatch?.[1] || ''),
      riskLevel,
      riskScore,
      recommendations: parseBullets(recsMatch?.[1] || ''),
      killChainPhase
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
