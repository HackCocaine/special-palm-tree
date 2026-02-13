/**
 * CTI Multi-Agent System - Specialized Threat Intelligence Analysis
 * 
 * Architecture:
 * 1. EXTRACTOR AGENT - Extracts IOCs, TTPs, entities from raw intel
 * 2. CORRELATOR AGENT - Temporal and cross-source correlation analysis
 * 3. ANALYST AGENT - MITRE ATT&CK mapping, kill chain analysis
 * 4. REPORTER AGENT - Executive summary with evidence and recommendations
 * 
 * Standards implemented:
 * - MITRE ATT&CK Framework
 * - STIX 2.1 Terminology
 * - Diamond Model of Intrusion Analysis
 * - Cyber Kill Chain
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { 
  ProcessedData, 
  ShodanScrapedData, 
  XScrapedData,
  ThreatSeverity,
  DataSource 
} from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
// Use qwen2.5:3b for CTI in CI - fast inference, good reasoning
const CTI_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:3b';
// Longer timeout for CPU inference (10 minutes)
const REQUEST_TIMEOUT = parseInt(process.env.CTI_REQUEST_TIMEOUT || '600000', 10);
// Max context size in characters (to avoid overwhelming the model)
const MAX_CONTEXT_SIZE = 8000;

// MITRE ATT&CK Tactics for mapping
const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
];

// Kill Chain Phases
const KILL_CHAIN = [
  'Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation',
  'Installation', 'Command & Control', 'Actions on Objectives'
];

export interface CTIAnalysis {
  timestamp: string;
  model: string;
  
  // Extracted Intelligence
  extraction: {
    iocs: {
      ips: Array<{ value: string; context: string; confidence: number }>;
      domains: Array<{ value: string; context: string; confidence: number }>;
      hashes: Array<{ value: string; type: string; context: string }>;
      cves: Array<{ id: string; description: string; severity: string; exploitability: string }>;
    };
    ttps: Array<{
      technique: string;
      techniqueId: string;
      tactic: string;
      evidence: string;
      confidence: number;
    }>;
    threatActors: Array<{
      name: string;
      aliases: string[];
      motivation: string;
      evidence: string;
    }>;
    malwareFamilies: Array<{
      name: string;
      type: string;
      capabilities: string[];
      evidence: string;
    }>;
  };
  
  // Correlation Analysis
  correlation: {
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
    campaignIndicators: {
      detected: boolean;
      confidence: number;
      description: string;
      relatedSignals: string[];
    };
  };
  
  // Strategic Analysis
  analysis: {
    killChainPhase: string;
    attackSurface: string[];
    riskAssessment: {
      level: 'critical' | 'high' | 'medium' | 'low';
      score: number;
      factors: string[];
    };
    mitreMapping: Array<{
      tactic: string;
      techniques: string[];
      mitigations: string[];
    }>;
    threatLandscape: string;
  };
  
  // Executive Report
  report: {
    headline: string;
    situationSummary: string;
    keyFindings: Array<{
      finding: string;
      severity: string;
      evidence: string;
      recommendation: string;
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

export class CTIAgentSystem {
  private outputDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Warmup the model before analysis (pre-loads into memory)
   */
  private async warmupModel(): Promise<boolean> {
    console.log(`[CTI-Agents] Warming up model ${CTI_MODEL}...`);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 120000); // 2 min for warmup
      
      const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model: CTI_MODEL,
          prompt: 'Respond with OK',
          stream: false,
          options: { num_predict: 5 }
        })
      });
      
      clearTimeout(timeout);
      if (res.ok) {
        console.log('[CTI-Agents] Model warmed up successfully');
        return true;
      }
      return false;
    } catch (err) {
      console.error('[CTI-Agents] Warmup failed:', err);
      return false;
    }
  }

  /**
   * Run the full multi-agent CTI analysis pipeline
   */
  async analyze(): Promise<CTIAnalysis> {
    console.log(`[CTI-Agents] Starting multi-agent analysis with ${CTI_MODEL}`);
    console.log(`[CTI-Agents] Ollama host: ${OLLAMA_HOST}`);
    console.log(`[CTI-Agents] Request timeout: ${REQUEST_TIMEOUT/1000}s`);
    
    // Warmup model first (loads into memory)
    await this.warmupModel();
    
    // Load all available data
    console.log('[CTI-Agents] Loading data files...');
    const processedData = await this.loadJson<ProcessedData>('processed-data.json');
    const shodanData = await this.loadJson<ShodanScrapedData>('shodan-data.json');
    const xData = await this.loadJson<XScrapedData>('x-data.json');
    
    // Log data sizes
    console.log(`[CTI-Agents] Data loaded:`);
    console.log(`  - Shodan: ${shodanData?.hosts?.length || 0} hosts`);
    console.log(`  - X.com: ${xData?.posts?.length || 0} posts`);
    console.log(`  - Processed: ${processedData?.summary?.totalThreats || 0} threats, ${processedData?.indicators?.length || 0} IOCs`);

    if (!processedData && !shodanData && !xData) {
      console.log('[CTI-Agents] No data available for analysis');
      return this.emptyAnalysis();
    }

    // Build comprehensive context
    console.log('[CTI-Agents] Building context for LLM...');
    const context = this.buildContext(processedData, shodanData, xData);
    console.log(`[CTI-Agents] Context size: ${context.length} chars (max: ${MAX_CONTEXT_SIZE})`);
    
    // Run agents sequentially (each builds on previous)
    console.log('[CTI-Agents] Running extraction agent...');
    const extraction = await this.runExtractorAgent(context);
    
    console.log('[CTI-Agents] Running correlation agent...');
    const correlation = await this.runCorrelatorAgent(context, extraction);
    
    console.log('[CTI-Agents] Running analyst agent...');
    const analysis = await this.runAnalystAgent(context, extraction, correlation);
    
    console.log('[CTI-Agents] Running reporter agent...');
    const report = await this.runReporterAgent(context, extraction, correlation, analysis);

    const result: CTIAnalysis = {
      timestamp: new Date().toISOString(),
      model: CTI_MODEL,
      extraction,
      correlation,
      analysis,
      report
    };

    await this.saveResult(result);
    return result;
  }

  /**
   * Build comprehensive context from all sources
   * Pre-processes and summarizes data for efficient LLM analysis
   */
  private buildContext(
    processed: ProcessedData | null,
    shodan: ShodanScrapedData | null,
    xData: XScrapedData | null
  ): string {
    const sections: string[] = [];

    // Infrastructure Intelligence (Shodan) - summarized
    if (shodan && shodan.hosts.length > 0) {
      const infraSummary = this.summarizeInfrastructure(shodan);
      sections.push(`=== INFRASTRUCTURE INTELLIGENCE (Shodan) ===\n${infraSummary}`);
    }

    // Social Intelligence (X.com) - summarized
    if (xData && xData.posts.length > 0) {
      const socialSummary = this.summarizeSocialIntel(xData);
      sections.push(`=== SOCIAL INTELLIGENCE (X.com) ===\n${socialSummary}`);
    }

    // Processed Threats and Indicators - summarized
    if (processed) {
      const processedSummary = this.summarizeProcessedData(processed);
      sections.push(`=== PROCESSED THREAT DATA ===\n${processedSummary}`);
    }

    let context = sections.join('\n\n');
    
    // Truncate if too large (to avoid overwhelming the model)
    if (context.length > MAX_CONTEXT_SIZE) {
      console.log(`[CTI-Agents] Context too large (${context.length}), truncating to ${MAX_CONTEXT_SIZE}`);
      context = context.substring(0, MAX_CONTEXT_SIZE) + '\n\n[... truncated for brevity ...]';
    }

    return context;
  }

  private summarizeInfrastructure(shodan: ShodanScrapedData): string {
    const hosts = shodan.hosts;
    const lines: string[] = [];
    
    lines.push(`Total hosts scanned: ${hosts.length}`);
    
    // Port distribution
    const portCounts = new Map<number, number>();
    const vulnHosts: Array<{ ip: string; port: number; vulns: string[] }> = [];
    
    for (const host of hosts) {
      portCounts.set(host.port, (portCounts.get(host.port) || 0) + 1);
      if (host.vulns && host.vulns.length > 0) {
        vulnHosts.push({ ip: host.ip, port: host.port, vulns: host.vulns });
      }
    }
    
    lines.push(`\nExposed ports:`);
    for (const [port, count] of Array.from(portCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5)) {
      const service = this.portToService(port);
      lines.push(`  - Port ${port} (${service}): ${count} hosts`);
    }
    
    if (vulnHosts.length > 0) {
      lines.push(`\nVulnerable hosts (${vulnHosts.length} total):`);
      for (const vh of vulnHosts.slice(0, 10)) {
        lines.push(`  - ${vh.ip}:${vh.port} - CVEs: ${vh.vulns.join(', ')}`);
      }
    }
    
    // Sample IPs for evidence
    lines.push(`\nSample IPs (for verification):`);
    for (const host of hosts.slice(0, 5)) {
      lines.push(`  - ${host.ip}:${host.port} (${host.product || 'unknown'}) - Shodan: https://www.shodan.io/host/${host.ip}`);
    }
    
    return lines.join('\n');
  }

  private summarizeSocialIntel(xData: XScrapedData): string {
    const posts = xData.posts;
    const lines: string[] = [];
    
    lines.push(`Total posts: ${posts.length}`);
    
    // Sort by engagement, take top 5 only (concise)
    const sortedPosts = [...posts].sort((a, b) => 
      (b.metrics.likes + b.metrics.reposts) - (a.metrics.likes + a.metrics.reposts)
    ).slice(0, 5);
    
    lines.push(`\\nTop posts:`);
    for (const post of sortedPosts) {
      const engagement = post.metrics.likes + post.metrics.reposts;
      const url = post.id 
        ? `https://x.com/${post.author.username}/status/${post.id}`
        : '';
      
      // Concise format: one line per post
      const text = post.text.substring(0, 150).replace(/\\n/g, ' ');
      lines.push(`- @${post.author.username}: "${text}..." (${engagement} eng) ${url}`.trim());
    }
    
    return lines.join('\\n');
  }

  private summarizeProcessedData(data: ProcessedData): string {
    const lines: string[] = [];
    
    lines.push(`Total threats: ${data.summary.totalThreats}`);
    lines.push(`Severity breakdown: Critical=${data.summary.bySeverity.critical || 0}, High=${data.summary.bySeverity.high || 0}, Medium=${data.summary.bySeverity.medium || 0}`);
    
    lines.push(`\nCategories:`);
    for (const [cat, count] of Object.entries(data.summary.byCategory)) {
      lines.push(`  - ${cat}: ${count}`);
    }
    
    lines.push(`\nIndicators of Compromise (${data.indicators.length} total):`);
    const iocsByType = new Map<string, string[]>();
    for (const ioc of data.indicators) {
      if (!iocsByType.has(ioc.type)) iocsByType.set(ioc.type, []);
      iocsByType.get(ioc.type)!.push(ioc.value);
    }
    for (const [type, values] of iocsByType) {
      lines.push(`  ${type}: ${values.slice(0, 5).join(', ')}${values.length > 5 ? ` (+${values.length - 5} more)` : ''}`);
    }
    
    return lines.join('\n');
  }

  /**
   * AGENT 1: Extraction Agent
   * Extracts structured IOCs, TTPs, threat actors from raw intel
   */
  private async runExtractorAgent(context: string): Promise<CTIAnalysis['extraction']> {
    const prompt = `You are a CTI Extraction Specialist. Your role is to extract structured threat intelligence from raw data.

CONTEXT DATA:
${context}

EXTRACTION TASK:
Extract ALL indicators of compromise (IOCs), tactics/techniques/procedures (TTPs), threat actors, and malware families.

For TTPs, map to MITRE ATT&CK where possible. Available tactics: ${MITRE_TACTICS.join(', ')}

RESPOND WITH VALID JSON:
{
  "iocs": {
    "ips": [{"value": "x.x.x.x", "context": "why this IP is significant", "confidence": 0.0-1.0}],
    "domains": [{"value": "domain.com", "context": "why significant", "confidence": 0.0-1.0}],
    "hashes": [{"value": "hash", "type": "md5|sha1|sha256", "context": "what malware"}],
    "cves": [{"id": "CVE-XXXX-XXXXX", "description": "what it does", "severity": "critical|high|medium|low", "exploitability": "active|proof-of-concept|theoretical"}]
  },
  "ttps": [{"technique": "technique name", "techniqueId": "T1XXX", "tactic": "tactic name", "evidence": "what indicates this", "confidence": 0.0-1.0}],
  "threatActors": [{"name": "actor name", "aliases": [], "motivation": "financial|espionage|hacktivism|unknown", "evidence": "what indicates this actor"}],
  "malwareFamilies": [{"name": "malware name", "type": "ransomware|trojan|worm|apt-tool", "capabilities": [], "evidence": "what indicates this malware"}]
}

Be thorough but only include items with actual evidence from the context. Set confidence based on evidence strength.`;

    const response = await this.callOllama(prompt);
    return this.parseJsonResponse(response, {
      iocs: { ips: [], domains: [], hashes: [], cves: [] },
      ttps: [],
      threatActors: [],
      malwareFamilies: []
    });
  }

  /**
   * AGENT 2: Correlator Agent
   * Analyzes temporal patterns and cross-source correlations
   */
  private async runCorrelatorAgent(
    context: string, 
    extraction: CTIAnalysis['extraction']
  ): Promise<CTIAnalysis['correlation']> {
    const prompt = `You are a CTI Correlation Analyst. Your role is to identify patterns and connections across intelligence sources.

CONTEXT DATA:
${context}

EXTRACTED INTELLIGENCE:
${JSON.stringify(extraction, null, 2)}

CORRELATION TASK:
1. Identify TEMPORAL PATTERNS - what happened when, in what sequence
2. Find CROSS-SOURCE LINKS - connections between infrastructure (Shodan) and social (X.com) signals
3. Detect CAMPAIGN INDICATORS - signs of coordinated activity

For each finding, provide specific EVIDENCE with source URLs where available.

RESPOND WITH VALID JSON:
{
  "temporalPatterns": [{
    "pattern": "pattern name",
    "description": "detailed description of what was observed",
    "timeframe": "e.g., within last 24h, Feb 12-13",
    "confidence": 0.0-1.0,
    "evidence": [{"source": "Shodan|X.com", "excerpt": "relevant text", "url": "direct link to evidence"}]
  }],
  "crossSourceLinks": [{
    "infraSignal": "what was seen in infrastructure data",
    "socialSignal": "what was discussed on social media",
    "relationship": "how they connect",
    "timeDelta": "time difference between observations",
    "significance": "why this correlation matters"
  }],
  "campaignIndicators": {
    "detected": true|false,
    "confidence": 0.0-1.0,
    "description": "description of potential campaign",
    "relatedSignals": ["list of related signals"]
  }
}

Focus on actionable correlations. Include direct URLs for verification.`;

    const response = await this.callOllama(prompt);
    return this.parseJsonResponse(response, {
      temporalPatterns: [],
      crossSourceLinks: [],
      campaignIndicators: { detected: false, confidence: 0, description: '', relatedSignals: [] }
    });
  }

  /**
   * AGENT 3: Analyst Agent
   * Strategic analysis using MITRE ATT&CK and Kill Chain
   */
  private async runAnalystAgent(
    context: string,
    extraction: CTIAnalysis['extraction'],
    correlation: CTIAnalysis['correlation']
  ): Promise<CTIAnalysis['analysis']> {
    const prompt = `You are a Senior CTI Analyst. Your role is to provide strategic threat analysis.

CONTEXT:
${context}

EXTRACTED IOCs & TTPs:
${JSON.stringify(extraction, null, 2)}

CORRELATION FINDINGS:
${JSON.stringify(correlation, null, 2)}

ANALYSIS TASK:
1. Determine the KILL CHAIN PHASE of observed activity: ${KILL_CHAIN.join(' → ')}
2. Identify the ATTACK SURFACE at risk
3. Assess RISK LEVEL with specific factors
4. Map findings to MITRE ATT&CK with recommended mitigations
5. Summarize the overall THREAT LANDSCAPE

RESPOND WITH VALID JSON:
{
  "killChainPhase": "current phase from: ${KILL_CHAIN.join(', ')}",
  "attackSurface": ["list of exposed assets/services at risk"],
  "riskAssessment": {
    "level": "critical|high|medium|low",
    "score": 0-100,
    "factors": ["specific factors contributing to risk level"]
  },
  "mitreMapping": [{
    "tactic": "tactic name",
    "techniques": ["T1xxx - technique names"],
    "mitigations": ["M1xxx - specific mitigations or actions"]
  }],
  "threatLandscape": "2-3 sentence summary of the current threat environment based on this intelligence"
}

Be specific and reference actual findings from the data.`;

    const response = await this.callOllama(prompt);
    return this.parseJsonResponse(response, {
      killChainPhase: 'Reconnaissance',
      attackSurface: [],
      riskAssessment: { level: 'medium', score: 50, factors: [] },
      mitreMapping: [],
      threatLandscape: 'Insufficient data for threat landscape assessment.'
    });
  }

  /**
   * AGENT 4: Reporter Agent
   * Generates executive summary with evidence and recommendations
   */
  private async runReporterAgent(
    context: string,
    extraction: CTIAnalysis['extraction'],
    correlation: CTIAnalysis['correlation'],
    analysis: CTIAnalysis['analysis']
  ): Promise<CTIAnalysis['report']> {
    const prompt = `You are a CTI Report Writer. Your role is to create an executive intelligence briefing.

ALL ANALYSIS DATA:
Extraction: ${JSON.stringify(extraction, null, 2)}
Correlation: ${JSON.stringify(correlation, null, 2)}
Analysis: ${JSON.stringify(analysis, null, 2)}

REPORT TASK:
Create an EXECUTIVE BRIEFING suitable for security leadership. Include:
1. Attention-grabbing HEADLINE
2. SITUATION SUMMARY (2-3 paragraphs)
3. KEY FINDINGS with severity, evidence, and specific recommendations
4. IMMEDIATE ACTIONS (within 24-48 hours)
5. STRATEGIC RECOMMENDATIONS (longer term)
6. SOURCES AND REFERENCES with clickable URLs

IMPORTANT: Every finding MUST be backed by evidence with a reference URL.

RESPOND WITH VALID JSON:
{
  "headline": "attention-grabbing headline for the briefing",
  "situationSummary": "2-3 paragraph executive summary of the threat situation",
  "keyFindings": [{
    "finding": "what was discovered",
    "severity": "critical|high|medium|low",
    "evidence": "specific evidence supporting this finding",
    "recommendation": "what to do about it"
  }],
  "immediateActions": ["action 1", "action 2"],
  "strategicRecommendations": ["recommendation 1", "recommendation 2"],
  "sourcesAndReferences": [{
    "source": "source name",
    "url": "direct URL to evidence",
    "relevance": "why this source matters"
  }]
}

Write for a non-technical executive audience while maintaining technical accuracy.`;

    const response = await this.callOllama(prompt);
    return this.parseJsonResponse(response, {
      headline: 'Threat Intelligence Analysis Complete',
      situationSummary: 'Analysis completed. See key findings for details.',
      keyFindings: [],
      immediateActions: [],
      strategicRecommendations: [],
      sourcesAndReferences: []
    });
  }

  /**
   * Call Ollama API with streaming (avoids HeadersTimeout) and retry logic
   */
  private async callOllama(prompt: string, retries = 2): Promise<string> {
    const promptSize = prompt.length;
    const estimatedTokens = Math.ceil(promptSize / 4);
    
    console.log(`[CTI-Agents] Prompt: ${promptSize} chars (~${estimatedTokens} tokens)`);
    
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        console.log(`[CTI-Agents] Attempt ${attempt + 1}/${retries + 1}: Calling Ollama (streaming)...`);
        const startTime = Date.now();
        
        // Use streaming to avoid headers timeout - model responds immediately
        const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({
            model: CTI_MODEL,
            prompt,
            stream: true,  // Stream to avoid timeout waiting for full response
            options: {
              temperature: 0.3,
              num_predict: 1500,
              top_p: 0.9,
              top_k: 40
            }
          })
        });

        if (!res.ok) {
          const errorText = await res.text().catch(() => 'no body');
          throw new Error(`HTTP ${res.status}: ${errorText}`);
        }
        
        // Accumulate streaming response
        const reader = res.body?.getReader();
        if (!reader) throw new Error('No response body');
        
        const decoder = new TextDecoder();
        let fullResponse = '';
        let tokenCount = 0;
        
        console.log('[CTI-Agents] Receiving stream...');
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value, { stream: true });
          // Each line is a JSON object with "response" field
          for (const line of chunk.split('\\n')) {
            if (!line.trim()) continue;
            try {
              const json = JSON.parse(line) as { response?: string; done?: boolean; eval_count?: number };
              if (json.response) {
                fullResponse += json.response;
              }
              if (json.eval_count) tokenCount = json.eval_count;
            } catch {
              // Ignore parse errors for incomplete lines
            }
          }
        }
        
        clearTimeout(timeout);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`[CTI-Agents] ✓ Response: ${fullResponse.length} chars in ${elapsed}s (tokens: ${tokenCount || 'N/A'})`);
        
        return fullResponse;
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        const errCause = err instanceof Error && 'cause' in err ? (err.cause as Error)?.message : '';
        console.error(`[CTI-Agents] ✗ Attempt ${attempt + 1} failed:`);
        console.error(`  Error: ${errMsg}`);
        if (errCause) console.error(`  Cause: ${errCause}`);
        
        if (attempt === retries) throw err;
        await this.sleep(2000);
      }
    }
    throw new Error('All retries exhausted');
  }

  /**
   * Parse JSON from LLM response with fallback
   */
  private parseJsonResponse<T>(raw: string, fallback: T): T {
    try {
      // Try to find JSON in response
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as T;
      }
    } catch (err) {
      console.log('[CTI-Agents] Failed to parse JSON response');
    }
    return fallback;
  }

  private portToService(port: number): string {
    const services: Record<number, string> = {
      22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
      445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
      6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch'
    };
    return services[port] || `Port ${port}`;
  }

  private async loadJson<T>(filename: string): Promise<T | null> {
    try {
      const raw = await fs.readFile(path.join(this.outputDir, filename), 'utf-8');
      return JSON.parse(raw);
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

  private emptyAnalysis(): CTIAnalysis {
    return {
      timestamp: new Date().toISOString(),
      model: CTI_MODEL,
      extraction: {
        iocs: { ips: [], domains: [], hashes: [], cves: [] },
        ttps: [],
        threatActors: [],
        malwareFamilies: []
      },
      correlation: {
        temporalPatterns: [],
        crossSourceLinks: [],
        campaignIndicators: { detected: false, confidence: 0, description: '', relatedSignals: [] }
      },
      analysis: {
        killChainPhase: 'Unknown',
        attackSurface: [],
        riskAssessment: { level: 'low', score: 0, factors: [] },
        mitreMapping: [],
        threatLandscape: 'Insufficient data for analysis.'
      },
      report: {
        headline: 'No Intelligence Available',
        situationSummary: 'No data available for analysis.',
        keyFindings: [],
        immediateActions: [],
        strategicRecommendations: [],
        sourcesAndReferences: []
      }
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export default CTIAgentSystem;
