/**
 * CTI Minimal Orchestrator - Sequential Two-Model Architecture
 * 
 * Based on: "Minimal Multi-LLM Threat Signal Correlation Architecture"
 * 
 * Models:
 * - STRATEGIC (Mistral/Phi): Context understanding + hypothesis generation
 * - TECHNICAL (Qwen 3B): Technical validation + exploit reasoning
 * 
 * Sequential Workflow:
 * 1. X Signal Digest (Strategic)
 * 2. Shodan Snapshot Digest (Pre-process)
 * 3. Technical Validation (Qwen)
 * 4. Strategic Synthesis (Strategic)
 * 5. Dashboard JSON Structuring (Strategic)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { XScrapedData, XPost, ShodanScrapedData, ShodanHost } from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const STRATEGIC_MODEL = process.env.OLLAMA_MODEL_STRATEGIC || 'mistral:7b-instruct-q4_0';
const TECHNICAL_MODEL = process.env.OLLAMA_MODEL_TECHNICAL || 'saki007ster/CybersecurityRiskAnalyst';
// 10 minutes timeout for CPU inference in GitHub Actions
const REQUEST_TIMEOUT = parseInt(process.env.CTI_REQUEST_TIMEOUT || '600000', 10);
const MAX_RETRIES = parseInt(process.env.CTI_MAX_RETRIES || '2', 10);

// Token budget (~20k context strategy)
const MAX_X_SUMMARY_TOKENS = 3000;
const MAX_SHODAN_DIGEST_TOKENS = 4000;
const MAX_VALIDATION_TOKENS = 3000;

export interface CTIDashboardOutput {
  date: string;
  summary: string;
  confidence: 'low' | 'moderate' | 'high';
  observed_cves: string[];
  infrastructure_signals: Array<{
    type: string;
    count: number;
    description: string;
  }>;
  correlation_strength: 'weak' | 'moderate' | 'strong';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  // Additional context for dashboard
  x_intel_summary: string;
  shodan_summary: string;
  technical_assessment: string;
  recommended_actions: string[];
}

export interface OrchestratorResult {
  success: boolean;
  dashboard: CTIDashboardOutput;
  intermediateOutputs: {
    xDigest: string;
    shodanDigest: ShodanDigest;
    technicalValidation: string;
    strategicSynthesis: string;
  };
  error?: string;
}

interface ShodanDigest {
  totalHosts: number;
  topPorts: Array<{ port: number; service: string; count: number }>;
  topCountries: Array<{ country: string; count: number }>;
  vulnerableHosts: number;
  uniqueCVEs: string[];
  bannerPatterns: string[];
  deltaVsYesterday?: string;
}

export class CTIOrchestrator {
  private outputDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Main orchestration - Sequential two-model workflow
   */
  async run(): Promise<OrchestratorResult> {
    console.log('[Orchestrator] Starting minimal CTI pipeline...');
    console.log(`  Strategic: ${STRATEGIC_MODEL}`);
    console.log(`  Technical: ${TECHNICAL_MODEL}`);

    try {
      // Load raw data from scrapers
      const xData = await this.loadJson<XScrapedData>('x-data.json');
      const shodanData = await this.loadJson<ShodanScrapedData>('shodan-data.json');

      // Step 1: X Signal Digest (Strategic Model)
      console.log('\n[Step 1] X Signal Digest...');
      const xDigest = await this.generateXDigest(xData);
      console.log(`  ✓ X digest generated (${xDigest.length} chars)`);

      // Step 2: Shodan Snapshot Digest (Pre-process - no LLM needed)
      console.log('\n[Step 2] Shodan Snapshot Digest...');
      const shodanDigest = this.preprocessShodanData(shodanData);
      console.log(`  ✓ Shodan digest: ${shodanDigest.totalHosts} hosts, ${shodanDigest.uniqueCVEs.length} CVEs`);

      // Step 3: Technical Validation (Qwen 3B)
      console.log('\n[Step 3] Technical Validation...');
      const technicalValidation = await this.generateTechnicalValidation(xDigest, shodanDigest);
      console.log(`  ✓ Technical validation complete (${technicalValidation.length} chars)`);

      // Step 4: Strategic Synthesis (Strategic Model)
      console.log('\n[Step 4] Strategic Synthesis...');
      const strategicSynthesis = await this.generateStrategicSynthesis(
        xDigest, 
        shodanDigest, 
        technicalValidation
      );
      console.log(`  ✓ Strategic synthesis complete (${strategicSynthesis.length} chars)`);

      // Step 5: Dashboard JSON Structuring (Strategic Model)
      console.log('\n[Step 5] Dashboard JSON Generation...');
      const dashboard = await this.generateDashboardJSON(
        strategicSynthesis,
        xDigest,
        shodanDigest,
        technicalValidation
      );
      console.log(`  ✓ Dashboard JSON generated`);

      // Save intermediate outputs for debugging
      await this.saveIntermediateOutputs({
        xDigest,
        shodanDigest,
        technicalValidation,
        strategicSynthesis
      });

      return {
        success: true,
        dashboard,
        intermediateOutputs: {
          xDigest,
          shodanDigest,
          technicalValidation,
          strategicSynthesis
        }
      };

    } catch (error) {
      console.error('[Orchestrator] Pipeline failed:', error);
      return {
        success: false,
        dashboard: this.getEmptyDashboard(),
        intermediateOutputs: {
          xDigest: '',
          shodanDigest: this.getEmptyShodanDigest(),
          technicalValidation: '',
          strategicSynthesis: ''
        },
        error: String(error)
      };
    }
  }

  /**
   * Step 1: X Signal Digest using Strategic Model
   * Summarizes X posts into emerging themes, IoCs, CVEs, campaign intent
   */
  private async generateXDigest(xData: XScrapedData | null): Promise<string> {
    if (!xData || xData.posts.length === 0) {
      return 'No X.com social intelligence available for analysis.';
    }

    // Pre-filter: Remove replies, retweets without commentary, deduplicate
    const filteredPosts = this.filterXPosts(xData.posts);
    
    // Compress into token-efficient format
    const postsText = filteredPosts
      .slice(0, 20) // Max 20 posts for context efficiency
      .map((p, i) => `[${i + 1}] @${p.author.username}: ${this.truncate(p.text, 200)}`)
      .join('\n');

    const prompt = `You are a cyber threat intelligence analyst. Analyze the following X.com posts for threat signals.

POSTS:
${postsText}

Provide a structured analysis in natural language:

1. EMERGING THEMES: What threat topics are being discussed?
2. MENTIONED CVEs: List any CVE identifiers found (CVE-XXXX-XXXXX format)
3. MENTIONED IoCs: IPs, domains, hashes mentioned
4. EXPLOITATION TRENDS: Any active exploitation claims?
5. TONE ASSESSMENT: Speculative vs confirmed intelligence
6. CAMPAIGN INDICATORS: Any signs of coordinated activity?

Keep your response under 800 words. Focus on actionable intelligence.`;

    return await this.callOllama(STRATEGIC_MODEL, prompt);
  }

  /**
   * Step 2: Pre-process Shodan data without LLM
   * Aggregates and compresses infrastructure data
   */
  private preprocessShodanData(shodanData: ShodanScrapedData | null): ShodanDigest {
    if (!shodanData || shodanData.hosts.length === 0) {
      return this.getEmptyShodanDigest();
    }

    const hosts = shodanData.hosts;

    // Aggregate port frequency
    const portCounts: Record<string, { port: number; service: string; count: number }> = {};
    hosts.forEach(h => {
      const key = `${h.port}`;
      if (!portCounts[key]) {
        portCounts[key] = { port: h.port, service: h.product || 'unknown', count: 0 };
      }
      portCounts[key].count++;
      // Update service name if more specific
      if (h.product && h.product !== 'unknown') {
        portCounts[key].service = h.product;
      }
    });

    // Aggregate country frequency
    const countryCounts: Record<string, number> = {};
    hosts.forEach(h => {
      const country = h.country || 'Unknown';
      countryCounts[country] = (countryCounts[country] || 0) + 1;
    });

    // Collect unique CVEs
    const allCVEs = new Set<string>();
    hosts.forEach(h => {
      if (h.vulns) {
        h.vulns.forEach(cve => allCVEs.add(cve));
      }
    });

    // Collect banner patterns (unique services/versions)
    const bannerPatterns = new Set<string>();
    hosts.forEach(h => {
      if (h.product && h.version) {
        bannerPatterns.add(`${h.product} ${h.version}`);
      }
    });

    // Count vulnerable hosts
    const vulnerableHosts = hosts.filter(h => h.vulns && h.vulns.length > 0).length;

    return {
      totalHosts: hosts.length,
      topPorts: Object.values(portCounts)
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      topCountries: Object.entries(countryCounts)
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
      vulnerableHosts,
      uniqueCVEs: Array.from(allCVEs).slice(0, 20),
      bannerPatterns: Array.from(bannerPatterns).slice(0, 10)
    };
  }

  /**
   * Step 3: Technical Validation using Qwen 3B
   * Evaluates correlation between X intel and Shodan infrastructure
   */
  private async generateTechnicalValidation(
    xDigest: string, 
    shodanDigest: ShodanDigest
  ): Promise<string> {
    // Format Shodan digest as text
    const shodanText = this.formatShodanDigest(shodanDigest);

    const prompt = `You are a technical cybersecurity analyst. Analyze the correlation between social intelligence and infrastructure data.

SOCIAL INTELLIGENCE SUMMARY:
${this.truncate(xDigest, 2000)}

INFRASTRUCTURE DATA:
${shodanText}

Evaluate and respond with:

1. EXPLOIT PLAUSIBILITY: Do the CVEs mentioned socially match exposed infrastructure?
2. SERVICE-CVE ALIGNMENT: Which exposed services could be vulnerable to mentioned exploits?
3. INFRASTRUCTURE REUSE LIKELIHOOD: Any patterns suggesting coordinated infrastructure?
4. TACTICAL ASSESSMENT: Is this opportunistic scanning or targeted campaign?
5. CONFIDENCE LEVEL: Rate your assessment (low/moderate/high)

Be concise and technical. Under 500 words.`;

    return await this.callOllama(TECHNICAL_MODEL, prompt);
  }

  /**
   * Step 4: Strategic Synthesis using Strategic Model
   * Combines all analysis into executive-ready summary
   */
  private async generateStrategicSynthesis(
    xDigest: string,
    shodanDigest: ShodanDigest,
    technicalValidation: string
  ): Promise<string> {
    const shodanText = this.formatShodanDigest(shodanDigest);

    const prompt = `You are a senior threat intelligence analyst. Synthesize the following intelligence into an executive summary.

SOCIAL INTELLIGENCE (X.com):
${this.truncate(xDigest, 1500)}

INFRASTRUCTURE PATTERNS (Shodan):
${shodanText}

TECHNICAL ASSESSMENT:
${this.truncate(technicalValidation, 1500)}

Produce a synthesis with:

1. EXECUTIVE SUMMARY: 2-3 sentence overview for leadership
2. CORRELATION REASONING: How social chatter relates to infrastructure exposure
3. CONFIDENCE ESTIMATE: low / moderate / high - and why
4. RISK INTERPRETATION: What does this mean for defensive posture?
5. RECOMMENDED ACTIONS: Top 3 immediate actions

Write in clear, professional English. Under 600 words.`;

    return await this.callOllama(STRATEGIC_MODEL, prompt);
  }

  /**
   * Step 5: Generate Dashboard JSON
   * Final structured output for visualization
   */
  private async generateDashboardJSON(
    synthesis: string,
    xDigest: string,
    shodanDigest: ShodanDigest,
    technicalValidation: string
  ): Promise<CTIDashboardOutput> {
    // Extract CVEs from both sources
    const cvePattern = /CVE-\d{4}-\d{4,7}/gi;
    const allText = `${xDigest} ${technicalValidation} ${synthesis}`;
    const mentionedCVEs = [...new Set(allText.match(cvePattern) || [])];
    const combinedCVEs = [...new Set([...mentionedCVEs, ...shodanDigest.uniqueCVEs])];

    // Use LLM to structure final JSON
    const prompt = `Convert the following threat intelligence synthesis into a JSON structure.

SYNTHESIS:
${this.truncate(synthesis, 2000)}

Return ONLY valid JSON with this exact structure (no markdown, no explanation):
{
  "summary": "1-2 sentence executive summary",
  "confidence": "low|moderate|high",
  "correlation_strength": "weak|moderate|strong",
  "risk_level": "low|medium|high|critical",
  "recommended_actions": ["action1", "action2", "action3"]
}`;

    let llmStructure: Record<string, unknown> = {};
    try {
      const response = await this.callOllama(STRATEGIC_MODEL, prompt);
      // Extract JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        llmStructure = JSON.parse(jsonMatch[0]);
      }
    } catch {
      console.log('  Warning: LLM JSON extraction failed, using defaults');
    }

    // Build final dashboard output with fallbacks
    const dashboard: CTIDashboardOutput = {
      date: new Date().toISOString(),
      summary: String(llmStructure.summary || 'Threat intelligence analysis completed. See detailed sections for findings.'),
      confidence: this.validateConfidence(String(llmStructure.confidence || 'moderate')),
      observed_cves: combinedCVEs.slice(0, 15),
      infrastructure_signals: shodanDigest.topPorts.slice(0, 5).map(p => ({
        type: 'exposed_service',
        count: p.count,
        description: `${p.service} on port ${p.port}`
      })),
      correlation_strength: this.validateCorrelation(String(llmStructure.correlation_strength || 'moderate')),
      risk_level: this.validateRiskLevel(String(llmStructure.risk_level || 'medium')),
      x_intel_summary: this.truncate(xDigest, 500),
      shodan_summary: `${shodanDigest.totalHosts} hosts scanned, ${shodanDigest.vulnerableHosts} vulnerable, ${shodanDigest.uniqueCVEs.length} unique CVEs`,
      technical_assessment: this.truncate(technicalValidation, 500),
      recommended_actions: Array.isArray(llmStructure.recommended_actions) 
        ? llmStructure.recommended_actions.slice(0, 5)
        : ['Monitor threat feeds', 'Patch critical vulnerabilities', 'Review exposed services']
    };

    return dashboard;
  }

  // ========== Helper Methods ==========

  private filterXPosts(posts: XPost[]): XPost[] {
    return posts
      // Filter out likely replies (start with @)
      .filter(p => !p.text.startsWith('@'))
      // Filter out very short posts
      .filter(p => p.text.length > 50)
      // Sort by engagement
      .sort((a, b) => {
        const engA = a.metrics.likes + a.metrics.reposts * 2;
        const engB = b.metrics.likes + b.metrics.reposts * 2;
        return engB - engA;
      });
  }

  private formatShodanDigest(digest: ShodanDigest): string {
    const lines: string[] = [
      `Total Hosts Scanned: ${digest.totalHosts}`,
      `Vulnerable Hosts: ${digest.vulnerableHosts}`,
      `\nTop Exposed Ports:`,
      ...digest.topPorts.map(p => `  - Port ${p.port} (${p.service}): ${p.count} hosts`),
      `\nTop Countries:`,
      ...digest.topCountries.map(c => `  - ${c.country}: ${c.count} hosts`),
      `\nUnique CVEs Found: ${digest.uniqueCVEs.length}`,
      digest.uniqueCVEs.slice(0, 5).map(c => `  - ${c}`).join('\n'),
      `\nService Patterns:`,
      ...digest.bannerPatterns.slice(0, 5).map(b => `  - ${b}`)
    ];
    return lines.join('\n');
  }

  private async callOllama(model: string, prompt: string, retryCount = 0): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
      console.log(`    [Ollama] Calling ${model} (attempt ${retryCount + 1}/${MAX_RETRIES + 1})...`);
      const startTime = Date.now();
      
      const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model,
          prompt,
          stream: false,
          options: {
            temperature: 0.3,
            num_predict: 1024,
            top_p: 0.9
          }
        })
      });

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      if (!res.ok) {
        throw new Error(`Ollama HTTP ${res.status}`);
      }

      const data = await res.json() as { response: string };
      console.log(`    [Ollama] Response received in ${elapsed}s`);
      return data.response || '';
    } catch (error) {
      clearTimeout(timeout);
      
      // Retry on timeout or network errors
      if (retryCount < MAX_RETRIES) {
        const isTimeout = error instanceof Error && error.name === 'AbortError';
        const waitTime = Math.pow(2, retryCount) * 5000; // Exponential backoff: 5s, 10s
        console.log(`    [Ollama] ${isTimeout ? 'Timeout' : 'Error'}, retrying in ${waitTime/1000}s...`);
        await this.sleep(waitTime);
        return this.callOllama(model, prompt, retryCount + 1);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async loadJson<T>(filename: string): Promise<T | null> {
    try {
      const filePath = path.join(this.outputDir, filename);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as T;
    } catch {
      console.log(`  Note: ${filename} not found`);
      return null;
    }
  }

  private async saveIntermediateOutputs(outputs: Record<string, unknown>): Promise<void> {
    try {
      await fs.mkdir(this.outputDir, { recursive: true });
      await fs.writeFile(
        path.join(this.outputDir, 'orchestrator-debug.json'),
        JSON.stringify(outputs, null, 2)
      );
    } catch {
      // Non-critical, ignore
    }
  }

  private truncate(text: string, maxLen: number): string {
    if (text.length <= maxLen) return text;
    return text.substring(0, maxLen - 3) + '...';
  }

  private validateConfidence(value: string): 'low' | 'moderate' | 'high' {
    const v = value.toLowerCase();
    if (v.includes('high')) return 'high';
    if (v.includes('low')) return 'low';
    return 'moderate';
  }

  private validateCorrelation(value: string): 'weak' | 'moderate' | 'strong' {
    const v = value.toLowerCase();
    if (v.includes('strong')) return 'strong';
    if (v.includes('weak')) return 'weak';
    return 'moderate';
  }

  private validateRiskLevel(value: string): 'low' | 'medium' | 'high' | 'critical' {
    const v = value.toLowerCase();
    if (v.includes('critical')) return 'critical';
    if (v.includes('high')) return 'high';
    if (v.includes('low')) return 'low';
    return 'medium';
  }

  private getEmptyDashboard(): CTIDashboardOutput {
    return {
      date: new Date().toISOString(),
      summary: 'Insufficient data for analysis.',
      confidence: 'low',
      observed_cves: [],
      infrastructure_signals: [],
      correlation_strength: 'weak',
      risk_level: 'low',
      x_intel_summary: 'No social intelligence available.',
      shodan_summary: 'No infrastructure data available.',
      technical_assessment: 'Unable to perform technical validation.',
      recommended_actions: ['Configure data sources', 'Verify API credentials']
    };
  }

  private getEmptyShodanDigest(): ShodanDigest {
    return {
      totalHosts: 0,
      topPorts: [],
      topCountries: [],
      vulnerableHosts: 0,
      uniqueCVEs: [],
      bannerPatterns: []
    };
  }
}

export default CTIOrchestrator;
