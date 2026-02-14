/**
 * CTI Minimal Orchestrator - Refactored Sequential Two-Model Architecture
 * 
 * Refactors Applied:
 * 1. Token guardrails (approximate token counting)
 * 2. Structured X signals (not narrative)
 * 3. Compact input for technical model
 * 4. Deterministic dashboard classification (no LLM for categorical fields)
 * 5. Model-specific num_predict limits
 * 
 * Sequential Workflow:
 * 1. X Structured Signal Extraction (Strategic)
 * 2. Shodan Deterministic Aggregation (No LLM)
 * 3. Technical Validation (Technical Model - compact input)
 * 4. Strategic Executive Synthesis (Strategic)
 * 5. Deterministic Dashboard Structuring (No LLM)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { 
  XScrapedData, 
  XPost, 
  ShodanScrapedData,
  SignalLayer,
  StructuredSignals,
  AssessmentLayer,
  QuantifiedCorrelation,
  BaselineComparison,
  DataFreshness,
  IndicatorStatistics,
  RiskComputation,
  ThreatClassification,
  ModelMetadata
} from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const STRATEGIC_MODEL = process.env.OLLAMA_MODEL_STRATEGIC || process.env.OLLAMA_MODEL_REASONER || 'mistral:7b-instruct-q4_0';
const TECHNICAL_MODEL = process.env.OLLAMA_MODEL_TECHNICAL || process.env.OLLAMA_MODEL_SPECIALIST || 'saki007ster/CybersecurityRiskAnalyst';
// 10 minutes timeout for CPU inference in GitHub Actions
const REQUEST_TIMEOUT = parseInt(process.env.CTI_REQUEST_TIMEOUT || '600000', 10);
const MAX_RETRIES = parseInt(process.env.CTI_MAX_RETRIES || '2', 10);

// Token budget limits (safe zones)
const STRATEGIC_TOKEN_LIMIT = 6000;
const TECHNICAL_TOKEN_LIMIT = 4000;

// ==================== Interfaces ====================

/** Structured signals extracted from X posts (Refactor 2) */
interface XStructuredSignals {
  themes: string[];
  cves: string[];
  iocs: { ips: string[]; domains: string[]; hashes: string[] };
  exploitationClaims: string[];
  tone: 'speculative' | 'confirmed' | 'mixed';
  topPosts: Array<{ author: string; excerpt: string; engagement: number; url?: string }>;
}

/** Shodan preprocessed digest */
interface ShodanDigest {
  totalHosts: number;
  topPorts: Array<{ port: number; service: string; count: number }>;
  topCountries: Array<{ country: string; count: number }>;
  vulnerableHosts: number;
  uniqueCVEs: string[];
  bannerPatterns: string[];
  sampleHosts: Array<{ ip: string; port: number; service: string; vulns: string[] }>;
}

/** Technical validation output (Refactor 3) */
interface TechnicalAssessment {
  exploitAlignment: string;
  infrastructurePatterns: string;
  tacticalClassification: 'opportunistic' | 'targeted' | 'unknown';
  confidenceLevel: 'low' | 'moderate' | 'high';
  rawResponse: string;
}

/** Strategic synthesis output */
interface StrategicSynthesis {
  executiveSummary: string;
  correlationReasoning: string;
  recommendedActions: string[];
  rawResponse: string;
}

/** Final dashboard output aligned with frontend */
export interface CTIDashboardOutput {
  meta: {
    version: string;
    generatedAt: string;
    validUntil: string;
  };
  status: {
    riskLevel: 'critical' | 'elevated' | 'moderate' | 'low';
    riskScore: number;
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
  infrastructure: {
    totalHosts: number;
    exposedPorts: Array<{ port: number; service: string; count: number; percentage: number }>;
    topCountries: Array<{ country: string; count: number }>;
    vulnerableHosts: number;
    sampleHosts: Array<{ ip: string; port: number; service: string; vulns: string[] }>;
  };
  socialIntel?: {
    totalPosts: number;
    themes: string[];
    tone: string;
    topPosts: Array<{ excerpt: string; author: string; engagement: number; url?: string }>;
  };
  ctiAnalysis: {
    model: string;
    killChainPhase: string;
    threatLandscape: string;
    analystBrief: string;
    correlationStrength: string;
    technicalAssessment: string;
    methodologies: string[];
  };
  // New fields from minimal architecture (Signal/Assessment separation)
  signalLayer?: SignalLayer;
  assessmentLayer?: AssessmentLayer;
  modelMetadata?: ModelMetadata;
}

export interface OrchestratorResult {
  success: boolean;
  dashboard: CTIDashboardOutput;
  intermediateOutputs: {
    xSignals: XStructuredSignals;
    shodanDigest: ShodanDigest;
    technicalAssessment: TechnicalAssessment;
    strategicSynthesis: StrategicSynthesis;
    signalLayer: SignalLayer;
    assessmentLayer: AssessmentLayer;
  };
  error?: string;
}

// ==================== Orchestrator Class ====================

export class CTIOrchestrator {
  private outputDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Main orchestration - Refactored sequential workflow with Signal/Assessment separation
   */
  async run(): Promise<OrchestratorResult> {
    console.log('[Orchestrator] Starting refactored CTI pipeline...');
    console.log(`  Strategic: ${STRATEGIC_MODEL}`);
    console.log(`  Technical: ${TECHNICAL_MODEL}`);

    try {
      // Load raw data
      const xData = await this.loadJson<XScrapedData>('x-data.json');
      const shodanData = await this.loadJson<ShodanScrapedData>('shodan-data.json');

      // Step 1: Build Signal Layer (Immutable)
      console.log('\n[Step 1] Building Signal Layer...');
      const signalLayer = this.buildSignalLayer(xData, shodanData);
      console.log(`  ✓ Signals: ${signalLayer.structured.extractedCVEs.length} CVEs, ${signalLayer.structured.ips.length} IPs, ${signalLayer.structured.domains.length} domains`);

      // Step 2: Extract Structured X Signals (Strategic Model) - Legacy compatibility
      console.log('\n[Step 2] X Structured Signal Extraction...');
      const xSignals = await this.extractXSignals(xData);
      console.log(`  ✓ Extracted: ${xSignals.cves.length} CVEs, ${xSignals.themes.length} themes`);

      // Step 3: Shodan Deterministic Aggregation (No LLM)
      console.log('\n[Step 3] Shodan Deterministic Aggregation...');
      const shodanDigest = this.aggregateShodanData(shodanData);
      console.log(`  ✓ Aggregated: ${shodanDigest.totalHosts} hosts, ${shodanDigest.vulnerableHosts} vulnerable`);

      // Step 4: Technical Validation (Technical Model - compact input)
      console.log('\n[Step 4] Technical Validation...');
      const technicalAssessment = await this.runTechnicalValidation(xSignals, shodanDigest);
      console.log(`  ✓ Assessment: ${technicalAssessment.tacticalClassification}, confidence: ${technicalAssessment.confidenceLevel}`);

      // Step 5: Build Assessment Layer (Reprocessable) - NEW
      console.log('\n[Step 5] Building Assessment Layer...');
      const previousRiskScore = await this.loadPreviousRiskScore();
      const assessmentLayer = this.buildAssessmentLayer(
        signalLayer.structured,
        shodanDigest,
        technicalAssessment,
        previousRiskScore
      );
      console.log(`  ✓ Assessment: Risk=${assessmentLayer.scoring.computedScore}, Correlation=${assessmentLayer.correlation.strength}`);
      console.log(`  ✓ Classification: ${assessmentLayer.classification.type} (${assessmentLayer.classification.confidence}%)`);
      console.log(`  ✓ Baseline: ${assessmentLayer.baselineComparison.anomalyLevel} (${assessmentLayer.baselineComparison.delta > 0 ? '+' : ''}${assessmentLayer.baselineComparison.delta})`);

      // Step 6: Strategic Executive Synthesis
      console.log('\n[Step 6] Strategic Synthesis...');
      const strategicSynthesis = await this.runStrategicSynthesis(xSignals, shodanDigest, technicalAssessment);
      console.log(`  ✓ Synthesis complete (${strategicSynthesis.executiveSummary.length} chars)`);

      // Step 7: Deterministic Dashboard Structuring (No LLM)
      console.log('\n[Step 7] Deterministic Dashboard Generation...');
      const dashboard = this.buildDashboardDeterministic(
        xSignals, 
        shodanDigest, 
        technicalAssessment, 
        strategicSynthesis,
        signalLayer,
        assessmentLayer
      );
      console.log(`  ✓ Dashboard: Risk=${dashboard.status.riskLevel}, Score=${dashboard.status.riskScore}`);

      // Save debug outputs
      await this.saveIntermediateOutputs({ 
        xSignals, 
        shodanDigest, 
        technicalAssessment, 
        strategicSynthesis,
        signalLayer,
        assessmentLayer 
      });

      return {
        success: true,
        dashboard,
        intermediateOutputs: { 
          xSignals, 
          shodanDigest, 
          technicalAssessment, 
          strategicSynthesis,
          signalLayer,
          assessmentLayer 
        }
      };

    } catch (error) {
      console.error('[Orchestrator] Pipeline failed:', error);
      return {
        success: false,
        dashboard: this.getEmptyDashboard(),
        intermediateOutputs: {
          xSignals: this.getEmptyXSignals(),
          shodanDigest: this.getEmptyShodanDigest(),
          technicalAssessment: this.getEmptyTechnicalAssessment(),
          strategicSynthesis: this.getEmptyStrategicSynthesis(),
          signalLayer: this.getEmptySignalLayer(),
          assessmentLayer: this.getEmptyAssessmentLayer()
        },
        error: String(error)
      };
    }
  }

  // ==================== Step 1: X Structured Signal Extraction ====================

  /**
   * Extract structured signals from X posts using Strategic Model
   * Returns structured object instead of narrative (Refactor 2)
   */
  private async extractXSignals(xData: XScrapedData | null): Promise<XStructuredSignals> {
    if (!xData || xData.posts.length === 0) {
      return this.getEmptyXSignals();
    }

    const filteredPosts = this.filterXPosts(xData.posts);
    
    // Pre-extract IoCs and CVEs from posts (code-based extraction)
    const codeExtracted = this.extractIoCsFromPosts(filteredPosts);

    // Build compact prompt for LLM to extract themes and tone
    const postsText = filteredPosts
      .slice(0, 15)
      .map((p, i) => `[${i + 1}] ${this.truncateTokenSafe(p.text, 150)}`)
      .join('\n');

    const prompt = `Extract threat intelligence signals from these posts. Return ONLY a JSON object.

POSTS:
${postsText}

Return JSON (no markdown):
{"themes":["theme1","theme2"],"exploitation_claims":["claim1"],"tone":"speculative|confirmed|mixed"}`;

    // Check token budget
    this.assertTokenBudget(prompt, STRATEGIC_TOKEN_LIMIT, 'X Signal Extraction');

    let extracted: { themes?: string[]; exploitation_claims?: string[]; tone?: string } = {};
    try {
      const response = await this.callOllama(STRATEGIC_MODEL, prompt, false);
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        extracted = JSON.parse(jsonMatch[0]);
      }
    } catch {
      console.log('    Warning: LLM extraction partial, using code-extracted data');
    }

    // Build top posts for dashboard
    const topPosts = filteredPosts.slice(0, 5).map(p => ({
      author: p.author.username,
      excerpt: this.truncateTokenSafe(p.text, 100),
      engagement: p.metrics.likes + p.metrics.reposts * 2,
      url: p.permalink
    }));

    return {
      themes: extracted.themes || this.inferThemesFromPosts(filteredPosts),
      cves: codeExtracted.cves,
      iocs: codeExtracted.iocs,
      exploitationClaims: extracted.exploitation_claims || [],
      tone: this.validateTone(extracted.tone || 'mixed'),
      topPosts
    };
  }

  /** Code-based IoC extraction (no LLM needed) */
  private extractIoCsFromPosts(posts: XPost[]): { cves: string[]; iocs: { ips: string[]; domains: string[]; hashes: string[] } } {
    const allText = posts.map(p => p.text).join(' ');
    
    // CVE pattern
    const cves = [...new Set((allText.match(/CVE-\d{4}-\d{4,7}/gi) || []))];
    
    // IP pattern (simple v4)
    const ips = [...new Set((allText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))]
      .filter(ip => !ip.startsWith('0.') && !ip.startsWith('127.'));
    
    // Domain pattern (simple)
    const domains = [...new Set((allText.match(/\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b/gi) || []))]
      .filter(d => !d.includes('twitter') && !d.includes('x.com'));
    
    // Hash patterns (MD5, SHA1, SHA256)
    const hashes = [...new Set((allText.match(/\b[a-f0-9]{32,64}\b/gi) || []))];

    return { cves, iocs: { ips: ips.slice(0, 10), domains: domains.slice(0, 10), hashes: hashes.slice(0, 5) } };
  }

  /** Infer themes from post content (fallback) */
  private inferThemesFromPosts(posts: XPost[]): string[] {
    const themes = new Set<string>();
    const keywords = {
      'Ransomware': /ransomware|ransom|encrypt/i,
      'Vulnerability': /CVE-|vuln|exploit|zero-day/i,
      'APT': /APT|nation-state|espionage/i,
      'Data Breach': /breach|leak|exposed/i,
      'Malware': /malware|trojan|backdoor/i,
      'Phishing': /phish|credential|social engineering/i
    };
    
    posts.forEach(p => {
      Object.entries(keywords).forEach(([theme, pattern]) => {
        if (pattern.test(p.text)) themes.add(theme);
      });
    });
    
    return Array.from(themes).slice(0, 5);
  }

  // ==================== Step 2: Shodan Deterministic Aggregation ====================

  /** Aggregate Shodan data without LLM (deterministic) */
  private aggregateShodanData(shodanData: ShodanScrapedData | null): ShodanDigest {
    if (!shodanData || shodanData.hosts.length === 0) {
      return this.getEmptyShodanDigest();
    }

    const hosts = shodanData.hosts;

    // Port aggregation
    const portCounts: Record<string, { port: number; service: string; count: number }> = {};
    hosts.forEach(h => {
      const key = `${h.port}`;
      if (!portCounts[key]) {
        portCounts[key] = { port: h.port, service: h.product || 'unknown', count: 0 };
      }
      portCounts[key].count++;
      if (h.product && h.product !== 'unknown') {
        portCounts[key].service = h.product;
      }
    });

    // Country aggregation
    const countryCounts: Record<string, number> = {};
    hosts.forEach(h => {
      const country = h.country || 'Unknown';
      countryCounts[country] = (countryCounts[country] || 0) + 1;
    });

    // CVE collection
    const allCVEs = new Set<string>();
    hosts.forEach(h => h.vulns?.forEach(cve => allCVEs.add(cve)));

    // Banner patterns
    const bannerPatterns = new Set<string>();
    hosts.forEach(h => {
      if (h.product && h.version) bannerPatterns.add(`${h.product} ${h.version}`);
    });

    // Vulnerable hosts count
    const vulnerableHosts = hosts.filter(h => h.vulns && h.vulns.length > 0).length;

    // Sample hosts for dashboard (anonymize IPs)
    const sampleHosts = hosts
      .filter(h => h.vulns && h.vulns.length > 0)
      .slice(0, 5)
      .map(h => ({
        ip: this.anonymizeIP(h.ip),
        port: h.port,
        service: h.product || 'unknown',
        vulns: (h.vulns || []).slice(0, 3)
      }));

    const topPorts = Object.values(portCounts).sort((a, b) => b.count - a.count).slice(0, 10);

    return {
      totalHosts: hosts.length,
      topPorts,
      topCountries: Object.entries(countryCounts)
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
      vulnerableHosts,
      uniqueCVEs: Array.from(allCVEs).slice(0, 20),
      bannerPatterns: Array.from(bannerPatterns).slice(0, 10),
      sampleHosts
    };
  }

  // ==================== Step 3: Technical Validation ====================

  /**
   * Technical validation using Technical Model with compact structured input (Refactor 3)
   */
  private async runTechnicalValidation(
    xSignals: XStructuredSignals,
    shodanDigest: ShodanDigest
  ): Promise<TechnicalAssessment> {
    // Build compact structured input (not narrative)
    const compactInput = `SOCIAL SIGNALS:
CVEs: [${xSignals.cves.slice(0, 5).join(', ')}]
IoCs: ${xSignals.iocs.ips.length} IPs, ${xSignals.iocs.domains.length} domains
Themes: [${xSignals.themes.join(', ')}]
Exploitation Claims: ${xSignals.exploitationClaims.length > 0 ? xSignals.exploitationClaims.slice(0, 3).join('; ') : 'None observed'}
Tone: ${xSignals.tone}

INFRASTRUCTURE:
Total Hosts: ${shodanDigest.totalHosts}
Vulnerable: ${shodanDigest.vulnerableHosts}/${shodanDigest.totalHosts} (${((shodanDigest.vulnerableHosts / Math.max(shodanDigest.totalHosts, 1)) * 100).toFixed(1)}%)
Top Ports: [${shodanDigest.topPorts.slice(0, 5).map(p => `${p.port}/${p.service}`).join(', ')}]
Infrastructure CVEs: [${shodanDigest.uniqueCVEs.slice(0, 5).join(', ')}]`;

    const prompt = `Analyze correlation between social intelligence and infrastructure. Be concise.

${compactInput}

Respond with:
1. CVE-SERVICE ALIGNMENT: Do CVEs match exposed services?
2. TACTICAL CLASSIFICATION: opportunistic scanning or targeted campaign?
3. CONFIDENCE: low/moderate/high

Under 300 words.`;

    // Check token budget
    this.assertTokenBudget(prompt, TECHNICAL_TOKEN_LIMIT, 'Technical Validation');

    const response = await this.callOllama(TECHNICAL_MODEL, prompt, true);

    // Parse response for classification
    const tacticalMatch = response.toLowerCase();
    let tactical: 'opportunistic' | 'targeted' | 'unknown' = 'unknown';
    if (tacticalMatch.includes('targeted') || tacticalMatch.includes('campaign')) {
      tactical = 'targeted';
    } else if (tacticalMatch.includes('opportunistic') || tacticalMatch.includes('scanning')) {
      tactical = 'opportunistic';
    }

    let confidence: 'low' | 'moderate' | 'high' = 'moderate';
    if (tacticalMatch.includes('high confidence') || tacticalMatch.includes('confidence: high')) {
      confidence = 'high';
    } else if (tacticalMatch.includes('low confidence') || tacticalMatch.includes('confidence: low')) {
      confidence = 'low';
    }

    return {
      exploitAlignment: this.extractSection(response, 'alignment', 'CVE-service analysis pending'),
      infrastructurePatterns: this.extractSection(response, 'pattern', 'Infrastructure patterns analyzed'),
      tacticalClassification: tactical,
      confidenceLevel: confidence,
      rawResponse: response
    };
  }

  // ==================== Step 4: Strategic Synthesis ====================

  /**
   * Strategic synthesis using Strategic Model
   */
  private async runStrategicSynthesis(
    xSignals: XStructuredSignals,
    shodanDigest: ShodanDigest,
    technical: TechnicalAssessment
  ): Promise<StrategicSynthesis> {
    // Build concise input using structured signals
    const prompt = `Synthesize threat intelligence for executive briefing.

SOCIAL INTEL:
- Themes: ${xSignals.themes.join(', ') || 'None identified'}
- CVEs discussed: ${xSignals.cves.length}
- Tone: ${xSignals.tone}

INFRASTRUCTURE:
- ${shodanDigest.totalHosts} hosts, ${shodanDigest.vulnerableHosts} vulnerable
- Top services: ${shodanDigest.topPorts.slice(0, 3).map(p => p.service).join(', ')}

TECHNICAL ASSESSMENT:
- Classification: ${technical.tacticalClassification}
- Confidence: ${technical.confidenceLevel}

Provide:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. KEY FINDING (most important observation)
3. RECOMMENDED ACTIONS (top 3)

Under 400 words.`;

    // Check token budget
    this.assertTokenBudget(prompt, STRATEGIC_TOKEN_LIMIT, 'Strategic Synthesis');

    const response = await this.callOllama(STRATEGIC_MODEL, prompt, false);

    // Extract executive summary (first paragraph or after "EXECUTIVE SUMMARY")
    const summaryMatch = response.match(/(?:EXECUTIVE SUMMARY[:\s]*)?([^.]+\.[^.]+\.)/i);
    const executiveSummary = summaryMatch?.[1]?.trim() || response.split('\n')[0] || 'Threat analysis completed.';

    // Extract recommended actions
    const actionsMatch = response.match(/(?:RECOMMENDED|ACTIONS?)[:\s]*\n?([\s\S]*?)(?:\n\n|$)/i);
    let recommendedActions = ['Monitor threat indicators', 'Review exposed services', 'Update security controls'];
    if (actionsMatch) {
      const actionLines = actionsMatch[1].match(/[-•\d.]\s*(.+)/g);
      if (actionLines && actionLines.length > 0) {
        recommendedActions = actionLines.map(a => a.replace(/^[-•\d.]\s*/, '').trim()).slice(0, 5);
      }
    }

    return {
      executiveSummary,
      correlationReasoning: this.extractSection(response, 'correlation', 'Cross-source correlation analyzed'),
      recommendedActions,
      rawResponse: response
    };
  }

  // ==================== Step 5: Deterministic Dashboard Building ====================

  /**
   * Load previous risk score from disk for baseline comparison
   */
  private async loadPreviousRiskScore(): Promise<number> {
    try {
      const filePath = path.join(this.outputDir, 'previous-risk-score.json');
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);
      return data.score || 50;
    } catch {
      return 50; // Default baseline
    }
  }

  /**
   * Save current risk score for future baseline comparison
   */
  private async saveCurrentRiskScore(score: number): Promise<void> {
    try {
      const filePath = path.join(this.outputDir, 'previous-risk-score.json');
      await fs.writeFile(filePath, JSON.stringify({ score, timestamp: new Date().toISOString() }));
    } catch { /* non-critical */ }
  }

  /**
   * Build dashboard with deterministic classification (Refactor 4)
   * NO LLM for categorical fields
   * Includes Signal/Assessment separation
   */
  private buildDashboardDeterministic(
    xSignals: XStructuredSignals,
    shodanDigest: ShodanDigest,
    technical: TechnicalAssessment,
    synthesis: StrategicSynthesis,
    signalLayer?: SignalLayer,
    assessmentLayer?: AssessmentLayer
  ): CTIDashboardOutput {
    const now = new Date();
    const validUntil = new Date(now.getTime() + 6 * 60 * 60 * 1000);

    // Use assessment layer scoring if available, otherwise compute
    let riskLevel: 'critical' | 'elevated' | 'moderate' | 'low';
    let riskScore: number;
    let confidenceLevel: number;
    let trend: 'increasing' | 'stable' | 'decreasing';
    
    if (assessmentLayer) {
      // Derive from assessment layer to ensure consistency
      riskScore = assessmentLayer.scoring.computedScore;
      confidenceLevel = assessmentLayer.scoring.confidenceLevel;
      trend = assessmentLayer.baselineComparison.trendDirection;
      
      // Risk level based on computed score
      if (riskScore >= 75) {
        riskLevel = 'critical';
      } else if (riskScore >= 50) {
        riskLevel = 'elevated';
      } else if (riskScore >= 25) {
        riskLevel = 'moderate';
      } else {
        riskLevel = 'low';
      }
    } else {
      // Fallback to deterministic calculation
      const vulnerabilityRatio = shodanDigest.vulnerableHosts / Math.max(shodanDigest.totalHosts, 1);
      
      if (vulnerabilityRatio > 0.5 || xSignals.tone === 'confirmed') {
        riskLevel = 'critical';
        riskScore = 85 + Math.min(vulnerabilityRatio * 15, 15);
      } else if (vulnerabilityRatio > 0.25 || technical.tacticalClassification === 'targeted') {
        riskLevel = 'elevated';
        riskScore = 60 + vulnerabilityRatio * 40;
      } else if (vulnerabilityRatio > 0.1 || xSignals.cves.length > 3) {
        riskLevel = 'moderate';
        riskScore = 40 + vulnerabilityRatio * 40;
      } else {
        riskLevel = 'low';
        riskScore = 20 + vulnerabilityRatio * 40;
      }
      
      confidenceLevel = 50;
      trend = 'stable';
    }

    // Deterministic Correlation Strength (Refactor 4)
    const cveOverlap = this.countOverlap(xSignals.cves, shodanDigest.uniqueCVEs);
    let correlationStrength: string;
    if (cveOverlap > 5) {
      correlationStrength = 'strong';
    } else if (cveOverlap > 2) {
      correlationStrength = 'moderate';
    } else {
      correlationStrength = 'weak';
    }



    // Compute vulnerability ratio for findings
    const vulnerabilityRatio = shodanDigest.totalHosts > 0 
      ? shodanDigest.vulnerableHosts / shodanDigest.totalHosts 
      : 0;

    // Build key findings
    const keyFindings: string[] = [];
    if (shodanDigest.uniqueCVEs.length > 0) {
      keyFindings.push(`${shodanDigest.uniqueCVEs.length} CVE references identified in infrastructure`);
    }
    if (shodanDigest.vulnerableHosts > 0) {
      keyFindings.push(`${shodanDigest.vulnerableHosts} vulnerable hosts detected (${(vulnerabilityRatio * 100).toFixed(1)}%)`);
    }
    if (xSignals.themes.length > 0) {
      keyFindings.push(`Active social discussion: ${xSignals.themes.slice(0, 2).join(', ')}`);
    }
    if (cveOverlap > 0) {
      keyFindings.push(`${cveOverlap} CVEs appear in both social intel and infrastructure`);
    }
    if (keyFindings.length === 0) {
      keyFindings.push('Baseline threat monitoring active');
    }

    // Build timeline events
    const timeline = this.buildTimeline(xSignals, shodanDigest);

    // Calculate metrics - derive from actual data and assessment layer
    let totalSignals: number;
    let criticalCount: number;
    let highCount: number;
    let mediumCount: number;
    let lowCount: number;

    if (assessmentLayer) {
      // Derive from assessment layer scoring components for consistency
      const vulnScore = assessmentLayer.scoring.components.vulnerabilityRatio;
      const socialScore = assessmentLayer.scoring.components.socialIntensity;
      const corrScore = assessmentLayer.scoring.components.correlationScore;

      // Total signals based on actual indicator count
      totalSignals = assessmentLayer.iocStats.totalIndicators;

      // Severity distribution based on risk score and component analysis
      if (riskScore >= 75) {
        // Critical risk: mostly critical and high
        criticalCount = Math.max(1, Math.round(totalSignals * 0.4));
        highCount = Math.max(1, Math.round(totalSignals * 0.3));
        mediumCount = Math.max(1, Math.round(totalSignals * 0.2));
        lowCount = Math.max(0, totalSignals - criticalCount - highCount - mediumCount);
      } else if (riskScore >= 50) {
        // Elevated risk: mix of high and medium
        criticalCount = Math.round(totalSignals * 0.15);
        highCount = Math.max(1, Math.round(totalSignals * 0.35));
        mediumCount = Math.max(1, Math.round(totalSignals * 0.35));
        lowCount = Math.max(1, totalSignals - criticalCount - highCount - mediumCount);
      } else if (riskScore >= 25) {
        // Moderate risk: mostly medium
        criticalCount = Math.round(totalSignals * 0.05);
        highCount = Math.round(totalSignals * 0.2);
        mediumCount = Math.max(1, Math.round(totalSignals * 0.5));
        lowCount = Math.max(1, totalSignals - criticalCount - highCount - mediumCount);
      } else {
        // Low risk: mostly low
        criticalCount = 0;
        highCount = Math.round(totalSignals * 0.1);
        mediumCount = Math.round(totalSignals * 0.3);
        lowCount = Math.max(1, totalSignals - highCount - mediumCount);
      }
    } else {
      // Fallback calculation
      totalSignals = xSignals.cves.length + shodanDigest.vulnerableHosts + xSignals.exploitationClaims.length;
      const severityDist = this.calculateSeverityDistribution(riskLevel, totalSignals);
      criticalCount = severityDist.criticalCount;
      highCount = severityDist.highCount;
      mediumCount = severityDist.mediumCount;
      lowCount = severityDist.lowCount;
    }

    // Build categories
    const categories: Array<{ name: string; count: number; percentage: number }> = [];
    if (shodanDigest.uniqueCVEs.length > 0) {
      categories.push({ name: 'Vulnerability', count: shodanDigest.uniqueCVEs.length, percentage: 0 });
    }
    if (shodanDigest.vulnerableHosts > 0) {
      categories.push({ name: 'Infrastructure', count: shodanDigest.vulnerableHosts, percentage: 0 });
    }
    if (xSignals.themes.length > 0) {
      categories.push({ name: 'Threat Intel', count: xSignals.themes.length, percentage: 0 });
    }
    if (categories.length === 0) {
      categories.push({ name: 'General', count: 1, percentage: 100 });
    }
    const catTotal = categories.reduce((s, c) => s + c.count, 0);
    categories.forEach(c => c.percentage = Math.round((c.count / catTotal) * 100));

    // Infer kill chain phase
    const killChainPhase = technical.tacticalClassification === 'targeted' 
      ? 'Weaponization' 
      : (shodanDigest.vulnerableHosts > 0 ? 'Reconnaissance' : 'Pre-Attack');

    // Build model metadata for benchmarking
    const modelMetadata: ModelMetadata = {
      strategic: STRATEGIC_MODEL,
      technical: TECHNICAL_MODEL,
      quantization: process.env.OLLAMA_QUANTIZATION || 'Q4_K_M',
      version: '3.0.0'
    };

    // Save current risk score for future baseline comparison
    this.saveCurrentRiskScore(Math.round(riskScore));

    return {
      meta: {
        version: '3.0.0',
        generatedAt: now.toISOString(),
        validUntil: validUntil.toISOString()
      },
      status: {
        riskLevel,
        riskScore: Math.round(riskScore),
        trend,
        confidenceLevel
      },
      executive: {
        headline: this.generateHeadline(riskLevel),
        summary: synthesis.executiveSummary,
        keyFindings,
        recommendedActions: synthesis.recommendedActions
      },
      metrics: {
        totalSignals: Math.max(totalSignals, 1),
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        categories
      },
      timeline,
      sources: [
        { name: 'X.com Social Intel', signalCount: xSignals.topPosts.length, lastUpdate: now.toISOString() },
        { name: 'Shodan Infrastructure', signalCount: shodanDigest.totalHosts, lastUpdate: now.toISOString() }
      ],
      indicators: {
        cves: [...new Set([...xSignals.cves, ...shodanDigest.uniqueCVEs])].slice(0, 15),
        domains: xSignals.iocs.domains,
        ips: xSignals.iocs.ips.map(ip => this.anonymizeIP(ip)),
        keywords: xSignals.themes
      },
      infrastructure: {
        totalHosts: shodanDigest.totalHosts,
        exposedPorts: shodanDigest.topPorts.slice(0, 5).map(p => ({
          ...p,
          percentage: Math.round((p.count / Math.max(shodanDigest.totalHosts, 1)) * 100)
        })),
        topCountries: shodanDigest.topCountries,
        vulnerableHosts: shodanDigest.vulnerableHosts,
        sampleHosts: shodanDigest.sampleHosts
      },
      socialIntel: xSignals.topPosts.length > 0 ? {
        totalPosts: xSignals.topPosts.length,
        themes: xSignals.themes,
        tone: xSignals.tone,
        topPosts: xSignals.topPosts
      } : undefined,
      ctiAnalysis: {
        model: TECHNICAL_MODEL,
        killChainPhase,
        threatLandscape: synthesis.executiveSummary,
        analystBrief: `Classification: ${technical.tacticalClassification}. Confidence: ${technical.confidenceLevel}. Correlation: ${correlationStrength}.`,
        correlationStrength,
        technicalAssessment: technical.rawResponse.slice(0, 500),
        methodologies: [
          'Deterministic risk scoring (vulnerability ratio)',
          'Code-based IoC extraction',
          'Cross-source CVE correlation',
          'Structured signal analysis',
          'Quantified correlation model',
          'Baseline comparison tracking'
        ]
      },
      signalLayer,
      assessmentLayer,
      modelMetadata
    };
  }

  // ==================== New Assessment Layer Methods ====================

  /**
   * Build Signal Layer - Raw and structured extraction
   * Separates immutable signal from reprocessable assessment
   */
  private buildSignalLayer(
    xData: XScrapedData | null,
    shodanData: ShodanScrapedData | null
  ): SignalLayer {
    const xPosts = xData?.posts || [];
    const shodanHosts = shodanData?.hosts || [];

    // Build structured signals from raw data
    const structured = this.buildStructuredSignals(xPosts, shodanHosts);

    return {
      raw: {
        xPosts,
        shodanResults: shodanHosts
      },
      structured
    };
  }

  /**
   * Filter posts for cybersecurity relevance
   */
  private filterRelevantPosts(posts: XPost[]): XPost[] {
    const securityKeywords = [
      'cve', 'vulnerability', 'exploit', 'exploitation', 'ransomware', 'malware',
      'apt', 'threat', 'attack', 'breach', 'security', 'cyber', 'hacking',
      'zero-day', '0day', 'backdoor', 'phishing', 'dox', 'leak', 'exposed',
      'sql injection', 'xss', 'csrf', 'rce', 'privilege escalation',
      'lpe', 'remote code', 'buffer overflow', 'sqli', 'bug bounty',
      'patch', 'fix', 'update', 'advisory', 'bulletin', 'security notice',
      'critical', 'high severity', 'cvss', 'nvd', 'mitre', 'cisa',
      'infosec', 'appsec', 'netsec', 'blueteam', 'redteam', 'purpleteam',
      'defender', 'sentinel', 'siem', 'edr', 'xdr', 'mdr', 'soc',
      'pentest', 'penetration test', 'audit', 'assessment', 'scan'
    ];

    const irrelevantPatterns = [
      /apartment\s+fire/i,
      /elephant\s+birth/i,
      /staking\s+campaign/i,
      /quiz\s+about/i,
      /birthday\s+party/i,
      /weather\s+forecast/i,
      /sports\s+game/i,
      /crypto\s+price/i,
      /nft\s+drop/i,
      /airdrop/i,
      /giveaway/i,
      /^rt\s+@/i,
      /^retweet/i
    ];

    return posts.filter(post => {
      const text = post.text.toLowerCase();

      // Check for security relevance
      const hasSecurityKeyword = securityKeywords.some(kw => text.includes(kw.toLowerCase()));

      // Check for irrelevant content
      const isIrrelevant = irrelevantPatterns.some(pattern => pattern.test(post.text));

      // Must have security keyword AND not be irrelevant
      return hasSecurityKeyword && !isIrrelevant;
    });
  }

  /**
   * Build structured signals from raw data
   */
  private buildStructuredSignals(
    xPosts: XPost[],
    shodanHosts: any[]
  ): StructuredSignals {
    // Filter posts for relevance first
    const relevantPosts = this.filterRelevantPosts(xPosts);

    // If no relevant posts, use empty arrays
    const postsToProcess = relevantPosts.length > 0 ? relevantPosts : [];
    const allText = postsToProcess.map(p => p.text).join(' ');

    // Extract CVEs
    const extractedCVEs = [...new Set((allText.match(/CVE-\d{4}-\d{4,7}/gi) || []))];

    // Extract IPs
    const ips = [...new Set((allText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))]
      .filter(ip => !ip.startsWith('0.') && !ip.startsWith('127.'));

    // Extract domains
    const domains = [...new Set((allText.match(/\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b/gi) || []))]
      .filter(d => !d.includes('twitter') && !d.includes('x.com'));

    // Extract ports from Shodan
    const ports = [...new Set(shodanHosts.map(h => h.port).filter(Boolean))];

    // Extract services from Shodan
    const services = [...new Set(shodanHosts.map(h => h.product).filter(Boolean))];

    // Extract keywords/themes
    const keywords = this.inferThemesFromPosts(xPosts);

    // Extract exploitation claims
    const exploitationClaims = this.extractExploitationClaims(allText);

    // Determine tone
    const tone = this.calculateTone(xPosts, allText);

    // Top posts - from filtered relevant posts only
    const topPosts = postsToProcess
      .sort((a, b) => (b.metrics.likes + b.metrics.reposts * 2) - (a.metrics.likes + a.metrics.reposts * 2))
      .slice(0, 5)
      .map(p => ({
        author: p.author.username,
        excerpt: this.truncateTokenSafe(p.text, 100),
        engagement: p.metrics.likes + p.metrics.reposts * 2,
        url: p.permalink,
        timestamp: p.timestamp
      }));

    return {
      extractedCVEs,
      domains,
      ips,
      ports,
      services,
      keywords,
      exploitationClaims,
      tone,
      topPosts
    };
  }

  /**
   * Extract exploitation claims from text
   */
  private extractExploitationClaims(text: string): string[] {
    const claims: string[] = [];
    const patterns = [
      /(?:exploit|exploiting|exploited|exploitation)\s+(?:in|on|for|of)\s+([^.]+)/gi,
      /(?:being\s+)?exploited\s+(?:in|in\s+the)\s+wild/gi,
      /(?:active|ongoing)\s+exploit/gi,
      /(?:proof\s+of\s+concept|poc)\s+(?:released|available)/gi
    ];

    patterns.forEach(pattern => {
      const matches = text.match(pattern);
      if (matches) {
        claims.push(...matches.map(m => m.trim()));
      }
    });

    return [...new Set(claims)].slice(0, 10);
  }

  /**
   * Calculate tone from posts
   */
  private calculateTone(
    posts: XPost[],
    allText: string
  ): 'speculative' | 'confirmed' | 'mixed' {
    const confirmedPatterns = /(?:confirmed|verified|observed|detected|active)/gi;
    const speculativePatterns = /(?:allegedly|reportedly|possibly|maybe|might|could|rumor)/gi;

    const confirmedCount = (allText.match(confirmedPatterns) || []).length;
    const speculativeCount = (allText.match(speculativePatterns) || []).length;

    if (confirmedCount > speculativeCount * 2) return 'confirmed';
    if (speculativeCount > confirmedCount * 2) return 'speculative';
    return 'mixed';
  }

  /**
   * Build Assessment Layer - Reprocessable analysis
   */
  private buildAssessmentLayer(
    signals: StructuredSignals,
    shodanDigest: ShodanDigest,
    technical: TechnicalAssessment,
    previousRiskScore: number = 50
  ): AssessmentLayer {
    const correlation = this.computeQuantifiedCorrelation(signals, shodanDigest);
    const iocStats = this.computeIndicatorStatistics(signals, shodanDigest);
    const freshness = this.computeDataFreshness(signals);
    const scoring = this.computeRiskComputation(
      signals,
      shodanDigest,
      correlation,
      freshness,
      previousRiskScore
    );
    const baselineComparison = this.computeBaselineComparison(
      scoring.computedScore,
      previousRiskScore
    );
    const classification = this.classifyThreat(signals, shodanDigest, correlation, technical);

    return {
      correlation,
      scoring,
      baselineComparison,
      freshness,
      classification,
      iocStats,
      narrative: this.generateNarrative(signals, correlation, classification)
    };
  }

  /**
   * Compute quantified correlation model
   * Returns numerical correlation with factor breakdown
   */
  private computeQuantifiedCorrelation(
    signals: StructuredSignals,
    shodanDigest: ShodanDigest
  ): QuantifiedCorrelation {
    // CVE overlap factor
    const socialCVEs = new Set(signals.extractedCVEs.map(c => c.toUpperCase()));
    const infraCVEs = new Set(shodanDigest.uniqueCVEs.map(c => c.toUpperCase()));
    const overlapCount = [...socialCVEs].filter(c => infraCVEs.has(c)).length;
    const cveOverlapFactor = Math.min(overlapCount / Math.max(socialCVEs.size, 1), 1);

    // Service match factor
    const socialServices = new Set(signals.keywords.map(k => k.toLowerCase()));
    const infraServices = new Set(shodanDigest.topPorts.map(p => p.service.toLowerCase()));
    const serviceMatches = [...socialServices].filter(s => 
      [...infraServices].some(i => i.includes(s) || s.includes(i))
    ).length;
    const serviceMatchFactor = Math.min(serviceMatches / Math.max(socialServices.size, 1), 1);

    // Temporal proximity factor (based on data freshness)
    const temporalFactor = 0.7; // Default high since data is current

    // Infrastructure-social alignment
    const alignmentFactor = (cveOverlapFactor + serviceMatchFactor) / 2;

    // Calculate weighted correlation score
    const score = 
      (cveOverlapFactor * 0.3) +
      (serviceMatchFactor * 0.3) +
      (temporalFactor * 0.2) +
      (alignmentFactor * 0.2);

    // Map to strength label
    let strength: 'weak' | 'moderate' | 'strong';
    if (score < 0.3) strength = 'weak';
    else if (score < 0.6) strength = 'moderate';
    else strength = 'strong';

    return {
      score: Math.round(score * 100) / 100,
      strength,
      factors: {
        cveOverlap: Math.round(cveOverlapFactor * 100) / 100,
        serviceMatch: Math.round(serviceMatchFactor * 100) / 100,
        temporalProximity: temporalFactor,
        infraSocialAlignment: Math.round(alignmentFactor * 100) / 100
      },
      explanation: `Correlation strength ${strength} (${Math.round(score * 100)}%) based on ${overlapCount} CVE overlaps and ${serviceMatches} service matches.`
    };
  }

  /**
   * Compute baseline comparison with delta tracking
   */
  private computeBaselineComparison(
    currentScore: number,
    previousScore: number
  ): BaselineComparison {
    const delta = currentScore - previousScore;
    
    let anomalyLevel: 'stable' | 'mild' | 'moderate' | 'severe';
    const absDelta = Math.abs(delta);
    if (absDelta < 5) anomalyLevel = 'stable';
    else if (absDelta < 15) anomalyLevel = 'mild';
    else if (absDelta < 30) anomalyLevel = 'moderate';
    else anomalyLevel = 'severe';

    const trendDirection = delta > 5 ? 'increasing' : delta < -5 ? 'decreasing' : 'stable';

    return {
      previousRiskScore: previousScore,
      currentRiskScore: currentScore,
      delta: Math.round(delta),
      anomalyLevel,
      trendDirection
    };
  }

  /**
   * Compute data freshness score
   */
  private computeDataFreshness(signals: StructuredSignals): DataFreshness {
    const now = new Date();
    
    // Calculate average age of social posts
    let socialAgeHours = 3; // Default
    if (signals.topPosts.length > 0) {
      const ages = signals.topPosts.map(p => {
        const postTime = new Date(p.timestamp);
        return (now.getTime() - postTime.getTime()) / (1000 * 60 * 60);
      });
      socialAgeHours = ages.reduce((a, b) => a + b, 0) / ages.length;
    }

    // Infrastructure data is typically current
    const infraAgeHours = 1;

    // Calculate freshness score (1 - normalized average age)
    const avgAge = (socialAgeHours + infraAgeHours) / 2;
    const freshnessScore = Math.max(0, 1 - (avgAge / 24)); // Normalize to 24 hours

    let status: 'high' | 'moderate' | 'stale';
    if (avgAge < 6) status = 'high';
    else if (avgAge < 24) status = 'moderate';
    else status = 'stale';

    return {
      socialAgeHours: Math.round(socialAgeHours * 10) / 10,
      infraAgeHours,
      freshnessScore: Math.round(freshnessScore * 100) / 100,
      status
    };
  }

  /**
   * Compute indicator statistics (anti-inflation)
   */
  private computeIndicatorStatistics(
    signals: StructuredSignals,
    shodanDigest: ShodanDigest
  ): IndicatorStatistics {
    const allIndicators = [
      ...signals.extractedCVEs,
      ...signals.domains,
      ...signals.ips,
      ...signals.ports.map(p => String(p)),
      ...signals.services
    ];

    const uniqueCVECount = signals.extractedCVEs.length;
    const uniqueDomainCount = signals.domains.length;
    const uniqueIPCount = signals.ips.length;
    const uniquePortCount = signals.ports.length;
    const uniqueServiceCount = signals.services.length;

    // Count duplicates (appear in both X and Shodan)
    const duplicates = signals.extractedCVEs.filter(cve => 
      shodanDigest.uniqueCVEs.includes(cve)
    ).length;

    const totalIndicators = allIndicators.length;
    const duplicationRatio = totalIndicators > 0 ? duplicates / totalIndicators : 0;

    return {
      uniqueCVECount,
      uniqueDomainCount,
      uniqueIPCount,
      uniquePortCount,
      uniqueServiceCount,
      totalIndicators,
      duplicates,
      duplicationRatio: Math.round(duplicationRatio * 100) / 100
    };
  }

  /**
   * Compute risk computation with transparent weights
   */
  private computeRiskComputation(
    signals: StructuredSignals,
    shodanDigest: ShodanDigest,
    correlation: QuantifiedCorrelation,
    freshness: DataFreshness,
    previousRiskScore: number
  ): RiskComputation {
    // Calculate component scores (0-1)
    const vulnerabilityRatio = shodanDigest.totalHosts > 0 
      ? shodanDigest.vulnerableHosts / shodanDigest.totalHosts 
      : 0;

    const socialIntensity = Math.min(
      (signals.extractedCVEs.length + signals.exploitationClaims.length) / 10,
      1
    );

    const correlationScore = correlation.score;
    const freshnessScore = freshness.freshnessScore;
    const baselineDelta = Math.min(Math.abs(previousRiskScore - 50) / 50, 1);

    // Weights for transparency
    const weights = {
      vulnerabilityRatio: 0.35,
      socialIntensity: 0.25,
      correlationScore: 0.25,
      freshnessScore: 0.10,
      baselineDelta: 0.05
    };

    // Compute weighted score (0-100)
    let computedScore = Math.round(
      (vulnerabilityRatio * weights.vulnerabilityRatio +
       socialIntensity * weights.socialIntensity +
       correlationScore * weights.correlationScore +
       freshnessScore * weights.freshnessScore +
       baselineDelta * weights.baselineDelta) * 100
    );

    // Cap risk if data is stale - stale data cannot support critical risk
    if (freshness.status === 'stale') {
      computedScore = Math.min(computedScore, 50); // Max moderate risk with stale data
    } else if (freshness.status === 'moderate') {
      computedScore = Math.min(computedScore, 75); // Max elevated risk with moderate freshness
    }

    // Confidence based on data quality
    const confidenceLevel = Math.round(
      (freshnessScore * 0.4 + correlationScore * 0.3 + (1 - socialIntensity) * 0.3) * 100
    );

    return {
      weights,
      components: {
        vulnerabilityRatio: Math.round(vulnerabilityRatio * 100) / 100,
        socialIntensity: Math.round(socialIntensity * 100) / 100,
        correlationScore,
        freshnessScore,
        baselineDelta: Math.round(baselineDelta * 100) / 100
      },
      computedScore,
      confidenceLevel
    };
  }

  /**
   * Classify threat type
   */
  private classifyThreat(
    signals: StructuredSignals,
    shodanDigest: ShodanDigest,
    correlation: QuantifiedCorrelation,
    technical: TechnicalAssessment
  ): ThreatClassification {
    let type: 'opportunistic' | 'targeted' | 'campaign';
    let confidence: number;
    let indicators: string[] = [];
    let rationale: string;

    // Classification heuristics - must respect correlation data
    const highExposedServices = shodanDigest.totalHosts > 100;
    const lowCVESpecificity = signals.extractedCVEs.length < 3;
    const specificCVE = signals.extractedCVEs.length >= 3;
    const specificService = shodanDigest.topPorts.length > 0 && signals.keywords.length > 0;
    const narrowInfraScope = shodanDigest.totalHosts < 50 && shodanDigest.totalHosts > 0;
    const repeatedSignals = signals.exploitationClaims.length > 3;
    
    // Correlation-based checks - cannot claim strong correlation if score is low
    const hasStrongCorrelation = correlation.score > 0.6 && correlation.strength === 'strong';
    const hasModerateCorrelation = correlation.score > 0.3 && correlation.strength === 'moderate';
    const hasWeakCorrelation = correlation.score < 0.3 || correlation.strength === 'weak';
    const hasActualOverlap = correlation.factors.cveOverlap > 0 || correlation.factors.serviceMatch > 0.3;
    
    // Targeted requires: specific CVE, narrow scope, AND actual correlation evidence
    const isTargetedCandidate = specificCVE && narrowInfraScope && hasActualOverlap;
    
    // Campaign requires: repeated signals AND moderate+ correlation
    const isCampaignCandidate = repeatedSignals && (hasModerateCorrelation || hasStrongCorrelation);

    if (isTargetedCandidate && technical.tacticalClassification === 'targeted') {
      type = 'targeted';
      confidence = hasStrongCorrelation ? 75 : hasModerateCorrelation ? 60 : 40;
      indicators = [];
      if (specificCVE) indicators.push('Specific CVE targeting');
      if (narrowInfraScope) indicators.push('Narrow infrastructure scope');
      if (hasStrongCorrelation) indicators.push('Strong cross-source correlation');
      else if (hasModerateCorrelation) indicators.push('Moderate cross-source correlation');
      else indicators.push('Limited correlation evidence');
      
      rationale = hasStrongCorrelation 
        ? 'Indicators suggest targeted attack pattern with specific CVE and strong infrastructure correlation.'
        : 'Some indicators suggest targeting but correlation evidence is limited.';
    } else if (isCampaignCandidate) {
      type = 'campaign';
      confidence = hasStrongCorrelation ? 80 : 65;
      indicators = ['Repeated exploitation signals'];
      if (hasStrongCorrelation) indicators.push('Strong temporal clustering');
      if (hasActualOverlap) indicators.push('Multi-indicator overlap');
      rationale = 'Pattern consistent with coordinated campaign activity.';
    } else {
      // Default: opportunistic - especially when correlation is weak
      type = 'opportunistic';
      
      // Confidence based on data quality
      if (hasWeakCorrelation || correlation.score === 0) {
        confidence = 30; // Low confidence due to lack of correlation
        indicators = ['No significant cross-source correlation'];
        if (lowCVESpecificity) indicators.push('Low CVE specificity');
        rationale = 'Pattern suggests opportunistic scanning. No strong correlation between social and infrastructure indicators.';
      } else {
        confidence = highExposedServices && lowCVESpecificity ? 70 : 50;
        indicators = ['Broad infrastructure exposure'];
        if (lowCVESpecificity) indicators.push('Low CVE specificity');
        if (!hasStrongCorrelation) indicators.push('Weak cross-source correlation');
        rationale = 'Pattern consistent with opportunistic scanning rather than targeted exploitation.';
      }
    }

    return {
      type,
      confidence,
      rationale,
      indicators
    };
  }

  /**
   * Generate narrative summary
   */
  private generateNarrative(
    signals: StructuredSignals,
    correlation: QuantifiedCorrelation,
    classification: ThreatClassification
  ): string {
    return `Today we observed ${signals.tone} activity related to ${signals.keywords.slice(0, 2).join(', ') || 'threat intelligence'}. ` +
           `The correlation strength is ${correlation.strength} (${Math.round(correlation.score * 100)}%), ` +
           `primarily driven by ${Object.entries(correlation.factors)
             .sort(([,a], [,b]) => b - a)[0][0].replace(/([A-Z])/g, ' $1').toLowerCase()}. ` +
           `This pattern is consistent with ${classification.type} ${classification.type === 'campaign' ? 'activity' : 'scanning'}.`;
  }

  // ==================== Helper Methods ====================

  /** Token budget assertion (Refactor 1) */
  private assertTokenBudget(text: string, limit: number, context: string): void {
    const approxTokens = Math.ceil(text.length / 4);
    if (approxTokens > limit) {
      console.log(`    Warning: ${context} prompt (${approxTokens} tokens) exceeds safe limit (${limit})`);
    }
  }

  /** Token-safe truncation */
  private truncateTokenSafe(text: string, maxTokens: number): string {
    const maxChars = maxTokens * 4;
    if (text.length <= maxChars) return text;
    return text.substring(0, maxChars - 3) + '...';
  }

  /** Call Ollama with model-specific settings (Refactor 5) */
  private async callOllama(model: string, prompt: string, isTechnical: boolean, retryCount = 0): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
      console.log(`    [Ollama] Calling ${model.split('/').pop()} (attempt ${retryCount + 1}/${MAX_RETRIES + 1})...`);
      const startTime = Date.now();

      // Model-specific settings (Refactor 5)
      const options = {
        temperature: isTechnical ? 0.2 : 0.3,
        num_predict: isTechnical ? 600 : 900,
        top_p: 0.9
      };

      const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({ model, prompt, stream: false, options })
      });

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      if (!res.ok) {
        throw new Error(`Ollama HTTP ${res.status}`);
      }

      const data = await res.json() as { response: string };
      console.log(`    [Ollama] Response in ${elapsed}s`);
      return data.response || '';
    } catch (error) {
      clearTimeout(timeout);

      if (retryCount < MAX_RETRIES) {
        const isTimeout = error instanceof Error && error.name === 'AbortError';
        const waitTime = Math.pow(2, retryCount) * 5000;
        console.log(`    [Ollama] ${isTimeout ? 'Timeout' : 'Error'}, retrying in ${waitTime / 1000}s...`);
        await this.sleep(waitTime);
        return this.callOllama(model, prompt, isTechnical, retryCount + 1);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private filterXPosts(posts: XPost[]): XPost[] {
    return posts
      .filter(p => !p.text.startsWith('@'))
      .filter(p => p.text.length > 50)
      .sort((a, b) => (b.metrics.likes + b.metrics.reposts * 2) - (a.metrics.likes + a.metrics.reposts * 2));
  }

  private anonymizeIP(ip: string): string {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
    return ip;
  }

  private countOverlap(arr1: string[], arr2: string[]): number {
    const set2 = new Set(arr2.map(s => s.toUpperCase()));
    return arr1.filter(s => set2.has(s.toUpperCase())).length;
  }

  private validateTone(tone: string): 'speculative' | 'confirmed' | 'mixed' {
    const t = tone.toLowerCase();
    if (t.includes('confirm')) return 'confirmed';
    if (t.includes('specul')) return 'speculative';
    return 'mixed';
  }

  private extractSection(text: string, keyword: string, fallback: string): string {
    const lines = text.split('\n');
    for (const line of lines) {
      if (line.toLowerCase().includes(keyword)) {
        return line.replace(/^[\d.\-:*]+\s*/, '').trim() || fallback;
      }
    }
    return fallback;
  }

  private generateHeadline(riskLevel: string): string {
    const headlines: Record<string, string> = {
      critical: 'CRITICAL: Immediate action required',
      elevated: 'ELEVATED: Active threats detected',
      moderate: 'MODERATE: Monitor and assess',
      low: 'LOW: Routine monitoring active'
    };
    return headlines[riskLevel] || 'Threat Level: MODERATE';
  }

  private inferTrend(xSignals: XStructuredSignals, shodanDigest: ShodanDigest): 'increasing' | 'stable' | 'decreasing' {
    if (xSignals.tone === 'confirmed' || xSignals.exploitationClaims.length > 2) {
      return 'increasing';
    }
    if (shodanDigest.vulnerableHosts > shodanDigest.totalHosts * 0.3) {
      return 'increasing';
    }
    return 'stable';
  }

  private calculateSeverityDistribution(riskLevel: string, total: number): { criticalCount: number; highCount: number; mediumCount: number; lowCount: number } {
    const t = Math.max(total, 1);
    switch (riskLevel) {
      case 'critical':
        return { criticalCount: Math.ceil(t * 0.4), highCount: Math.ceil(t * 0.3), mediumCount: Math.ceil(t * 0.2), lowCount: Math.floor(t * 0.1) };
      case 'elevated':
        return { criticalCount: Math.ceil(t * 0.15), highCount: Math.ceil(t * 0.35), mediumCount: Math.ceil(t * 0.35), lowCount: Math.floor(t * 0.15) };
      case 'moderate':
        return { criticalCount: Math.ceil(t * 0.05), highCount: Math.ceil(t * 0.2), mediumCount: Math.ceil(t * 0.5), lowCount: Math.floor(t * 0.25) };
      default:
        return { criticalCount: 0, highCount: Math.ceil(t * 0.1), mediumCount: Math.ceil(t * 0.3), lowCount: Math.floor(t * 0.6) };
    }
  }

  private buildTimeline(xSignals: XStructuredSignals, shodanDigest: ShodanDigest): Array<{ id: string; title: string; severity: string; category: string; timestamp: string; sourceUrl?: string }> {
    const timeline: Array<{ id: string; title: string; severity: string; category: string; timestamp: string; sourceUrl?: string }> = [];
    const now = new Date();

    if (shodanDigest.vulnerableHosts > 0) {
      timeline.push({
        id: `infra_${Date.now()}`,
        title: `Vulnerable Infrastructure Detected (${shodanDigest.vulnerableHosts} hosts)`,
        severity: shodanDigest.vulnerableHosts > 10 ? 'critical' : 'high',
        category: 'Infrastructure',
        timestamp: now.toISOString()
      });
    }

    xSignals.topPosts.slice(0, 3).forEach((post, i) => {
      timeline.push({
        id: `social_${Date.now()}_${i}`,
        title: post.excerpt.slice(0, 60) + '...',
        severity: 'medium',
        category: 'Social Intel',
        timestamp: now.toISOString(),
        sourceUrl: post.url
      });
    });

    return timeline.slice(0, 5);
  }

  // ==================== Data Loading ====================

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
      await fs.writeFile(path.join(this.outputDir, 'orchestrator-debug.json'), JSON.stringify(outputs, null, 2));
    } catch { /* non-critical */ }
  }

  // ==================== Empty State Factories ====================

  private getEmptyXSignals(): XStructuredSignals {
    return { themes: [], cves: [], iocs: { ips: [], domains: [], hashes: [] }, exploitationClaims: [], tone: 'mixed', topPosts: [] };
  }

  private getEmptyShodanDigest(): ShodanDigest {
    return { totalHosts: 0, topPorts: [], topCountries: [], vulnerableHosts: 0, uniqueCVEs: [], bannerPatterns: [], sampleHosts: [] };
  }

  private getEmptyTechnicalAssessment(): TechnicalAssessment {
    return { exploitAlignment: '', infrastructurePatterns: '', tacticalClassification: 'unknown', confidenceLevel: 'low', rawResponse: '' };
  }

  private getEmptyStrategicSynthesis(): StrategicSynthesis {
    return { executiveSummary: 'Insufficient data for analysis.', correlationReasoning: '', recommendedActions: ['Configure data sources'], rawResponse: '' };
  }

  private getEmptySignalLayer(): SignalLayer {
    return {
      raw: { xPosts: [], shodanResults: [] },
      structured: {
        extractedCVEs: [],
        domains: [],
        ips: [],
        ports: [],
        services: [],
        keywords: [],
        exploitationClaims: [],
        tone: 'mixed',
        topPosts: []
      }
    };
  }

  private getEmptyAssessmentLayer(): AssessmentLayer {
    return {
      correlation: {
        score: 0,
        strength: 'weak',
        factors: { cveOverlap: 0, serviceMatch: 0, temporalProximity: 0, infraSocialAlignment: 0 },
        explanation: 'No data available for correlation analysis.'
      },
      scoring: {
        weights: { vulnerabilityRatio: 0.35, socialIntensity: 0.25, correlationScore: 0.25, freshnessScore: 0.1, baselineDelta: 0.05 },
        components: { vulnerabilityRatio: 0, socialIntensity: 0, correlationScore: 0, freshnessScore: 0, baselineDelta: 0 },
        computedScore: 0,
        confidenceLevel: 0
      },
      baselineComparison: {
        previousRiskScore: 50,
        currentRiskScore: 0,
        delta: 0,
        anomalyLevel: 'stable',
        trendDirection: 'stable'
      },
      freshness: {
        socialAgeHours: 0,
        infraAgeHours: 0,
        freshnessScore: 0,
        status: 'stale'
      },
      classification: {
        type: 'opportunistic',
        confidence: 0,
        rationale: 'Insufficient data for threat classification.',
        indicators: []
      },
      iocStats: {
        uniqueCVECount: 0,
        uniqueDomainCount: 0,
        uniqueIPCount: 0,
        uniquePortCount: 0,
        uniqueServiceCount: 0,
        totalIndicators: 0,
        duplicates: 0,
        duplicationRatio: 0
      },
      narrative: 'No data available for analysis.'
    };
  }

  private getEmptyDashboard(): CTIDashboardOutput {
    const now = new Date();
    return {
      meta: { version: '3.0.0', generatedAt: now.toISOString(), validUntil: new Date(now.getTime() + 6 * 3600000).toISOString() },
      status: { riskLevel: 'low', riskScore: 20, trend: 'stable', confidenceLevel: 35 },
      executive: { headline: 'LOW: Insufficient data', summary: 'Unable to complete analysis.', keyFindings: [], recommendedActions: ['Configure data sources'] },
      metrics: { totalSignals: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, categories: [] },
      timeline: [],
      sources: [],
      indicators: { cves: [], domains: [], ips: [], keywords: [] },
      infrastructure: { totalHosts: 0, exposedPorts: [], topCountries: [], vulnerableHosts: 0, sampleHosts: [] },
      ctiAnalysis: { model: TECHNICAL_MODEL, killChainPhase: 'Unknown', threatLandscape: '', analystBrief: '', correlationStrength: 'weak', technicalAssessment: '', methodologies: [] },
      signalLayer: this.getEmptySignalLayer(),
      assessmentLayer: this.getEmptyAssessmentLayer(),
      modelMetadata: { strategic: STRATEGIC_MODEL, technical: TECHNICAL_MODEL }
    };
  }
}

export default CTIOrchestrator;
