/**
 * LLM Analyzer - Ollama Local
 * 
 * Modelos recomendados para CTI (por capacidad):
 * - llama3.2:3b  (~2GB)  - Recomendado para análisis de amenazas, mejor comprensión
 * - phi3:mini    (~2GB)  - Buena alternativa, rápido
 * - qwen2:1.5b   (~1GB)  - Balance velocidad/capacidad
 * - qwen2:0.5b   (~500MB)- Solo si memoria es muy limitada
 * 
 * Para containers GitHub Actions: llama3.2:3b funciona con 4GB+ RAM
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { ProcessedData, LLMAnalysisResult } from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
// Default to more capable model - override with OLLAMA_MODEL env var if needed
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.2:3b';

export class LLMAnalyzer {
  private outputDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  async analyze(): Promise<LLMAnalysisResult> {
    console.log(`[LLM] Ollama ${OLLAMA_MODEL} @ ${OLLAMA_HOST}`);
    
    const data = await this.loadData();
    if (!data || data.threats.length === 0) {
      console.log('[LLM] No data - using empty result');
      return this.emptyResult();
    }

    // Normalizar datos para el modelo pequeño
    const normalized = this.normalizeForLLM(data);
    const prompt = this.buildCompactPrompt(normalized);
    
    console.log(`[LLM] Prompt: ${prompt.length} chars, ${normalized.threatCount} threats`);

    try {
      const response = await this.callOllama(prompt);
      const result = this.parseResponse(response, normalized);
      await this.saveResult(result);
      return result;
    } catch (err) {
      console.log('[LLM] Ollama failed, using heuristics');
      const result = this.heuristicAnalysis(normalized);
      await this.saveResult(result);
      return result;
    }
  }

  /**
   * Normaliza y reduce datos para modelo pequeño
   * - Limita cantidad de elementos
   * - Extrae solo campos esenciales
   * - Incluye datos de correlación temporal
   */
  private normalizeForLLM(data: ProcessedData): NormalizedData {
    const { threats, indicators, summary, correlation } = data;
    
    // Top 5 amenazas por severidad
    const topThreats = threats
      .slice(0, 5)
      .map(t => ({
        sev: t.severity[0].toUpperCase(),
        cat: this.shortCategory(t.category),
        title: this.truncate(t.title, 40)
      }));

    // Contar IOCs por tipo
    const iocCounts = indicators.reduce((acc, i) => {
      acc[i.type] = (acc[i.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // CVEs únicos (máx 5)
    const cves = [...new Set(
      indicators.filter(i => i.type === 'cve').map(i => i.value)
    )].slice(0, 5);

    // Extraer datos de correlación
    const correlationSignals = correlation?.signals?.slice(0, 5).map(s => ({
      label: s.label,
      infraCount: s.sources.find(src => src.source === 'shodan')?.count || 0,
      socialCount: s.sources.find(src => src.source === 'x.com')?.count || 0,
      deltaHours: s.temporalAnalysis?.timeDeltaHours ?? null
    })) || [];

    const topCorr = correlation?.temporalCorrelations?.[0];

    return {
      threatCount: summary.totalThreats,
      critical: summary.bySeverity.critical || 0,
      high: summary.bySeverity.high || 0,
      medium: summary.bySeverity.medium || 0,
      topCategory: this.getTopKey(summary.byCategory),
      topThreats,
      iocCounts,
      cves,
      sources: Object.keys(summary.bySource),
      correlation: {
        signals: correlationSignals,
        pattern: correlation?.dominantPattern || 'insufficient-data',
        topCorrelation: topCorr?.interpretation || null
      }
    };
  }

  /**
   * Prompt for CTI analyst-style response with STRICT GROUNDING
   * CRITICAL: Model can ONLY reference data provided in prompt
   * No hallucination, no invented data, no assumptions
   * OUTPUT MUST BE IN ENGLISH ONLY
   */
  private buildCompactPrompt(d: NormalizedData): string {
    // Build ONLY factual data points
    const facts: string[] = [];
    
    // Fact 1: Signal counts (verifiable)
    facts.push(`FACT: ${d.threatCount} total signals collected`);
    facts.push(`FACT: Severity breakdown - ${d.critical} critical, ${d.high} high, ${d.medium} medium`);
    
    // Fact 2: Sources used
    facts.push(`FACT: Sources - ${d.sources.join(', ')}`);
    
    // Fact 3: Correlation data (only if exists) - Enhanced correlation context
    const corrSignals = d.correlation.signals.filter(s => s.infraCount > 0 && s.socialCount > 0);
    if (corrSignals.length > 0) {
      facts.push(`FACT: Cross-source correlation detected`);
      for (const sig of corrSignals.slice(0, 3)) {
        const delta = sig.deltaHours !== null ? Math.abs(sig.deltaHours).toFixed(1) : 'unknown';
        const direction = sig.deltaHours !== null 
          ? (sig.deltaHours > 0 ? 'infra preceded social' : 'social preceded infra')
          : 'timing unclear';
        facts.push(`CORR: ${sig.label} - infrastructure (${sig.infraCount} hosts), social (${sig.socialCount} mentions), ${delta}h delta, ${direction}`);
      }
      facts.push(`FACT: Dominant pattern - ${d.correlation.pattern}`);
      
      // Add interpretation guidance based on pattern
      if (d.correlation.pattern === 'infra-first') {
        facts.push(`CONTEXT: Infrastructure activity before social discussion typically indicates reconnaissance or early exploitation`);
      } else if (d.correlation.pattern === 'social-first') {
        facts.push(`CONTEXT: Social discussion before infrastructure activity may indicate emerging threat awareness or coordinated campaigns`);
      }
    } else {
      facts.push(`FACT: No cross-source correlation detected`);
    }
    
    // Fact 4: Specific signals detected
    const threatList = d.topThreats
      .map(t => `SIGNAL: [${t.sev}] ${t.cat} - ${t.title}`)
      .join('\n');

    return `STRICT GROUNDING RULES (ENGLISH ONLY OUTPUT):
1. ONLY reference data labeled FACT, CORR, or SIGNAL below
2. Do NOT invent CVEs, IPs, or specific numbers not provided
3. Do NOT assume causation - only state temporal observations
4. If data insufficient, say "insufficient data"
5. RESPOND IN ENGLISH ONLY - No other languages

VERIFIED DATA:
${facts.join('\n')}

${threatList}

OUTPUT JSON (use ONLY facts above, ENGLISH ONLY):
{"risk":"critical|high|medium|low","summary":"1-2 sentences in ENGLISH using ONLY facts provided. Focus on correlation between infrastructure and social signals if available.","action":"Specific action based on facts, in ENGLISH"}`;
  }

  private async callOllama(prompt: string): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);

    try {
      const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model: OLLAMA_MODEL,
          prompt,
          stream: false,
          options: {
            // GROUNDING: Minimize creativity, maximize factual adherence
            temperature: 0.01,      // Near-zero for deterministic output
            num_predict: 150,       // Allow slightly more for proper JSON
            top_p: 0.5,             // Narrow token selection
            top_k: 10,              // Very limited vocabulary
            repeat_penalty: 1.2,    // Discourage repetition
            stop: ['}', '\n\n']
          }
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      
      const json = await res.json() as { response: string };
      console.log(`[LLM] Response: ${json.response.length} chars`);
      return json.response;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Parser robusto con múltiples estrategias de fallback
   */
  private parseResponse(raw: string, data: NormalizedData): LLMAnalysisResult {
    let parsed: { risk?: string; summary?: string; action?: string } = {};

    // Estrategia 1: JSON completo
    try {
      const jsonMatch = raw.match(/\{[^{}]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      }
    } catch { /* fallback */ }

    // Estrategia 2: Extraer campos individualmente
    if (!parsed.risk) {
      const riskMatch = raw.match(/risk["\s:]+(\w+)/i);
      parsed.risk = riskMatch?.[1]?.toLowerCase();
    }
    if (!parsed.summary) {
      const sumMatch = raw.match(/summary["\s:]+["']?([^"'\n]+)/i);
      parsed.summary = sumMatch?.[1];
    }
    if (!parsed.action) {
      const actMatch = raw.match(/action["\s:]+["']?([^"'\n]+)/i);
      parsed.action = actMatch?.[1];
    }

    // Validar y normalizar risk level
    const validRisks = ['critical', 'high', 'medium', 'low'];
    const risk = validRisks.includes(parsed.risk || '') 
      ? parsed.risk! 
      : this.calculateRisk(data);

    // Construir resultado
    const summary = parsed.summary || this.defaultSummary(data);
    const action = parsed.action || this.defaultAction(data);

    return this.buildResult(data, risk, summary, action, 'ollama');
  }

  /**
   * Análisis heurístico cuando Ollama falla
   */
  private heuristicAnalysis(data: NormalizedData): LLMAnalysisResult {
    const risk = this.calculateRisk(data);
    const summary = this.defaultSummary(data);
    const action = this.defaultAction(data);
    return this.buildResult(data, risk, summary, action, 'heuristic');
  }

  private calculateRisk(d: NormalizedData): string {
    if (d.critical > 0) return 'critical';
    if (d.high > 2) return 'high';
    if (d.high > 0 || d.medium > 5) return 'medium';
    return 'low';
  }

  private defaultSummary(d: NormalizedData): string {
    // STRICT GROUNDING: Use ONLY data from normalized input
    const hasCorrelation = d.correlation.signals.some(s => s.infraCount > 0 && s.socialCount > 0);
    
    if (hasCorrelation) {
      const topSignal = d.correlation.signals.find(s => s.infraCount > 0 && s.socialCount > 0);
      const pattern = d.correlation.pattern;
      
      if (topSignal) {
        // Use exact numbers from data
        const infraCount = topSignal.infraCount;
        const socialCount = topSignal.socialCount;
        const hours = topSignal.deltaHours !== null ? topSignal.deltaHours.toFixed(0) : null;
        
        if (pattern === 'infra-first' && hours) {
          return `Both infrastructure exposure (${infraCount} signals) and social discussion (${socialCount} mentions) around ${topSignal.label} increased today. Infrastructure signals preceded social discussion by approximately ${hours} hours, suggesting early scanning activity rather than confirmed exploitation.`;
        } else if (pattern === 'social-first' && hours) {
          return `Social discussion of ${topSignal.label} (${socialCount} mentions) preceded infrastructure detection (${infraCount} signals) by ${hours} hours, indicating threat awareness before observable exposure.`;
        } else {
          return `${topSignal.label} detected across infrastructure (${infraCount}) and social (${socialCount}) sources. Temporal pattern: ${pattern}.`;
        }
      }
    }

    // No correlation - use only counts from data
    const sources = d.sources.join(' and ');
    
    if (d.threatCount === 0) {
      return `No threat signals detected from ${sources}. Intelligence collection completed without actionable findings.`;
    }
    
    // Build factual statement from exact counts
    const severityParts: string[] = [];
    if (d.critical > 0) severityParts.push(`${d.critical} critical`);
    if (d.high > 0) severityParts.push(`${d.high} high`);
    if (d.medium > 0) severityParts.push(`${d.medium} medium`);
    
    const severityText = severityParts.length > 0 ? ` (${severityParts.join(', ')})` : '';
    
    return `Intelligence collection from ${sources} identified ${d.threatCount} signals${severityText}. Primary category: ${this.formatCategory(d.topCategory)}.`;
  }

  private defaultAction(d: NormalizedData): string {
    // Correlation-aware recommendations
    const hasCorrelation = d.correlation.signals.some(s => s.infraCount > 0 && s.socialCount > 0);
    
    if (hasCorrelation && d.correlation.pattern === 'infra-first') {
      const topSignal = d.correlation.signals.find(s => s.infraCount > 0 && s.socialCount > 0);
      return `Verify ${topSignal?.label || 'affected services'} exposure and assess scanning activity scope`;
    }
    
    if (d.critical > 0) return 'Initiate incident response review for critical findings';
    if (d.high > 0) return 'Prioritize assessment of high-severity infrastructure exposure';
    return 'Continue routine threat monitoring across infrastructure and social channels';
  }

  private formatCategory(cat: string): string {
    const map: Record<string, string> = {
      malware: 'Malware', ransomware: 'Ransomware', phishing: 'Phishing',
      ddos: 'DDoS', apt: 'APT', vulnerability: 'Vulnerability',
      data_breach: 'Data Breach', supply_chain: 'Supply Chain',
      infrastructure: 'Infrastructure', other: 'General'
    };
    return map[cat] || cat;
  }

  private buildResult(
    data: NormalizedData, 
    risk: string, 
    summary: string, 
    action: string,
    model: string
  ): LLMAnalysisResult {
    // Build additional context-aware recommendations
    const recommendations = [action];
    
    // Add correlation-based recommendations
    const correlatedSignals = data.correlation.signals.filter(s => s.infraCount > 0 && s.socialCount > 0);
    if (correlatedSignals.length > 0) {
      const topSignal = correlatedSignals[0];
      recommendations.push(`Monitor ${topSignal.label} activity across both infrastructure and social channels`);
    }
    if (data.critical > 0 || data.high > 1) {
      recommendations.push('Review security controls and access policies');
    }

    // Technical context including correlation
    const techParts: string[] = [];
    if (correlatedSignals.length > 0) {
      techParts.push(`Cross-source correlation: ${correlatedSignals.map(s => s.label).join(', ')}`);
      techParts.push(`Temporal pattern: ${data.correlation.pattern}`);
    }
    if (Object.keys(data.iocCounts).length > 0) {
      techParts.push(`Indicators: ${Object.entries(data.iocCounts).map(([k,v]) => `${v} ${k}`).join(', ')}`);
    }
    techParts.push(`Sources: ${data.sources.map(s => s === 'x.com' ? 'Social Intelligence' : 'Infrastructure Recon').join(', ')}`);

    // Build insights array with correlation insight
    const insights: LLMAnalysisResult['insights'] = [{
      id: `insight_${Date.now()}`,
      type: 'correlation',
      title: 'Cross-Source Correlation Analysis',
      content: summary,
      confidence: model === 'ollama' ? 75 : 70,
      relatedThreats: []
    }];

    // Add temporal pattern insight if correlation exists
    if (data.correlation.topCorrelation) {
      insights.push({
        id: `insight_temporal_${Date.now()}`,
        type: 'trend',
        title: 'Temporal Pattern Detection',
        content: data.correlation.topCorrelation,
        confidence: 65,
        relatedThreats: []
      });
    }

    // Build trending topics from correlated signals
    const trendingTopics = correlatedSignals.slice(0, 3).map(s => ({
      topic: s.label,
      growth: s.deltaHours !== null && s.deltaHours > 0 ? 20 : 5,
      relevance: Math.min(s.infraCount + s.socialCount, 100)
    }));
    
    if (trendingTopics.length === 0) {
      trendingTopics.push({
        topic: this.formatCategory(data.topCategory),
        growth: data.critical > 0 ? 25 : (data.high > 0 ? 10 : 0),
        relevance: 100
      });
    }

    return {
      insights,
      executiveSummary: summary,
      technicalSummary: techParts.join('. ') + '.',
      recommendations: recommendations.slice(0, 4),
      trendingTopics,
      analysisTimestamp: new Date().toISOString(),
      model: `${OLLAMA_MODEL}-${model}`,
      tokenUsage: { input: 0, output: 0, total: 0 }
    };
  }

  private emptyResult(): LLMAnalysisResult {
    return {
      insights: [],
      executiveSummary: 'No threat intelligence data available for analysis. Intelligence collection may be pending or sources temporarily unavailable.',
      technicalSummary: 'Awaiting data from configured intelligence sources.',
      recommendations: ['Verify intelligence source connectivity', 'Check scraper configuration and credentials'],
      trendingTopics: [],
      analysisTimestamp: new Date().toISOString(),
      model: 'none',
      tokenUsage: { input: 0, output: 0, total: 0 }
    };
  }

  // Helpers
  private shortCategory(cat: string): string {
    const map: Record<string, string> = {
      malware: 'MAL', ransomware: 'RAN', phishing: 'PHI',
      ddos: 'DDOS', apt: 'APT', vulnerability: 'VUL',
      data_breach: 'BRE', supply_chain: 'SUP', other: 'OTH'
    };
    return map[cat] || cat.substring(0, 3).toUpperCase();
  }

  private truncate(s: string, len: number): string {
    return s.length > len ? s.substring(0, len - 3) + '...' : s;
  }

  private getTopKey(obj: Record<string, number>): string {
    return Object.entries(obj)
      .sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';
  }

  private async loadData(): Promise<ProcessedData | null> {
    try {
      const raw = await fs.readFile(
        path.join(this.outputDir, 'processed-data.json'), 'utf-8'
      );
      return JSON.parse(raw);
    } catch { return null; }
  }

  private async saveResult(result: LLMAnalysisResult): Promise<void> {
    await fs.mkdir(this.outputDir, { recursive: true });
    await fs.writeFile(
      path.join(this.outputDir, 'llm-analysis.json'),
      JSON.stringify(result, null, 2)
    );
  }
}

interface NormalizedData {
  threatCount: number;
  critical: number;
  high: number;
  medium: number;
  topCategory: string;
  topThreats: Array<{ sev: string; cat: string; title: string }>;
  iocCounts: Record<string, number>;
  cves: string[];
  sources: string[];
  // Correlation data
  correlation: {
    signals: Array<{ label: string; infraCount: number; socialCount: number; deltaHours: number | null }>;
    pattern: string;
    topCorrelation: string | null;
  };
}

export default LLMAnalyzer;
