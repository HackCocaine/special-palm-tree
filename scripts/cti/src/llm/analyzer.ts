/**
 * LLM Analyzer - Ollama Local (modelo ligero ~500MB)
 * Optimizado para GitHub Actions con prompts compactos
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { ProcessedData, LLMAnalysisResult } from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'qwen2:0.5b';

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
   * - Calcula métricas agregadas
   */
  private normalizeForLLM(data: ProcessedData): NormalizedData {
    const { threats, indicators, summary } = data;
    
    // Top 5 amenazas por severidad
    const topThreats = threats
      .slice(0, 5)
      .map(t => ({
        sev: t.severity[0].toUpperCase(), // c/h/m/l/i
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

    return {
      threatCount: summary.totalThreats,
      critical: summary.bySeverity.critical || 0,
      high: summary.bySeverity.high || 0,
      medium: summary.bySeverity.medium || 0,
      topCategory: this.getTopKey(summary.byCategory),
      topThreats,
      iocCounts,
      cves,
      sources: Object.keys(summary.bySource)
    };
  }

  /**
   * Prompt ultra-compacto para modelo pequeño
   * ~200 tokens de entrada máximo
   */
  private buildCompactPrompt(d: NormalizedData): string {
    const threatList = d.topThreats
      .map(t => `[${t.sev}] ${t.cat}: ${t.title}`)
      .join('\n');

    return `CTI Report. Answer JSON only.
Stats: ${d.threatCount} threats, ${d.critical} critical, ${d.high} high
Top category: ${d.topCategory}
CVEs: ${d.cves.join(', ') || 'none'}
IOCs: ${Object.entries(d.iocCounts).map(([k,v]) => `${k}:${v}`).join(', ')}

Threats:
${threatList}

Output format:
{"risk":"critical|high|medium|low","summary":"1 sentence","action":"1 priority action"}`;
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
            temperature: 0.1,
            num_predict: 100,
            top_p: 0.9,
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
    return `${d.threatCount} amenazas detectadas, ${d.critical} críticas. Foco: ${d.topCategory}.`;
  }

  private defaultAction(d: NormalizedData): string {
    if (d.critical > 0) return 'Revisar amenazas críticas inmediatamente';
    if (d.high > 0) return 'Priorizar amenazas de severidad alta';
    return 'Monitorear indicadores detectados';
  }

  private buildResult(
    data: NormalizedData, 
    risk: string, 
    summary: string, 
    action: string,
    model: string
  ): LLMAnalysisResult {
    return {
      insights: [{
        id: `insight_${Date.now()}`,
        type: 'trend',
        title: 'Análisis CTI',
        content: summary,
        confidence: model === 'ollama' ? 75 : 70,
        relatedThreats: []
      }],
      executiveSummary: summary,
      technicalSummary: `IOCs: ${Object.entries(data.iocCounts).map(([k,v]) => `${v} ${k}`).join(', ')}. CVEs: ${data.cves.length}. Fuentes: ${data.sources.join(', ')}.`,
      recommendations: [action],
      trendingTopics: [{
        topic: data.topCategory,
        growth: 0,
        relevance: 100
      }],
      analysisTimestamp: new Date().toISOString(),
      model: `${OLLAMA_MODEL}-${model}`,
      tokenUsage: { input: 0, output: 0, total: 0 }
    };
  }

  private emptyResult(): LLMAnalysisResult {
    return {
      insights: [],
      executiveSummary: 'Sin datos para analizar.',
      technicalSummary: 'Ejecutar scrapers primero.',
      recommendations: ['Ejecutar pipeline con scrapers habilitados'],
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
}

export default LLMAnalyzer;
