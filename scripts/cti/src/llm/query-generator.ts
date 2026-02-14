/**
 * LLM Query Generator - Genera queries de Shodan basado en intel de X.com
 * 
 * Flujo: X.com social intel → LLM analysis → Dynamic Shodan queries
 * 
 * El LLM analiza:
 * - Menciones de CVEs específicos
 * - Campañas de ransomware/malware activas
 * - Puertos/servicios mencionados en discusiones
 * - Países/regiones objetivo
 * - TTPs (Tactics, Techniques, Procedures) observados
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { XScrapedData, XPost } from '../types/index.js';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
// Use same model as CTI analysis by default; allow override
const QUERY_MODEL = process.env.OLLAMA_QUERY_MODEL || process.env.OLLAMA_MODEL || 'qwen2.5:3b';

export interface ShodanQuerySuggestion {
  query: string;
  rationale: string;
  priority: 'high' | 'medium' | 'low';
  tags: string[];
}

export interface QueryGeneratorResult {
  timestamp: string;
  model: string;
  sourcePostsAnalyzed: number;
  queries: ShodanQuerySuggestion[];
  extractedIndicators: {
    cves: string[];
    ports: number[];
    services: string[];
    countries: string[];
    malwareFamilies: string[];
    threatActors: string[];
  };
  rawAnalysis: string;
}

// Mapeo de servicios/malware a puertos Shodan
const SERVICE_TO_PORT: Record<string, string> = {
  'ssh': 'port:22',
  'rdp': 'port:3389',
  'smb': 'port:445',
  'ftp': 'port:21',
  'telnet': 'port:23',
  'mysql': 'port:3306',
  'postgres': 'port:5432',
  'redis': 'port:6379',
  'mongodb': 'port:27017',
  'elasticsearch': 'port:9200',
  'apache': 'product:apache',
  'nginx': 'product:nginx',
  'iis': 'product:iis',
  'exchange': 'product:exchange',
  'citrix': 'product:citrix',
  'fortinet': 'product:fortinet',
  'palo alto': 'product:"palo alto"',
  'cisco': 'product:cisco',
  'mikrotik': 'product:mikrotik',
  'kubernetes': 'port:6443',
  'docker': 'port:2375,2376',
  'jenkins': 'product:jenkins',
  'gitlab': 'product:gitlab',
  'confluence': 'product:confluence',
  'jira': 'product:jira'
};

// Mapeo de países mencionados a códigos Shodan
const COUNTRY_TO_CODE: Record<string, string> = {
  'united states': 'US',
  'usa': 'US',
  'us': 'US',
  'china': 'CN',
  'russia': 'RU',
  'iran': 'IR',
  'north korea': 'KP',
  'germany': 'DE',
  'uk': 'GB',
  'united kingdom': 'GB',
  'france': 'FR',
  'japan': 'JP',
  'india': 'IN',
  'brazil': 'BR',
  'mexico': 'MX',
  'spain': 'ES'
};

export class QueryGenerator {
  private outputDir: string;
  private cacheDir: string;

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
    this.cacheDir = process.env.CTI_CACHE_DIR || './DATA/cti-cache';
  }

  /**
   * Verifica si hay cache válido (TTL de 24 horas)
   */
  private async loadFromCache(): Promise<QueryGeneratorResult | null> {
    try {
      const cachePath = path.join(this.cacheDir, 'query-generator-cache.json');
      await fs.access(cachePath);
      
      const raw = await fs.readFile(cachePath, 'utf-8');
      const cached = JSON.parse(raw) as QueryGeneratorResult;
      
      // Verificar si el cache es del mismo día
      const cacheDate = new Date(cached.timestamp).toDateString();
      const today = new Date().toDateString();
      
      if (cacheDate === today) {
        console.log('[QueryGen] Using cached queries from today');
        return cached;
      }
      
      console.log('[QueryGen] Cache expired (different day)');
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Guarda resultado en cache
   */
  private async saveToCache(result: QueryGeneratorResult): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      await fs.writeFile(
        path.join(this.cacheDir, 'query-generator-cache.json'),
        JSON.stringify(result, null, 2)
      );
      console.log('[QueryGen] Saved to cache');
    } catch (err) {
      console.log('[QueryGen] Failed to save cache:', err);
    }
  }

  /**
   * Genera queries de Shodan analizando datos de X.com con LLM
   */
  async generateQueries(useCache: boolean = true): Promise<QueryGeneratorResult> {
    console.log(`[QueryGen] Using model: ${QUERY_MODEL}`);
    
    // Intentar usar cache primero
    if (useCache) {
      const cached = await this.loadFromCache();
      if (cached) return cached;
    }
    
    const xData = await this.loadXData();
    if (!xData || xData.posts.length === 0) {
      console.log('[QueryGen] No X.com data available');
      return this.emptyResult();
    }

    // Extraer indicadores directamente del texto (rápido, sin LLM)
    const indicators = this.extractIndicatorsFromPosts(xData.posts);
    
    // Construir prompt con contexto social
    const prompt = this.buildAnalysisPrompt(xData.posts, indicators);
    
    console.log(`[QueryGen] Analyzing ${xData.posts.length} posts for query generation`);

    let rawAnalysis = '';
    let llmQueries: ShodanQuerySuggestion[] = [];

    try {
      rawAnalysis = await this.callOllama(prompt);
      llmQueries = this.parseLLMResponse(rawAnalysis);
    } catch (err) {
      console.log('[QueryGen] LLM failed, using heuristic query generation');
      rawAnalysis = 'LLM unavailable - using heuristics';
    }

    // Combinar queries del LLM con queries heurísticas basadas en indicadores
    const heuristicQueries = this.generateHeuristicQueries(indicators);
    const allQueries = this.mergeAndDeduplicateQueries(llmQueries, heuristicQueries);

    const result: QueryGeneratorResult = {
      timestamp: new Date().toISOString(),
      model: QUERY_MODEL,
      sourcePostsAnalyzed: xData.posts.length,
      queries: allQueries,
      extractedIndicators: indicators,
      rawAnalysis
    };

    await this.saveResult(result);
    await this.saveToCache(result);
    return result;
  }

  /**
   * Extrae indicadores directamente del texto de posts
   * Enhanced extraction for better context-aware queries
   */
  private extractIndicatorsFromPosts(posts: XPost[]): QueryGeneratorResult['extractedIndicators'] {
    const allText = posts.map(p => p.text.toLowerCase()).join(' ');
    
    // CVEs (pattern: CVE-YYYY-NNNNN) - also capture mentioned CVEs
    const cveMatches = allText.match(/cve-\d{4}-\d{4,}/gi) || [];
    const cves = [...new Set(cveMatches.map(c => c.toUpperCase()))];

    // Puertos mencionados explícitamente
    const portMatches = allText.match(/port[:\s]+(\d+)/gi) || [];
    const ports = [...new Set(portMatches.map(p => {
      const num = p.match(/\d+/)?.[0];
      return num ? parseInt(num) : 0;
    }).filter(p => p > 0 && p < 65536))];

    // Servicios/productos - expanded list
    const services = Object.keys(SERVICE_TO_PORT)
      .filter(service => allText.includes(service.toLowerCase()));

    // Países
    const countries = Object.keys(COUNTRY_TO_CODE)
      .filter(country => allText.includes(country.toLowerCase()))
      .map(c => COUNTRY_TO_CODE[c]);

    // Malware families - expanded list with modern ransomware
    const malwarePatterns = [
      'lockbit', 'blackcat', 'alphv', 'clop', 'royal', 'play', 'akira',
      'rhysida', 'medusa', 'bianlian', 'hive', 'conti', 'revil', 'sodinokibi',
      'emotet', 'qakbot', 'cobalt strike', 'trickbot', 'icedid', 'bumblebee',
      'dragonforce', 'reynolds', 'blackbasta', 'blacksuit', 'hunters',
      'cactus', 'trigona', '8base', 'noescape', 'qilin', 'phobos', 'mallox'
    ];
    const malwareFamilies = malwarePatterns.filter(m => allText.includes(m));

    // Threat actors - expanded with current APT groups
    const actorPatterns = [
      'lazarus', 'apt28', 'apt29', 'cozy bear', 'fancy bear', 'sandworm',
      'hafnium', 'nobelium', 'scattered spider', 'lapsus', 'fin7', 'fin8',
      'mustangpanda', 'unc6384', 'volt typhoon', 'charming kitten', 
      'turla', 'gamaredon', 'kimsuky', 'ta505', 'ta577', 'ta569',
      'unc3886', 'unc4841', 'midnight blizzard', 'star blizzard'
    ];
    const threatActors = actorPatterns.filter(a => allText.includes(a));

    return { cves, ports, services, countries, malwareFamilies, threatActors };
  }

  /**
   * Construye prompt para análisis de CTI
   */
  private buildAnalysisPrompt(posts: XPost[], indicators: QueryGeneratorResult['extractedIndicators']): string {
    // Resumir posts (máx 15 más relevantes por engagement)
    const sortedPosts = posts
      .sort((a, b) => (b.metrics.likes + b.metrics.reposts) - (a.metrics.likes + a.metrics.reposts))
      .slice(0, 15);

    const postSummaries = sortedPosts.map((p, i) => {
      const engagement = p.metrics.likes + p.metrics.reposts;
      return `[${i + 1}] @${p.author.username} (${engagement} engagement): ${p.text.slice(0, 200)}${p.text.length > 200 ? '...' : ''}`;
    }).join('\n\n');

    return `You are a CTI analyst. Analyze these recent security-related social media posts and suggest Shodan queries.

CONTEXT - Already Extracted Indicators:
- CVEs: ${indicators.cves.join(', ') || 'none'}
- Ports: ${indicators.ports.join(', ') || 'none'}
- Services: ${indicators.services.join(', ') || 'none'}
- Malware: ${indicators.malwareFamilies.join(', ') || 'none'}
- Threat Actors: ${indicators.threatActors.join(', ') || 'none'}

SOCIAL INTEL (Top 15 posts by engagement):
${postSummaries}

INSTRUCTIONS:
Based on the social intel above, suggest Shodan queries to find potentially exposed infrastructure.

SHODAN QUERY SYNTAX (free tier):
- port:22 (single port)
- port:22,3389,445 (multiple ports)
- country:US (single country)
- product:apache (product name)
- os:windows (operating system)
- Combine with spaces: port:22 country:US

IMPORTANT: Free tier cannot use vuln: filter. Focus on ports, products, and countries.
IMPORTANT: Do NOT suggest generic baseline scans like "port:22,3389,445" unless those services are explicitly supported by social evidence.
Every query must be traceable to at least one social indicator (CVE, actor, malware family, campaign, product, or discussed region).

RESPOND WITH JSON ARRAY:
[
  {
    "query": "shodan query string",
    "rationale": "why this query is relevant based on the social intel",
    "priority": "high|medium|low",
    "tags": ["relevant", "tags"]
  }
]

Only suggest 3-5 queries. Be specific and actionable.`;
  }

  /**
   * Llama a Ollama con el modelo configurado
   */
  private async callOllama(prompt: string): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000); // 2 min timeout

    try {
      const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          model: QUERY_MODEL,
          prompt,
          stream: false,
          options: {
            temperature: 0.3,      // Algo de creatividad para queries
            num_predict: 800,      // Respuesta más larga
            top_p: 0.9,
            top_k: 40
          }
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      
      const json = await res.json() as { response: string };
      console.log(`[QueryGen] LLM response: ${json.response.length} chars`);
      return json.response;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Parsea respuesta del LLM
   */
  private parseLLMResponse(raw: string): ShodanQuerySuggestion[] {
    try {
      // Buscar array JSON en la respuesta
      const jsonMatch = raw.match(/\[[\s\S]*\]/);
      if (!jsonMatch) return [];

      const parsed = JSON.parse(jsonMatch[0]) as ShodanQuerySuggestion[];
      
      // Validar y filtrar
      return parsed.filter(q => 
        q.query && 
        typeof q.query === 'string' && 
        q.query.length > 3 &&
        !q.query.includes('vuln:') && // Free tier no puede usar vuln:
        !this.isOverGenericQuery(q.query)
      ).map(q => ({
        query: q.query.trim(),
        rationale: q.rationale || 'LLM suggested',
        priority: ['high', 'medium', 'low'].includes(q.priority) ? q.priority : 'medium',
        tags: Array.isArray(q.tags) ? q.tags : []
      }));
    } catch {
      console.log('[QueryGen] Failed to parse LLM JSON response');
      return [];
    }
  }

  /**
   * Genera queries heurísticas MÍNIMAS basadas en indicadores explícitos.
   * Objetivo: evitar mapeos manuales (falsos positivos) y preferir razonamiento del LLM.
   */
  private generateHeuristicQueries(indicators: QueryGeneratorResult['extractedIndicators']): ShodanQuerySuggestion[] {
    const queries: ShodanQuerySuggestion[] = [];

    // Query basada en servicios mencionados explícitamente (evidencia social)
    if (indicators.services.length > 0) {
      const serviceTerms = indicators.services
        .map(s => SERVICE_TO_PORT[s])
        .filter(Boolean)
        .slice(0, 3);

      if (serviceTerms.length > 0) {
        queries.push({
          query: serviceTerms.join(' '),
          rationale: `Services explicitly discussed in social intel: ${indicators.services.join(', ')}`,
          priority: 'high',
          tags: ['services', 'explicit']
        });
      }
    }

    // Query based on explicit ports mentioned
    if (indicators.ports.length > 0) {
      queries.push({
        query: `port:${indicators.ports.slice(0, 5).join(',')}`,
        rationale: `Ports explicitly mentioned in social discussion`,
        priority: 'medium',
        tags: ['ports', 'explicit-mention']
      });
    }

    // Geographic constraint if mentioned (only as refinement)
    if (indicators.countries.length > 0 && queries.length > 0) {
      const country = indicators.countries[0];
      queries[0] = {
        ...queries[0],
        query: `${queries[0].query} country:${country}`,
        rationale: `${queries[0].rationale} - geographic focus mentioned: ${country}`,
        tags: [...queries[0].tags, 'geographic', country.toLowerCase()]
      };
    }

    // If no explicit indicators extracted, return empty (avoid generic scans)
    if (queries.length === 0) {
      console.log('[QueryGen] No explicit indicators to query - returning empty (avoid generic scans)');
    }

    return queries;
  }

  /**
   * Combina y deduplica queries del LLM y heurísticas
   */
  private mergeAndDeduplicateQueries(
    llmQueries: ShodanQuerySuggestion[],
    heuristicQueries: ShodanQuerySuggestion[]
  ): ShodanQuerySuggestion[] {
    const seen = new Set<string>();
    const result: ShodanQuerySuggestion[] = [];

    // LLM queries tienen prioridad (van primero)
    for (const q of [...llmQueries, ...heuristicQueries]) {
      const normalized = q.query.toLowerCase().trim();
      if (!seen.has(normalized) && !this.isOverGenericQuery(q.query)) {
        seen.add(normalized);
        result.push(q);
      }
    }

    // Limitar a 5 queries para respetar rate limits de Shodan free tier
    return result.slice(0, 5);
  }

  private isOverGenericQuery(query: string): boolean {
    const normalized = query.toLowerCase().replace(/\s+/g, ' ').trim();
    const genericPatterns = [
      'port:22,3389,445',
      'port:22,445',
      'port:22',
      'port:3389',
      'port:445',
      'port:22,3389,445,3306'
    ];

    return genericPatterns.includes(normalized);
  }

  private async loadXData(): Promise<XScrapedData | null> {
    try {
      const raw = await fs.readFile(
        path.join(this.outputDir, 'x-data.json'),
        'utf-8'
      );
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  private async saveResult(result: QueryGeneratorResult): Promise<void> {
    await fs.mkdir(this.outputDir, { recursive: true });
    await fs.writeFile(
      path.join(this.outputDir, 'shodan-queries.json'),
      JSON.stringify(result, null, 2)
    );
    console.log(`[QueryGen] Saved ${result.queries.length} queries to shodan-queries.json`);
  }

  private emptyResult(): QueryGeneratorResult {
    return {
      timestamp: new Date().toISOString(),
      model: QUERY_MODEL,
      sourcePostsAnalyzed: 0,
      queries: [{
        query: 'port:22,3389,445',
        rationale: 'Default query (no social intel available)',
        priority: 'low',
        tags: ['default']
      }],
      extractedIndicators: {
        cves: [],
        ports: [],
        services: [],
        countries: [],
        malwareFamilies: [],
        threatActors: []
      },
      rawAnalysis: ''
    };
  }
}

export default QueryGenerator;
