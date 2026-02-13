/**
 * Data Processor - Pre-procesa y normaliza datos de todas las fuentes
 * Extrae indicadores, categoriza amenazas y prepara datos para el LLM
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import {
  DataSource,
  ThreatSeverity,
  ThreatCategory,
  ProcessedData,
  ProcessedThreat,
  ThreatIndicator,
  XScrapedData,
  XPost,
  ShodanScrapedData,
  ShodanHost,
  ShodanExploit
} from '../types/index.js';

// Patrones para extracción de IOCs (Indicators of Compromise)
const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
  cve: /CVE-\d{4}-\d{4,}/gi,
  md5: /\b[a-f0-9]{32}\b/gi,
  sha256: /\b[a-f0-9]{64}\b/gi,
  url: /https?:\/\/[^\s<>\[\]"']+/gi
};

// Keywords para categorización de amenazas
const THREAT_KEYWORDS: Record<ThreatCategory, string[]> = {
  [ThreatCategory.MALWARE]: ['malware', 'virus', 'trojan', 'worm', 'backdoor', 'rat', 'infostealer'],
  [ThreatCategory.RANSOMWARE]: ['ransomware', 'ransom', 'lockbit', 'blackcat', 'alphv', 'conti', 'encryption'],
  [ThreatCategory.PHISHING]: ['phishing', 'spearphishing', 'social engineering', 'credential', 'bec'],
  [ThreatCategory.DDoS]: ['ddos', 'denial of service', 'botnet', 'amplification', 'flood'],
  [ThreatCategory.APT]: ['apt', 'nation-state', 'threat actor', 'campaign', 'lazarus', 'cozy bear'],
  [ThreatCategory.VULNERABILITY]: ['cve', 'vulnerability', 'exploit', 'zero-day', '0day', 'rce', 'sqli'],
  [ThreatCategory.DATA_BREACH]: ['breach', 'leak', 'exposed', 'database', 'dump', 'stolen'],
  [ThreatCategory.SUPPLY_CHAIN]: ['supply chain', 'solarwinds', 'npm', 'pypi', 'dependency'],
  [ThreatCategory.SOCIAL_ENGINEERING]: ['social engineering', 'impersonation', 'vishing', 'smishing'],
  [ThreatCategory.INFRASTRUCTURE]: ['infrastructure', 'c2', 'command and control', 'server', 'hosting'],
  [ThreatCategory.OTHER]: []
};

// Keywords para determinar severidad
const SEVERITY_KEYWORDS: Record<ThreatSeverity, string[]> = {
  [ThreatSeverity.CRITICAL]: ['critical', 'emergency', 'active exploitation', 'zero-day', '0day', 'urgent'],
  [ThreatSeverity.HIGH]: ['high', 'severe', 'dangerous', 'widespread', 'active'],
  [ThreatSeverity.MEDIUM]: ['medium', 'moderate', 'potential', 'risk'],
  [ThreatSeverity.LOW]: ['low', 'minor', 'limited'],
  [ThreatSeverity.INFO]: ['info', 'informational', 'fyi', 'awareness']
};

export class DataProcessor {
  private outputDir: string;
  private indicators: Map<string, ThreatIndicator> = new Map();
  private threats: ProcessedThreat[] = [];

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Procesa todos los datos de las fuentes disponibles
   */
  async process(): Promise<ProcessedData> {
    console.log('[DataProcessor] Starting data processing...');

    // Cargar datos de cada fuente
    const xData = await this.loadSourceData<XScrapedData>('x-data.json');
    const shodanData = await this.loadSourceData<ShodanScrapedData>('shodan-data.json');

    // Procesar cada fuente
    if (xData) {
      await this.processXData(xData);
    }

    if (shodanData) {
      await this.processShodanData(shodanData);
    }

    // Consolidar y generar resumen
    const processedData = this.consolidate();

    // Guardar datos procesados
    await this.saveProcessedData(processedData);

    console.log(`[DataProcessor] Processed ${processedData.threats.length} threats and ${processedData.indicators.length} indicators`);
    
    return processedData;
  }

  /**
   * Carga datos de una fuente específica
   */
  private async loadSourceData<T>(filename: string): Promise<T | null> {
    try {
      const filePath = path.join(this.outputDir, filename);
      const data = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      console.log(`[DataProcessor] No data found for ${filename}`);
      return null;
    }
  }

  /**
   * Procesa datos de X.com
   */
  private async processXData(data: XScrapedData): Promise<void> {
    console.log(`[DataProcessor] Processing ${data.posts.length} X.com posts...`);

    for (const post of data.posts) {
      // Extraer indicadores del texto
      const extractedIndicators = this.extractIndicators(post.text, DataSource.X_COM);
      
      // Determinar categoría y severidad
      const category = this.categorize(post.text);
      const severity = this.determineSeverity(post.text, post.metrics);

      // Si el post tiene contenido CTI relevante
      if (category !== ThreatCategory.OTHER || extractedIndicators.length > 0) {
        const threat: ProcessedThreat = {
          id: this.generateId('threat'),
          title: this.generateTitle(post.text),
          description: post.text,
          category,
          severity,
          indicators: extractedIndicators,
          sources: [DataSource.X_COM],
          socialContext: {
            sentiment: this.analyzeSentiment(post.text),
            engagement: post.metrics.likes + post.metrics.reposts + post.metrics.replies,
            keyPhrases: this.extractKeyPhrases(post.text),
            influencers: post.metrics.likes > 100 ? [post.author.username] : []
          },
          timestamp: post.timestamp,
          confidence: this.calculateConfidence(extractedIndicators, post.metrics)
        };

        this.threats.push(threat);

        // Agregar indicadores al mapa
        for (const indicator of extractedIndicators) {
          this.mergeIndicator(indicator);
        }
      }
    }
  }

  /**
   * Procesa datos de Shodan
   */
  private async processShodanData(data: ShodanScrapedData): Promise<void> {
    console.log(`[DataProcessor] Processing ${data.hosts.length} Shodan hosts and ${data.exploits.length} exploits...`);

    // Procesar hosts vulnerables
    const vulnerableHosts = data.hosts.filter(h => h.vulns && h.vulns.length > 0);
    
    if (vulnerableHosts.length > 0) {
      const hostIndicators: ThreatIndicator[] = [];

      for (const host of vulnerableHosts) {
        // Crear indicador IP
        const ipIndicator: ThreatIndicator = {
          id: this.generateId('ioc'),
          type: 'ip',
          value: host.ip,
          confidence: 70,
          sources: [DataSource.SHODAN],
          firstSeen: host.lastUpdate,
          lastSeen: host.lastUpdate,
          context: `Host vulnerable (${host.vulns?.join(', ')})`
        };
        hostIndicators.push(ipIndicator);
        this.mergeIndicator(ipIndicator);

        // Crear indicadores CVE
        for (const vuln of host.vulns || []) {
          const cveIndicator: ThreatIndicator = {
            id: this.generateId('ioc'),
            type: 'cve',
            value: vuln,
            confidence: 85,
            sources: [DataSource.SHODAN],
            firstSeen: host.lastUpdate,
            lastSeen: host.lastUpdate,
            context: `Found in ${host.product || 'unknown product'} at ${host.ip}`
          };
          this.mergeIndicator(cveIndicator);
        }
      }

      // Crear threat para hosts vulnerables
      const threat: ProcessedThreat = {
        id: this.generateId('threat'),
        title: `Vulnerable Infrastructure Detected (${vulnerableHosts.length} hosts)`,
        description: `Shodan scan detected ${vulnerableHosts.length} hosts with known vulnerabilities. Top affected: ${vulnerableHosts.slice(0, 5).map(h => h.product || 'unknown').join(', ')}`,
        category: ThreatCategory.VULNERABILITY,
        severity: this.calculateShodanSeverity(vulnerableHosts),
        indicators: hostIndicators,
        sources: [DataSource.SHODAN],
        technicalContext: {
          affectedSystems: [...new Set(vulnerableHosts.map(h => h.product || 'unknown'))],
          attackVectors: [...new Set(vulnerableHosts.flatMap(h => h.vulns || []))],
          mitigations: ['Apply security patches', 'Update vulnerable software', 'Implement network segmentation']
        },
        timestamp: data.timestamp,
        confidence: 80
      };

      this.threats.push(threat);
    }

    // Procesar exploits
    for (const exploit of data.exploits) {
      if (exploit.cve) {
        const cveIndicator: ThreatIndicator = {
          id: this.generateId('ioc'),
          type: 'cve',
          value: exploit.cve,
          confidence: 90,
          sources: [DataSource.SHODAN],
          firstSeen: data.timestamp,
          lastSeen: data.timestamp,
          context: exploit.description
        };
        this.mergeIndicator(cveIndicator);
      }
    }
  }

  /**
   * Extrae indicadores de un texto
   */
  private extractIndicators(text: string, source: DataSource): ThreatIndicator[] {
    const indicators: ThreatIndicator[] = [];
    const now = new Date().toISOString();

    // Extraer IPs
    const ips = text.match(IOC_PATTERNS.ipv4) || [];
    for (const ip of ips) {
      if (!this.isPrivateIP(ip)) {
        indicators.push({
          id: this.generateId('ioc'),
          type: 'ip',
          value: ip,
          confidence: 60,
          sources: [source],
          firstSeen: now,
          lastSeen: now
        });
      }
    }

    // Extraer CVEs
    const cves = text.match(IOC_PATTERNS.cve) || [];
    for (const cve of cves) {
      indicators.push({
        id: this.generateId('ioc'),
        type: 'cve',
        value: cve.toUpperCase(),
        confidence: 90,
        sources: [source],
        firstSeen: now,
        lastSeen: now
      });
    }

    // Extraer hashes
    const md5s = text.match(IOC_PATTERNS.md5) || [];
    for (const hash of md5s) {
      indicators.push({
        id: this.generateId('ioc'),
        type: 'hash',
        value: hash.toLowerCase(),
        confidence: 75,
        sources: [source],
        firstSeen: now,
        lastSeen: now
      });
    }

    const sha256s = text.match(IOC_PATTERNS.sha256) || [];
    for (const hash of sha256s) {
      indicators.push({
        id: this.generateId('ioc'),
        type: 'hash',
        value: hash.toLowerCase(),
        confidence: 80,
        sources: [source],
        firstSeen: now,
        lastSeen: now
      });
    }

    return indicators;
  }

  /**
   * Determina la categoría de amenaza
   */
  private categorize(text: string): ThreatCategory {
    const lowerText = text.toLowerCase();
    let maxScore = 0;
    let bestCategory = ThreatCategory.OTHER;

    for (const [category, keywords] of Object.entries(THREAT_KEYWORDS)) {
      const score = keywords.filter(kw => lowerText.includes(kw)).length;
      if (score > maxScore) {
        maxScore = score;
        bestCategory = category as ThreatCategory;
      }
    }

    return bestCategory;
  }

  /**
   * Determina la severidad de una amenaza
   */
  private determineSeverity(text: string, metrics?: { likes: number; reposts: number; replies: number }): ThreatSeverity {
    const lowerText = text.toLowerCase();

    // Verificar keywords de severidad
    for (const [severity, keywords] of Object.entries(SEVERITY_KEYWORDS)) {
      if (keywords.some(kw => lowerText.includes(kw))) {
        return severity as ThreatSeverity;
      }
    }

    // Si tiene muchas interacciones, probablemente es importante
    if (metrics) {
      const totalEngagement = metrics.likes + metrics.reposts + metrics.replies;
      if (totalEngagement > 1000) return ThreatSeverity.HIGH;
      if (totalEngagement > 100) return ThreatSeverity.MEDIUM;
    }

    return ThreatSeverity.LOW;
  }

  /**
   * Calcula severidad basada en hosts de Shodan
   */
  private calculateShodanSeverity(hosts: ShodanHost[]): ThreatSeverity {
    const criticalVulns = hosts.filter(h => 
      h.vulns?.some(v => v.includes('CVE-2024') || v.includes('CVE-2023'))
    ).length;

    if (criticalVulns > 10) return ThreatSeverity.CRITICAL;
    if (criticalVulns > 5) return ThreatSeverity.HIGH;
    if (criticalVulns > 0) return ThreatSeverity.MEDIUM;
    return ThreatSeverity.LOW;
  }

  /**
   * Genera un título corto para una amenaza
   */
  private generateTitle(text: string): string {
    // Buscar CVEs primero
    const cves = text.match(IOC_PATTERNS.cve);
    if (cves && cves.length > 0) {
      return `Threat: ${cves[0]}`;
    }

    // Usar primeras palabras relevantes
    const words = text.split(/\s+/).filter(w => w.length > 3);
    return words.slice(0, 6).join(' ') + '...';
  }

  /**
   * Analiza el sentimiento de un texto
   */
  private analyzeSentiment(text: string): 'positive' | 'negative' | 'neutral' {
    const lowerText = text.toLowerCase();
    
    const negativeWords = ['attack', 'breach', 'hack', 'malware', 'threat', 'vulnerable', 'danger', 'critical', 'urgent'];
    const positiveWords = ['patched', 'fixed', 'secured', 'protected', 'mitigated', 'resolved'];

    const negScore = negativeWords.filter(w => lowerText.includes(w)).length;
    const posScore = positiveWords.filter(w => lowerText.includes(w)).length;

    if (negScore > posScore + 1) return 'negative';
    if (posScore > negScore + 1) return 'positive';
    return 'neutral';
  }

  /**
   * Extrae frases clave de un texto
   */
  private extractKeyPhrases(text: string): string[] {
    const phrases: string[] = [];
    
    // Extraer hashtags
    const hashtags = text.match(/#\w+/g) || [];
    phrases.push(...hashtags);

    // Extraer CVEs
    const cves = text.match(IOC_PATTERNS.cve) || [];
    phrases.push(...cves);

    return [...new Set(phrases)].slice(0, 10);
  }

  /**
   * Calcula confianza basada en indicadores y métricas
   */
  private calculateConfidence(indicators: ThreatIndicator[], metrics?: { likes: number; reposts: number; replies: number }): number {
    let confidence = 30; // Base

    // Más indicadores = más confianza
    confidence += Math.min(indicators.length * 10, 30);

    // CVEs son muy confiables
    if (indicators.some(i => i.type === 'cve')) {
      confidence += 20;
    }

    // Alto engagement aumenta confianza
    if (metrics) {
      const engagement = metrics.likes + metrics.reposts;
      if (engagement > 100) confidence += 10;
      if (engagement > 1000) confidence += 10;
    }

    return Math.min(confidence, 100);
  }

  /**
   * Verifica si una IP es privada
   */
  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
  }

  /**
   * Mezcla indicadores detectados con existentes
   */
  private mergeIndicator(indicator: ThreatIndicator): void {
    const key = `${indicator.type}:${indicator.value}`;
    const existing = this.indicators.get(key);

    if (existing) {
      // Actualizar indicador existente
      existing.lastSeen = indicator.lastSeen;
      existing.confidence = Math.max(existing.confidence, indicator.confidence);
      existing.sources = [...new Set([...existing.sources, ...indicator.sources])];
    } else {
      this.indicators.set(key, indicator);
    }
  }

  /**
   * Consolida todos los datos procesados
   */
  private consolidate(): ProcessedData {
    const indicators = Array.from(this.indicators.values());
    
    // Ordenar amenazas por severidad y confianza
    const sortedThreats = this.threats.sort((a, b) => {
      const severityOrder = [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM, ThreatSeverity.LOW, ThreatSeverity.INFO];
      const aIdx = severityOrder.indexOf(a.severity);
      const bIdx = severityOrder.indexOf(b.severity);
      if (aIdx !== bIdx) return aIdx - bIdx;
      return b.confidence - a.confidence;
    });

    // Generar resumen
    const summary = {
      totalThreats: sortedThreats.length,
      bySeverity: this.countBy(sortedThreats, 'severity') as Record<ThreatSeverity, number>,
      byCategory: this.countBy(sortedThreats, 'category') as Record<ThreatCategory, number>,
      bySource: this.countBySource(sortedThreats)
    };

    return {
      threats: sortedThreats,
      indicators,
      summary,
      processingTimestamp: new Date().toISOString()
    };
  }

  /**
   * Cuenta elementos por un campo
   */
  private countBy(items: ProcessedThreat[], field: 'severity' | 'category'): Record<string, number> {
    return items.reduce((acc, item) => {
      const value = item[field];
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  /**
   * Cuenta amenazas por fuente
   */
  private countBySource(threats: ProcessedThreat[]): Record<DataSource, number> {
    const counts: Record<string, number> = {};
    for (const threat of threats) {
      for (const source of threat.sources) {
        counts[source] = (counts[source] || 0) + 1;
      }
    }
    return counts as Record<DataSource, number>;
  }

  /**
   * Guarda datos procesados
   */
  private async saveProcessedData(data: ProcessedData): Promise<void> {
    await fs.mkdir(this.outputDir, { recursive: true });
    await fs.writeFile(
      path.join(this.outputDir, 'processed-data.json'),
      JSON.stringify(data, null, 2)
    );
  }

  /**
   * Genera ID único
   */
  private generateId(prefix: string): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `${prefix}_${timestamp}_${random}`;
  }
}

export default DataProcessor;
