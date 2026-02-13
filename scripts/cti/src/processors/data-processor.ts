/**
 * Data Processor - Pre-procesa y normaliza datos de todas las fuentes
 * Extrae indicadores, categoriza amenazas y prepara datos para el LLM
 * Implementa correlación temporal cross-source (infraestructura vs social)
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
  ShodanExploit,
  CorrelationSignal,
  CorrelatedData,
  TemporalCorrelation,
  EvidenceLink
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

// Patrones para normalizar texto scrapeado
const TEXT_CLEANUP_PATTERNS = {
  emojis: /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F000}-\u{1F02F}\u{1F0A0}-\u{1F0FF}]/gu,
  longUrls: /https?:\/\/([^\s\/]+)[^\s]*/g,
  mentions: /@[\w]+/g,
  hashtags: /#[\w]+/g,
  multipleSpaces: /\s{2,}/g,
  controlChars: /[\x00-\x1F\x7F]/g,
  rtPrefix: /^RT\s+/i,
  threadMarkers: /\(\d+\/\d+\)|\d+\/\d+|🧵/g
};

// ==================== CORRELATION MAPPINGS ====================

/**
 * Mapeo de puertos a señales correlacionables
 * Estos servicios son comúnmente discutidos en social cuando hay scanning/exploitation
 */
const PORT_TO_SIGNAL: Record<number, { id: string; label: string; keywords: string[] }> = {
  22: { id: 'ssh', label: 'SSH', keywords: ['ssh', 'openssh', 'secure shell', 'ssh brute', 'ssh scan'] },
  23: { id: 'telnet', label: 'Telnet', keywords: ['telnet', 'telnet scan'] },
  25: { id: 'smtp', label: 'SMTP', keywords: ['smtp', 'mail server', 'email server'] },
  80: { id: 'http', label: 'HTTP', keywords: ['http', 'web server', 'apache', 'nginx'] },
  443: { id: 'https', label: 'HTTPS', keywords: ['https', 'ssl', 'tls', 'certificate'] },
  445: { id: 'smb', label: 'SMB', keywords: ['smb', 'samba', 'windows share', 'eternalblue', 'wannacry'] },
  1433: { id: 'mssql', label: 'MSSQL', keywords: ['mssql', 'sql server', 'microsoft sql'] },
  3306: { id: 'mysql', label: 'MySQL', keywords: ['mysql', 'mariadb', 'database'] },
  3389: { id: 'rdp', label: 'RDP', keywords: ['rdp', 'remote desktop', 'bluekeep', 'windows rdp'] },
  5432: { id: 'postgres', label: 'PostgreSQL', keywords: ['postgres', 'postgresql', 'pgsql'] },
  5900: { id: 'vnc', label: 'VNC', keywords: ['vnc', 'remote access', 'vnc scan'] },
  6379: { id: 'redis', label: 'Redis', keywords: ['redis', 'redis scan', 'redis exposed'] },
  8080: { id: 'http-alt', label: 'HTTP-Alt', keywords: ['proxy', 'http proxy', 'web proxy'] },
  27017: { id: 'mongodb', label: 'MongoDB', keywords: ['mongodb', 'mongo', 'nosql'] }
};

/**
 * Keywords de amenazas que pueden aparecer en social y correlacionarse con infra
 */
const THREAT_SIGNALS: Array<{ id: string; label: string; keywords: string[] }> = [
  { id: 'scanning', label: 'Scanning Activity', keywords: ['scan', 'scanning', 'port scan', 'mass scan', 'shodan'] },
  { id: 'bruteforce', label: 'Brute Force', keywords: ['brute force', 'brute-force', 'password spray', 'credential stuffing'] },
  { id: 'ransomware', label: 'Ransomware', keywords: ['ransomware', 'ransom', 'lockbit', 'blackcat', 'encrypt'] },
  { id: 'botnet', label: 'Botnet', keywords: ['botnet', 'mirai', 'ddos', 'zombie', 'c2'] },
  { id: 'exploit', label: 'Exploitation', keywords: ['exploit', 'rce', 'remote code', 'zero-day', '0day'] }
];

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

// ==================== DATA PROCESSOR CLASS ====================

export class DataProcessor {
  private outputDir: string;
  private indicators: Map<string, ThreatIndicator> = new Map();
  private threats: ProcessedThreat[] = [];
  
  // Correlation tracking
  private signalTracker: Map<string, {
    infraData: { count: number; firstSeen: string; lastSeen: string; samples: string[] };
    socialData: { count: number; firstSeen: string; lastSeen: string; samples: string[] };
  }> = new Map();

  constructor() {
    this.outputDir = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
  }

  /**
   * Procesa todos los datos de las fuentes disponibles
   * Implementa correlación temporal cross-source
   */
  async process(): Promise<ProcessedData> {
    console.log('[DataProcessor] Starting data processing with correlation...');

    // Cargar datos de cada fuente
    const xData = await this.loadSourceData<XScrapedData>('x-data.json');
    const shodanData = await this.loadSourceData<ShodanScrapedData>('shodan-data.json');

    // Procesar infraestructura primero (Shodan) para extraer señales
    if (shodanData) {
      await this.processShodanData(shodanData);
      this.extractInfraSignals(shodanData);
    }

    // Procesar social (X.com) y extraer señales
    if (xData) {
      await this.processXData(xData);
      this.extractSocialSignals(xData);
    }

    // Generar correlación temporal
    const correlation = this.buildCorrelation();
    console.log(`[DataProcessor] Correlation: ${correlation.summary.correlatedSignals} cross-source signals, pattern: ${correlation.dominantPattern}`);

    // Consolidar y generar resumen
    const processedData = this.consolidate(correlation);

    // Guardar datos procesados
    await this.saveProcessedData(processedData);

    console.log(`[DataProcessor] Processed ${processedData.threats.length} threats, ${processedData.indicators.length} indicators, ${correlation.signals.length} correlation signals`);
    
    return processedData;
  }

  /**
   * Extrae señales de infraestructura (puertos, servicios) de Shodan
   */
  private extractInfraSignals(data: ShodanScrapedData): void {
    if (!data.hosts || data.hosts.length === 0) return;

    // Agrupar por puerto/servicio
    const portCounts = new Map<number, { count: number; firstSeen: string; lastSeen: string; ips: string[] }>();
    
    for (const host of data.hosts) {
      const existing = portCounts.get(host.port) || { 
        count: 0, 
        firstSeen: host.lastUpdate, 
        lastSeen: host.lastUpdate,
        ips: [] 
      };
      
      existing.count++;
      if (host.lastUpdate < existing.firstSeen) existing.firstSeen = host.lastUpdate;
      if (host.lastUpdate > existing.lastSeen) existing.lastSeen = host.lastUpdate;
      if (existing.ips.length < 5) existing.ips.push(host.ip);
      
      portCounts.set(host.port, existing);
    }

    // Convertir a señales
    for (const [port, stats] of portCounts) {
      const signalDef = PORT_TO_SIGNAL[port];
      if (signalDef) {
        this.trackSignal(signalDef.id, 'infra', {
          count: stats.count,
          firstSeen: stats.firstSeen,
          lastSeen: stats.lastSeen,
          samples: stats.ips
        });
      }
    }

    console.log(`[DataProcessor] Extracted ${portCounts.size} infrastructure signals from Shodan`);
  }

  /**
   * Extrae señales sociales (keywords, topics) de X.com
   */
  private extractSocialSignals(data: XScrapedData): void {
    if (!data.posts || data.posts.length === 0) return;

    const signalMatches = new Map<string, { count: number; firstSeen: string; lastSeen: string; excerpts: string[] }>();

    for (const post of data.posts) {
      const text = post.text.toLowerCase();
      const timestamp = post.timestamp;

      // Buscar señales de puertos/servicios
      for (const [, signalDef] of Object.entries(PORT_TO_SIGNAL)) {
        if (signalDef.keywords.some(kw => text.includes(kw))) {
          this.updateSignalMatch(signalMatches, signalDef.id, timestamp, post.text.substring(0, 100));
        }
      }

      // Buscar señales de amenazas
      for (const signalDef of THREAT_SIGNALS) {
        if (signalDef.keywords.some(kw => text.includes(kw))) {
          this.updateSignalMatch(signalMatches, signalDef.id, timestamp, post.text.substring(0, 100));
        }
      }
    }

    // Registrar señales sociales
    for (const [signalId, stats] of signalMatches) {
      this.trackSignal(signalId, 'social', {
        count: stats.count,
        firstSeen: stats.firstSeen,
        lastSeen: stats.lastSeen,
        samples: stats.excerpts
      });
    }

    console.log(`[DataProcessor] Extracted ${signalMatches.size} social signals from X.com`);
  }

  private updateSignalMatch(
    map: Map<string, { count: number; firstSeen: string; lastSeen: string; excerpts: string[] }>,
    signalId: string,
    timestamp: string,
    excerpt: string
  ): void {
    const existing = map.get(signalId) || { count: 0, firstSeen: timestamp, lastSeen: timestamp, excerpts: [] };
    existing.count++;
    if (timestamp < existing.firstSeen) existing.firstSeen = timestamp;
    if (timestamp > existing.lastSeen) existing.lastSeen = timestamp;
    if (existing.excerpts.length < 3) existing.excerpts.push(excerpt);
    map.set(signalId, existing);
  }

  private trackSignal(
    signalId: string, 
    source: 'infra' | 'social', 
    data: { count: number; firstSeen: string; lastSeen: string; samples: string[] }
  ): void {
    const existing = this.signalTracker.get(signalId) || {
      infraData: { count: 0, firstSeen: '', lastSeen: '', samples: [] },
      socialData: { count: 0, firstSeen: '', lastSeen: '', samples: [] }
    };

    if (source === 'infra') {
      existing.infraData = data;
    } else {
      existing.socialData = data;
    }

    this.signalTracker.set(signalId, existing);
  }

  /**
   * Construye datos de correlación temporal
   */
  private buildCorrelation(): CorrelatedData {
    const signals: CorrelationSignal[] = [];
    const temporalCorrelations: TemporalCorrelation[] = [];
    let infraOnly = 0, socialOnly = 0, correlated = 0;
    const deltas: number[] = [];

    for (const [signalId, tracker] of this.signalTracker) {
      const hasInfra = tracker.infraData.count > 0;
      const hasSocial = tracker.socialData.count > 0;

      // Get label
      const portSignal = Object.values(PORT_TO_SIGNAL).find(s => s.id === signalId);
      const threatSignal = THREAT_SIGNALS.find(s => s.id === signalId);
      const label = portSignal?.label || threatSignal?.label || signalId;

      const sources: CorrelationSignal['sources'] = [];
      if (hasInfra) {
        sources.push({
          source: DataSource.SHODAN,
          count: tracker.infraData.count,
          firstSeen: tracker.infraData.firstSeen,
          lastSeen: tracker.infraData.lastSeen,
          sampleData: tracker.infraData.samples
        });
      }
      if (hasSocial) {
        sources.push({
          source: DataSource.X_COM,
          count: tracker.socialData.count,
          firstSeen: tracker.socialData.firstSeen,
          lastSeen: tracker.socialData.lastSeen,
          sampleData: tracker.socialData.samples
        });
      }

      let temporalAnalysis: CorrelationSignal['temporalAnalysis'];
      
      if (hasInfra && hasSocial) {
        correlated++;
        const infraTime = new Date(tracker.infraData.firstSeen).getTime();
        const socialTime = new Date(tracker.socialData.firstSeen).getTime();
        const deltaHours = (socialTime - infraTime) / (1000 * 60 * 60);
        deltas.push(deltaHours);

        const infraPrecedesSocial = deltaHours > 0;
        const pattern = this.interpretPattern(deltaHours);

        temporalAnalysis = {
          infraPrecedesSocial,
          timeDeltaHours: Math.abs(deltaHours),
          pattern
        };

        temporalCorrelations.push({
          signal: label,
          infraTimestamp: tracker.infraData.firstSeen,
          socialTimestamp: tracker.socialData.firstSeen,
          deltahours: deltaHours,
          interpretation: this.interpretCorrelation(label, deltaHours, infraPrecedesSocial),
          evidence: {
            infra: tracker.infraData.samples.slice(0, 3).map(sample => ({
              source: DataSource.SHODAN,
              type: 'host' as const,
              title: `${label} host`,
              url: `https://www.shodan.io/host/${sample}`,
              timestamp: tracker.infraData.lastSeen,
              excerpt: `Exposed ${label} service`
            })),
            social: tracker.socialData.samples.slice(0, 3).map(excerpt => ({
              source: DataSource.X_COM,
              type: 'post' as const,
              title: `${label} discussion`,
              url: `https://x.com/search?q=${encodeURIComponent(label)}`,
              timestamp: tracker.socialData.lastSeen,
              excerpt: excerpt.substring(0, 100)
            }))
          }
        });
      } else if (hasInfra) {
        infraOnly++;
      } else {
        socialOnly++;
      }

      signals.push({
        id: signalId,
        type: portSignal ? 'port' : 'keyword',
        value: portSignal ? signalId : signalId,
        label,
        sources,
        temporalAnalysis
      });
    }

    const avgDelta = deltas.length > 0 ? deltas.reduce((a, b) => a + b, 0) / deltas.length : null;
    
    return {
      signals,
      temporalCorrelations,
      summary: {
        totalSignals: signals.length,
        infraOnlySignals: infraOnly,
        socialOnlySignals: socialOnly,
        correlatedSignals: correlated,
        avgTimeDelta: avgDelta
      },
      dominantPattern: this.determineDominantPattern(deltas)
    };
  }

  private interpretPattern(deltaHours: number): 'scanning' | 'exploitation' | 'discussion' | 'unknown' {
    if (deltaHours > 12) return 'scanning'; // Infra mucho antes → scanning early
    if (deltaHours > 0 && deltaHours <= 12) return 'exploitation'; // Infra un poco antes → posible exploit
    if (deltaHours < -6) return 'discussion'; // Social primero → discusión previa
    return 'unknown';
  }

  private interpretCorrelation(signal: string, deltaHours: number, infraFirst: boolean): string {
    const absHours = Math.abs(deltaHours).toFixed(1);
    if (infraFirst && deltaHours > 6) {
      return `Infrastructure exposure of ${signal} preceded social discussion by ~${absHours}h, suggesting early scanning activity`;
    }
    if (infraFirst && deltaHours <= 6) {
      return `${signal} activity detected in infrastructure shortly before social mentions (~${absHours}h), possible active exploitation`;
    }
    if (!infraFirst && Math.abs(deltaHours) > 6) {
      return `Social discussion of ${signal} preceded infrastructure detection by ~${absHours}h, threat awareness preceded exposure`;
    }
    return `${signal} signals appeared nearly simultaneously across sources`;
  }

  private determineDominantPattern(deltas: number[]): CorrelatedData['dominantPattern'] {
    if (deltas.length === 0) return 'insufficient-data';
    const avg = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    if (avg > 3) return 'infra-first';
    if (avg < -3) return 'social-first';
    return 'simultaneous';
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
      // Normalizar texto antes de procesar
      const normalizedText = this.normalizeScrapedText(post.text);
      
      // Extraer indicadores del texto normalizado
      const extractedIndicators = this.extractIndicators(normalizedText, DataSource.X_COM);
      
      // Determinar categoría y severidad
      const category = this.categorize(normalizedText);
      const severity = this.determineSeverity(normalizedText, post.metrics);

      // Si el post tiene contenido CTI relevante
      if (category !== ThreatCategory.OTHER || extractedIndicators.length > 0) {
        const threat: ProcessedThreat = {
          id: this.generateId('threat'),
          title: this.generateTitle(normalizedText),
          description: normalizedText,
          category,
          severity,
          indicators: extractedIndicators,
          sources: [DataSource.X_COM],
          socialContext: {
            sentiment: this.analyzeSentiment(normalizedText),
            engagement: post.metrics.likes + post.metrics.reposts + post.metrics.replies,
            keyPhrases: this.extractKeyPhrases(normalizedText),
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
   * Normaliza texto scrapeado para procesamiento LLM
   * Limpia emojis, URLs largas, menciones excesivas, etc.
   */
  private normalizeScrapedText(text: string): string {
    let normalized = text;
    
    // Remover RT prefix
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.rtPrefix, '');
    
    // Remover emojis
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.emojis, '');
    
    // Simplificar URLs largas a solo dominio
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.longUrls, (_, domain) => `[${domain}]`);
    
    // Remover thread markers
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.threadMarkers, '');
    
    // Limitar hashtags a primeros 3
    const hashtags = normalized.match(TEXT_CLEANUP_PATTERNS.hashtags) || [];
    if (hashtags.length > 3) {
      const keepHashtags = hashtags.slice(0, 3);
      normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.hashtags, (match) => {
        if (keepHashtags.includes(match)) {
          keepHashtags.splice(keepHashtags.indexOf(match), 1);
          return match;
        }
        return '';
      });
    }
    
    // Limitar menciones a primeras 2
    const mentions = normalized.match(TEXT_CLEANUP_PATTERNS.mentions) || [];
    if (mentions.length > 2) {
      const keepMentions = mentions.slice(0, 2);
      normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.mentions, (match) => {
        if (keepMentions.includes(match)) {
          keepMentions.splice(keepMentions.indexOf(match), 1);
          return match;
        }
        return '';
      });
    }
    
    // Remover caracteres de control
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.controlChars, '');
    
    // Colapsar múltiples espacios
    normalized = normalized.replace(TEXT_CLEANUP_PATTERNS.multipleSpaces, ' ');
    
    // Trim final
    return normalized.trim();
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
   * Consolida todos los datos procesados incluyendo correlación
   */
  private consolidate(correlation: CorrelatedData): ProcessedData {
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
      correlation,
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
