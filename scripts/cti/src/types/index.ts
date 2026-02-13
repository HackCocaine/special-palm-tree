/**
 * CTI Pipeline - Shared Types
 * Tipos compartidos para el sistema de agregación de inteligencia de amenazas
 */

import { z } from 'zod';

// ==================== Enums ====================

export enum ThreatSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export enum ThreatCategory {
  MALWARE = 'malware',
  RANSOMWARE = 'ransomware',
  PHISHING = 'phishing',
  DDoS = 'ddos',
  APT = 'apt',
  VULNERABILITY = 'vulnerability',
  DATA_BREACH = 'data_breach',
  SUPPLY_CHAIN = 'supply_chain',
  SOCIAL_ENGINEERING = 'social_engineering',
  INFRASTRUCTURE = 'infrastructure',
  OTHER = 'other'
}

export enum DataSource {
  X_COM = 'x.com',
  SHODAN = 'shodan',
  // Futuras fuentes
  MISP = 'misp',
  ALIENVAULT = 'alienvault',
  VIRUSTOTAL = 'virustotal',
  ABUSE_CH = 'abuse.ch'
}

// ==================== Base Interfaces ====================

export interface BaseScrapedData {
  source: DataSource;
  timestamp: string;
  rawData: unknown;
}

export interface CacheMetadata {
  createdAt: string;
  expiresAt: string;
  source: DataSource;
  checksum: string;
}

// ==================== X.com Types ====================

export interface XCookie {
  domain: string;
  expirationDate?: number;
  hostOnly: boolean;
  httpOnly: boolean;
  name: string;
  path: string;
  sameSite: string;
  secure: boolean;
  session: boolean;
  storeId: string;
  value: string;
}

export interface XCookiesFile {
  url: string;
  cookies: XCookie[];
}

export interface XPost {
  id: string;
  text: string;
  author: {
    username: string;
    displayName: string;
    verified: boolean;
  };
  metrics: {
    likes: number;
    reposts: number;
    replies: number;
    views: number;
  };
  timestamp: string;
  hashtags: string[];
  mentions: string[];
  urls: string[];
  media?: {
    type: 'image' | 'video' | 'gif';
    url: string;
  }[];
  permalink?: string; // Direct link to the original tweet for evidence
}

export interface XScrapedData extends BaseScrapedData {
  source: DataSource.X_COM;
  posts: XPost[];
  searchQuery: string;
}

// ==================== Shodan Types ====================

export interface ShodanHost {
  ip: string;
  port: number;
  hostnames: string[];
  org?: string;
  asn?: string;
  isp?: string;
  country: string;
  city?: string;
  os?: string;
  product?: string;
  version?: string;
  vulns?: string[];
  tags?: string[];
  lastUpdate: string;
}

export interface ShodanExploit {
  id: string;
  cve?: string;
  description: string;
  platform?: string;
  type?: string;
  source: string;
}

export interface ShodanScrapedData extends BaseScrapedData {
  source: DataSource.SHODAN;
  hosts: ShodanHost[];
  exploits: ShodanExploit[];
  query: string;
}

// ==================== Processed Data Types ====================

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'cve' | 'keyword';
  value: string;
  confidence: number; // 0-100
  sources: DataSource[];
  firstSeen: string;
  lastSeen: string;
  context?: string;
}

export interface ProcessedThreat {
  id: string;
  title: string;
  description: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  indicators: ThreatIndicator[];
  sources: DataSource[];
  socialContext?: {
    sentiment: 'positive' | 'negative' | 'neutral';
    engagement: number;
    keyPhrases: string[];
    influencers: string[];
  };
  technicalContext?: {
    affectedSystems: string[];
    attackVectors: string[];
    mitigations: string[];
  };
  timestamp: string;
  confidence: number;
}

export interface ProcessedData {
  threats: ProcessedThreat[];
  indicators: ThreatIndicator[];
  correlation: CorrelatedData;
  summary: {
    totalThreats: number;
    bySeverity: Record<ThreatSeverity, number>;
    byCategory: Record<ThreatCategory, number>;
    bySource: Record<DataSource, number>;
  };
  processingTimestamp: string;
}

// ==================== LLM Types ====================

export interface LLMAnalysisRequest {
  threats: ProcessedThreat[];
  contextWindow: 'short' | 'medium' | 'long';
  focusAreas?: ThreatCategory[];
}

export interface LLMInsight {
  id: string;
  type: 'trend' | 'correlation' | 'prediction' | 'recommendation';
  title: string;
  content: string;
  confidence: number;
  relatedThreats: string[]; // IDs de ProcessedThreat
  metadata?: Record<string, unknown>;
}

export interface LLMAnalysisResult {
  insights: LLMInsight[];
  executiveSummary: string;
  technicalSummary: string;
  recommendations: string[];
  trendingTopics: Array<{
    topic: string;
    growth: number; // Porcentaje
    relevance: number;
  }>;
  analysisTimestamp: string;
  model: string;
  tokenUsage: {
    input: number;
    output: number;
    total: number;
  };
}

// ==================== Dashboard Types ====================

export interface DashboardWidget {
  id: string;
  type: 'threat-feed' | 'severity-chart' | 'trend-graph' | 'map' | 'timeline' | 'insights';
  title: string;
  data: unknown;
  position: { x: number; y: number };
  size: { width: number; height: number };
}

export interface CTIDashboard {
  version: string;
  generatedAt: string;
  dataRange: {
    start: string;
    end: string;
  };
  summary: ProcessedData['summary'];
  topThreats: ProcessedThreat[];
  recentIndicators: ThreatIndicator[];
  llmAnalysis: LLMAnalysisResult;
  widgets: DashboardWidget[];
  metadata: {
    sourcesUsed: DataSource[];
    cacheHits: number;
    processingTimeMs: number;
  };
}

// ==================== Evidence & Source Links ====================

/**
 * Evidence link to original source
 * Allows users to verify and explore threat data
 */
export interface EvidenceLink {
  source: DataSource;
  type: 'post' | 'host' | 'exploit' | 'feed' | 'search';
  title: string;
  url: string;
  timestamp: string;
  excerpt?: string;
  metadata?: {
    author?: string;
    engagement?: number;
    port?: number;
    ip?: string;
  };
}

/**
 * Observable indicator with evidence
 */
export interface ObservableWithEvidence {
  type: 'ip' | 'port' | 'domain' | 'cve' | 'hash' | 'keyword';
  value: string;
  context: string;
  evidence: EvidenceLink[];
  severity: ThreatSeverity;
  confidence: number;
}

// ==================== Correlation Types ====================

/**
 * Señales correlacionables entre fuentes
 * Links infrastructure signals (Shodan) with social context (X.com)
 */
export interface CorrelationSignal {
  id: string;
  type: 'port' | 'service' | 'keyword' | 'protocol' | 'country';
  value: string;
  label: string; // Human readable: "SSH", "RDP", "ransomware"
  sources: Array<{
    source: DataSource;
    count: number;
    firstSeen: string;
    lastSeen: string;
    sampleData?: string[]; // IPs, posts excerpts, etc
    evidence?: EvidenceLink[]; // Links to original sources
  }>;
  temporalAnalysis?: {
    infraPrecedesSocial: boolean;
    timeDeltaHours: number;
    pattern: 'scanning' | 'exploitation' | 'discussion' | 'unknown';
  };
  correlationInsight?: string; // AI-generated insight about this correlation
}

export interface TemporalCorrelation {
  signal: string;
  infraTimestamp: string | null;
  socialTimestamp: string | null;
  deltahours: number | null;
  interpretation: string;
  evidence: {
    infra?: EvidenceLink[];
    social?: EvidenceLink[];
  };
}

export interface CorrelatedData {
  signals: CorrelationSignal[];
  temporalCorrelations: TemporalCorrelation[];
  summary: {
    totalSignals: number;
    infraOnlySignals: number;
    socialOnlySignals: number;
    correlatedSignals: number;
    avgTimeDelta: number | null;
  };
  dominantPattern: 'infra-first' | 'social-first' | 'simultaneous' | 'insufficient-data';
  executiveInsight?: string; // High-level correlation summary for executives
}

// ==================== Scraper Configuration ====================

export interface ScraperConfig {
  source: DataSource;
  enabled: boolean;
  rateLimit: {
    requestsPerMinute: number;
    cooldownMs: number;
  };
  cache: {
    enabled: boolean;
    ttlHours: number;
  };
  queries: string[];
}

export interface PipelineConfig {
  scrapers: ScraperConfig[];
  llm: {
    provider: 'openai' | 'anthropic';
    model: string;
    maxTokens: number;
    temperature: number;
  };
  output: {
    dashboardPath: string;
    cachePath: string;
    artifactsPath: string;
  };
}

// ==================== Zod Schemas for Validation ====================

export const ThreatIndicatorSchema = z.object({
  id: z.string(),
  type: z.enum(['ip', 'domain', 'hash', 'url', 'cve', 'keyword']),
  value: z.string(),
  confidence: z.number().min(0).max(100),
  sources: z.array(z.nativeEnum(DataSource)),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  context: z.string().optional()
});

export const ProcessedThreatSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  category: z.nativeEnum(ThreatCategory),
  severity: z.nativeEnum(ThreatSeverity),
  indicators: z.array(ThreatIndicatorSchema),
  sources: z.array(z.nativeEnum(DataSource)),
  timestamp: z.string().datetime(),
  confidence: z.number().min(0).max(100)
});

// ==================== Utility Types ====================

export type ScraperResult<T extends BaseScrapedData> = {
  success: true;
  data: T;
  fromCache: boolean;
} | {
  success: false;
  error: string;
  fromCache: false;
};

export type ProcessorResult = {
  success: true;
  data: ProcessedData;
} | {
  success: false;
  error: string;
};

export type LLMResult = {
  success: true;
  data: LLMAnalysisResult;
} | {
  success: false;
  error: string;
};
