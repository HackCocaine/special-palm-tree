/**
 * Shodan Scraper - Obtiene datos de amenazas desde Shodan
 * Búsquedas de hosts vulnerables, exploits y tendencias
 */

import { BaseScraper, registerScraper } from './base-scraper.js';
import {
  DataSource,
  ShodanScrapedData,
  ShodanHost,
  ShodanExploit,
  ScraperConfig
} from '../types/index.js';

// Query única optimizada - máximo valor con 1 request
// Combina CVEs recientes + servicios expuestos críticos
const CTI_QUERY = 'vuln:CVE-2024 vuln:CVE-2025';

interface ShodanAPIHost {
  ip_str: string;
  port: number;
  hostnames?: string[];
  org?: string;
  asn?: string;
  isp?: string;
  location?: {
    country_code?: string;
    city?: string;
  };
  os?: string;
  product?: string;
  version?: string;
  vulns?: string[];
  tags?: string[];
  timestamp?: string;
}

interface ShodanAPISearchResult {
  matches: ShodanAPIHost[];
  total: number;
}

interface ShodanAPIExploit {
  _id: string;
  cve?: string[];
  description: string;
  platform?: string;
  type?: string;
  source: string;
}

interface ShodanAPIExploitsResult {
  matches: ShodanAPIExploit[];
  total: number;
}

export class ShodanScraper extends BaseScraper<ShodanScrapedData> {
  private apiKey: string;
  private baseUrl = 'https://api.shodan.io';

  constructor(config: ScraperConfig) {
    super(config);
    this.apiKey = process.env.SHODAN_API_KEY || '';
    
    if (!this.apiKey) {
      console.warn('[ShodanScraper] No API key provided. Some features may be limited.');
    }
  }

  protected get scraperName(): string {
    return 'ShodanScraper';
  }

  protected async scrape(): Promise<ShodanScrapedData> {
    const hosts: ShodanHost[] = [];
    const exploits: ShodanExploit[] = [];
    const query = CTI_QUERY;

    console.log(`[ShodanScraper] Single optimized query: ${query}`);

    // Una sola búsqueda optimizada
    try {
      const searchResults = await this.searchHosts(query);
      hosts.push(...searchResults);
      console.log(`[ShodanScraper] Found ${searchResults.length} vulnerable hosts`);
    } catch (error) {
      console.error(`[ShodanScraper] Search failed:`, error);
    }

    // Generar exploits desde CVEs encontrados (sin request adicional)
    const cveSet = new Set<string>();
    hosts.forEach(h => h.vulns?.forEach(v => cveSet.add(v)));
    const exploitList = Array.from(cveSet).slice(0, 10).map(cve => ({
      id: this.generateId('exp'),
      cve,
      description: `Vulnerability ${cve} detected in scan`,
      source: 'shodan-scan'
    }));
    exploits.push(...exploitList);

    return {
      source: DataSource.SHODAN,
      timestamp: new Date().toISOString(),
      rawData: { hosts, exploits },
      hosts: this.deduplicateHosts(hosts),
      exploits,
      query
    };
  }

  /**
   * Busca hosts en Shodan
   */
  private async searchHosts(query: string): Promise<ShodanHost[]> {
    const url = `${this.baseUrl}/shodan/host/search?key=${this.apiKey}&query=${encodeURIComponent(query)}&limit=100`;
    
    const response = await fetch(url);
    
    if (!response.ok) {
      if (response.status === 401) {
        throw new Error('Invalid Shodan API key');
      }
      if (response.status === 429) {
        throw new Error('Rate limit exceeded');
      }
      throw new Error(`Shodan API error: ${response.status}`);
    }

    const data = await response.json() as ShodanAPISearchResult;
    
    return data.matches.map((match): ShodanHost => ({
      ip: match.ip_str,
      port: match.port,
      hostnames: match.hostnames || [],
      org: match.org,
      asn: match.asn,
      isp: match.isp,
      country: match.location?.country_code || 'Unknown',
      city: match.location?.city,
      os: match.os,
      product: match.product,
      version: match.version,
      vulns: match.vulns,
      tags: match.tags,
      lastUpdate: match.timestamp || new Date().toISOString()
    }));
  }

  /**
   * Busca exploits en Shodan
   */
  private async searchExploits(query: string): Promise<ShodanExploit[]> {
    const url = `${this.baseUrl}/api-info?key=${this.apiKey}`;
    
    // Primero verificar créditos de API
    const infoResponse = await fetch(url);
    if (!infoResponse.ok) {
      throw new Error('Failed to check API credits');
    }

    const exploitsUrl = `https://exploits.shodan.io/api/search?query=${encodeURIComponent(query)}&key=${this.apiKey}`;
    
    const response = await fetch(exploitsUrl);
    
    if (!response.ok) {
      // Exploits API puede no estar disponible en todos los planes
      console.warn('[ShodanScraper] Exploits API not available, using fallback');
      return this.generateSampleExploits();
    }

    const data = await response.json() as ShodanAPIExploitsResult;
    
    return data.matches.slice(0, 20).map((exploit): ShodanExploit => ({
      id: exploit._id,
      cve: exploit.cve?.[0],
      description: exploit.description.substring(0, 500),
      platform: exploit.platform,
      type: exploit.type,
      source: exploit.source
    }));
  }

  /**
   * Genera exploits de muestra cuando la API no está disponible
   */
  private generateSampleExploits(): ShodanExploit[] {
    const recentCVEs = [
      { cve: 'CVE-2024-21887', desc: 'Ivanti Connect Secure Command Injection' },
      { cve: 'CVE-2024-1709', desc: 'ConnectWise ScreenConnect Authentication Bypass' },
      { cve: 'CVE-2024-27198', desc: 'TeamCity Authentication Bypass' },
      { cve: 'CVE-2024-3400', desc: 'Palo Alto PAN-OS Command Injection' },
      { cve: 'CVE-2024-4577', desc: 'PHP CGI Argument Injection' }
    ];

    return recentCVEs.map((item, idx) => ({
      id: this.generateId('exp'),
      cve: item.cve,
      description: item.desc,
      platform: 'Multiple',
      type: 'remote',
      source: 'shodan-fallback'
    }));
  }

  /**
   * Elimina hosts duplicados por IP:Port
   */
  private deduplicateHosts(hosts: ShodanHost[]): ShodanHost[] {
    const seen = new Set<string>();
    return hosts.filter(host => {
      const key = `${host.ip}:${host.port}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

// Registrar el scraper
registerScraper(DataSource.SHODAN, ShodanScraper);

export default ShodanScraper;
