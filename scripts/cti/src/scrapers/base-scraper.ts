/**
 * Base Scraper - Abstract class for all data scrapers
 * Proporciona funcionalidad común: cache, rate limiting, logging
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import {
  DataSource,
  BaseScrapedData,
  CacheMetadata,
  ScraperConfig,
  ScraperResult
} from '../types/index.js';

export abstract class BaseScraper<T extends BaseScrapedData> {
  protected config: ScraperConfig;
  protected cacheDir: string;
  protected lastRequestTime: number = 0;

  constructor(config: ScraperConfig) {
    this.config = config;
    this.cacheDir = process.env.CTI_CACHE_DIR || './DATA/cti-cache';
  }

  /**
   * Método abstracto que cada scraper debe implementar
   */
  protected abstract scrape(): Promise<T>;

  /**
   * Nombre único del scraper para identificación
   */
  protected abstract get scraperName(): string;

  /**
   * Ejecuta el scraper con manejo de cache y rate limiting
   */
  async execute(): Promise<ScraperResult<T>> {
    console.log(`[${this.scraperName}] Starting execution...`);

    if (!this.config.enabled) {
      console.log(`[${this.scraperName}] Scraper disabled, skipping.`);
      return {
        success: false,
        error: 'Scraper disabled',
        fromCache: false
      };
    }

    // Check cache first
    if (this.config.cache.enabled && process.env.USE_CACHE === 'true') {
      const cached = await this.loadFromCache();
      if (cached) {
        console.log(`[${this.scraperName}] Using cached data.`);
        return {
          success: true,
          data: cached,
          fromCache: true
        };
      }
    }

    // Apply rate limiting
    await this.applyRateLimit();

    try {
      const data = await this.scrape();
      
      // Save to cache
      if (this.config.cache.enabled) {
        await this.saveToCache(data);
      }

      console.log(`[${this.scraperName}] Execution completed successfully.`);
      return {
        success: true,
        data,
        fromCache: false
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`[${this.scraperName}] Execution failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        fromCache: false
      };
    }
  }

  /**
   * Aplica rate limiting entre requests
   */
  protected async applyRateLimit(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;
    const minInterval = 60000 / this.config.rateLimit.requestsPerMinute;

    if (elapsed < minInterval) {
      const waitTime = minInterval - elapsed + this.config.rateLimit.cooldownMs;
      console.log(`[${this.scraperName}] Rate limiting: waiting ${waitTime}ms`);
      await this.sleep(waitTime);
    }

    this.lastRequestTime = Date.now();
  }

  /**
   * Genera la ruta del archivo de cache
   */
  protected getCachePath(): string {
    return path.join(this.cacheDir, `${this.config.source}-cache.json`);
  }

  /**
   * Genera la ruta del archivo de metadata de cache
   */
  protected getCacheMetadataPath(): string {
    return path.join(this.cacheDir, `${this.config.source}-cache.meta.json`);
  }

  /**
   * Carga datos del cache si son válidos
   */
  protected async loadFromCache(): Promise<T | null> {
    try {
      const metadataPath = this.getCacheMetadataPath();
      const cachePath = this.getCachePath();

      // Check if cache files exist
      await fs.access(metadataPath);
      await fs.access(cachePath);

      // Load and validate metadata
      const metadataRaw = await fs.readFile(metadataPath, 'utf-8');
      const metadata: CacheMetadata = JSON.parse(metadataRaw);

      // Check expiration
      const ttlHours = Number(process.env.CACHE_TTL_HOURS) || this.config.cache.ttlHours;
      const expiresAt = new Date(metadata.createdAt);
      expiresAt.setHours(expiresAt.getHours() + ttlHours);

      if (new Date() > expiresAt) {
        console.log(`[${this.scraperName}] Cache expired.`);
        return null;
      }

      // Load cached data
      const dataRaw = await fs.readFile(cachePath, 'utf-8');
      
      // Verify checksum
      const checksum = this.generateChecksum(dataRaw);
      if (checksum !== metadata.checksum) {
        console.log(`[${this.scraperName}] Cache checksum mismatch.`);
        return null;
      }

      return JSON.parse(dataRaw) as T;
    } catch {
      console.log(`[${this.scraperName}] No valid cache found.`);
      return null;
    }
  }

  /**
   * Guarda datos en el cache
   */
  protected async saveToCache(data: T): Promise<void> {
    try {
      // Ensure cache directory exists
      await fs.mkdir(this.cacheDir, { recursive: true });

      const dataString = JSON.stringify(data, null, 2);
      const checksum = this.generateChecksum(dataString);

      const metadata: CacheMetadata = {
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + this.config.cache.ttlHours * 3600000).toISOString(),
        source: this.config.source,
        checksum
      };

      await fs.writeFile(this.getCachePath(), dataString, 'utf-8');
      await fs.writeFile(this.getCacheMetadataPath(), JSON.stringify(metadata, null, 2), 'utf-8');

      console.log(`[${this.scraperName}] Data cached successfully.`);
    } catch (error) {
      console.error(`[${this.scraperName}] Failed to cache data:`, error);
    }
  }

  /**
   * Genera checksum MD5 de un string
   */
  protected generateChecksum(data: string): string {
    return crypto.createHash('md5').update(data).digest('hex');
  }

  /**
   * Helper para sleep/delay
   */
  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Genera un ID único para items
   */
  protected generateId(prefix: string = ''): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
  }
}

/**
 * Registrar nuevos scrapers en este factory
 * Permite agregar nuevas fuentes de datos fácilmente
 */
export type ScraperFactory = {
  [key in DataSource]?: new (config: ScraperConfig) => BaseScraper<BaseScrapedData>;
};

export const scraperRegistry: ScraperFactory = {};

/**
 * Decorador/helper para registrar scrapers
 */
export function registerScraper(source: DataSource, scraperClass: new (config: ScraperConfig) => BaseScraper<BaseScrapedData>): void {
  scraperRegistry[source] = scraperClass;
  console.log(`[Registry] Registered scraper for ${source}`);
}
