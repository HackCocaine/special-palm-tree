/**
 * X.com (Twitter) Scraper - Obtiene inteligencia de amenazas y contexto social
 * Usa Playwright para navegación headless con cookies de autenticación
 */

import { chromium, Browser, Page, Cookie } from 'playwright';
import * as fs from 'fs/promises';
import * as path from 'path';
import { BaseScraper, registerScraper } from './base-scraper.js';
import {
  DataSource,
  XScrapedData,
  XPost,
  XCookiesFile,
  XCookie,
  ScraperConfig
} from '../types/index.js';

// Query única optimizada - combina términos CTI en una sola búsqueda
// Usa OR para capturar múltiples amenazas sin múltiples requests
const CTI_QUERY = '(ransomware OR "data breach" OR CVE-2024 OR "zero-day" OR APT) (attack OR exploit OR campaign) -filter:replies min_faves:10';

export class XScraper extends BaseScraper<XScrapedData> {
  private browser: Browser | null = null;
  private page: Page | null = null;
  private cookiesPath: string;

  constructor(config: ScraperConfig) {
    super(config);
    this.cookiesPath = process.env.X_COOKIES_PATH || path.join(process.cwd(), 'DATA', 'x.com_13-02-2026.json');
  }

  protected get scraperName(): string {
    return 'XScraper';
  }

  protected async scrape(): Promise<XScrapedData> {
    const posts: XPost[] = [];

    try {
      await this.initBrowser();
      await this.loadCookies();

      // Verificar autenticación
      const isAuthenticated = await this.verifyAuthentication();
      if (!isAuthenticated) {
        throw new Error('Failed to authenticate with X.com cookies');
      }

      console.log(`[XScraper] Single optimized query`);

      // Una sola búsqueda optimizada
      try {
        const searchResults = await this.searchPosts(CTI_QUERY);
        posts.push(...searchResults);
        console.log(`[XScraper] Found ${searchResults.length} posts`);
      } catch (error) {
        console.error(`[XScraper] Query failed:`, error);
      }

    } finally {
      await this.closeBrowser();
    }

    return {
      source: DataSource.X_COM,
      timestamp: new Date().toISOString(),
      rawData: posts,
      posts: this.deduplicatePosts(posts),
      searchQuery: CTI_QUERY
    };
  }

  /**
   * Inicializa el browser de Playwright
   */
  private async initBrowser(): Promise<void> {
    console.log('[XScraper] Initializing browser...');
    
    this.browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--disable-dev-shm-usage',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor'
      ]
    });

    const context = await this.browser.newContext({
      viewport: { width: 1920, height: 1080 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
      locale: 'en-US',
      timezoneId: 'America/New_York'
    });

    this.page = await context.newPage();

    // Evadir detección de automatización
    await this.page.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => false });
      Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
    });
  }

  /**
   * Carga las cookies de autenticación
   */
  private async loadCookies(): Promise<void> {
    console.log(`[XScraper] Loading cookies from ${this.cookiesPath}...`);
    
    try {
      const cookiesRaw = await fs.readFile(this.cookiesPath, 'utf-8');
      const cookiesFile: XCookiesFile = JSON.parse(cookiesRaw);
      
      if (!cookiesFile.cookies || cookiesFile.cookies.length === 0) {
        throw new Error('No cookies found in file');
      }

      // Convertir formato de cookies a Playwright
      const playwrightCookies: Cookie[] = cookiesFile.cookies.map((cookie: XCookie) => ({
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        expires: cookie.expirationDate || -1,
        httpOnly: cookie.httpOnly,
        secure: cookie.secure,
        sameSite: this.convertSameSite(cookie.sameSite)
      }));

      await this.page!.context().addCookies(playwrightCookies);
      console.log(`[XScraper] Loaded ${playwrightCookies.length} cookies`);
    } catch (error) {
      throw new Error(`Failed to load cookies: ${error}`);
    }
  }

  /**
   * Convierte sameSite a formato Playwright
   */
  private convertSameSite(sameSite: string): 'Strict' | 'Lax' | 'None' {
    switch (sameSite.toLowerCase()) {
      case 'strict': return 'Strict';
      case 'lax': return 'Lax';
      case 'no_restriction':
      case 'none': return 'None';
      default: return 'Lax';
    }
  }

  /**
   * Verifica si las cookies permiten autenticación
   */
  private async verifyAuthentication(): Promise<boolean> {
    console.log('[XScraper] Verifying authentication...');
    
    try {
      await this.page!.goto('https://x.com/home', { 
        waitUntil: 'domcontentloaded',
        timeout: 30000 
      });

      // Esperar un poco para que cargue la página
      await this.sleep(3000);

      // Verificar si estamos autenticados buscando elementos de usuario logueado
      const isLoggedIn = await this.page!.evaluate(() => {
        // Buscar indicadores de sesión activa
        const composeButton = document.querySelector('[data-testid="SideNav_NewTweet_Button"]');
        const homeTimeline = document.querySelector('[data-testid="primaryColumn"]');
        return !!(composeButton || homeTimeline);
      });

      if (isLoggedIn) {
        console.log('[XScraper] Successfully authenticated');
        return true;
      }

      // Verificar si hay login wall
      const hasLoginWall = await this.page!.evaluate(() => {
        const loginButton = document.querySelector('[data-testid="loginButton"]');
        return !!loginButton;
      });

      if (hasLoginWall) {
        console.log('[XScraper] Login wall detected - cookies may be expired');
        return false;
      }

      return true;
    } catch (error) {
      console.error('[XScraper] Authentication check failed:', error);
      return false;
    }
  }

  /**
   * Busca posts en X.com
   */
  private async searchPosts(query: string): Promise<XPost[]> {
    const posts: XPost[] = [];
    
    const searchUrl = `https://x.com/search?q=${encodeURIComponent(query)}&src=typed_query&f=live`;
    
    await this.page!.goto(searchUrl, { 
      waitUntil: 'domcontentloaded',
      timeout: 30000 
    });

    // Esperar a que carguen los tweets
    await this.sleep(3000);

    // Scroll para cargar más contenido
    for (let i = 0; i < 3; i++) {
      await this.page!.evaluate(() => {
        window.scrollBy(0, window.innerHeight);
      });
      await this.sleep(1500);
    }

    // Extraer tweets
    const tweets = await this.page!.evaluate(() => {
      const tweetElements = document.querySelectorAll('[data-testid="tweet"]');
      const results: Array<{
        text: string;
        author: string;
        displayName: string;
        timestamp: string;
        metrics: { likes: string; reposts: string; replies: string };
      }> = [];

      tweetElements.forEach((tweet) => {
        try {
          const textElement = tweet.querySelector('[data-testid="tweetText"]');
          const text = textElement?.textContent || '';

          const authorElement = tweet.querySelector('[data-testid="User-Name"]');
          const authorLink = authorElement?.querySelector('a[href*="/"]');
          const author = authorLink?.getAttribute('href')?.replace('/', '') || 'unknown';
          const displayName = authorElement?.querySelector('span')?.textContent || author;

          const timeElement = tweet.querySelector('time');
          const timestamp = timeElement?.getAttribute('datetime') || new Date().toISOString();

          const likesElement = tweet.querySelector('[data-testid="like"]');
          const repostsElement = tweet.querySelector('[data-testid="retweet"]');
          const repliesElement = tweet.querySelector('[data-testid="reply"]');

          results.push({
            text,
            author,
            displayName,
            timestamp,
            metrics: {
              likes: likesElement?.textContent || '0',
              reposts: repostsElement?.textContent || '0',
              replies: repliesElement?.textContent || '0'
            }
          });
        } catch {
          // Skip malformed tweets
        }
      });

      return results;
    });

    // Procesar tweets extraídos
    for (const tweet of tweets) {
      if (!tweet.text || tweet.text.length < 10) continue;

      const post: XPost = {
        id: this.generateId('xpost'),
        text: tweet.text,
        author: {
          username: tweet.author,
          displayName: tweet.displayName,
          verified: false // Simplificado
        },
        metrics: {
          likes: this.parseMetric(tweet.metrics.likes),
          reposts: this.parseMetric(tweet.metrics.reposts),
          replies: this.parseMetric(tweet.metrics.replies),
          views: 0
        },
        timestamp: tweet.timestamp,
        hashtags: this.extractHashtags(tweet.text),
        mentions: this.extractMentions(tweet.text),
        urls: this.extractUrls(tweet.text)
      };

      posts.push(post);
    }

    return posts;
  }

  /**
   * Parsea métricas de engagement (ej: "1.2K" -> 1200)
   */
  private parseMetric(value: string): number {
    if (!value) return 0;
    const normalized = value.trim().toUpperCase();
    
    if (normalized.includes('K')) {
      return Math.round(parseFloat(normalized.replace('K', '')) * 1000);
    }
    if (normalized.includes('M')) {
      return Math.round(parseFloat(normalized.replace('M', '')) * 1000000);
    }
    
    return parseInt(normalized, 10) || 0;
  }

  /**
   * Extrae hashtags de un texto
   */
  private extractHashtags(text: string): string[] {
    const matches = text.match(/#\w+/g);
    return matches || [];
  }

  /**
   * Extrae menciones de un texto
   */
  private extractMentions(text: string): string[] {
    const matches = text.match(/@\w+/g);
    return matches || [];
  }

  /**
   * Extrae URLs de un texto
   */
  private extractUrls(text: string): string[] {
    const urlRegex = /https?:\/\/[^\s]+/g;
    const matches = text.match(urlRegex);
    return matches || [];
  }

  /**
   * Elimina posts duplicados
   */
  private deduplicatePosts(posts: XPost[]): XPost[] {
    const seen = new Set<string>();
    return posts.filter(post => {
      // Usar texto truncado como key para detectar duplicados
      const key = post.text.substring(0, 100);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Cierra el browser
   */
  private async closeBrowser(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
      console.log('[XScraper] Browser closed');
    }
  }
}

// Registrar el scraper
registerScraper(DataSource.X_COM, XScraper);

export default XScraper;
