#!/usr/bin/env node
/**
 * CTI Pipeline - Script Orquestador Principal
 * 
 * Uso:
 *   npx tsx src/index.ts [command]
 * 
 * Commands:
 *   scrape    - Ejecutar scrapers (X.com + Shodan)
 *   process   - Procesar y normalizar datos
 *   analyze   - Análisis con LLM local (Ollama)
 *   dashboard - Generar JSON del dashboard
 *   all       - Ejecutar pipeline completo (default)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { DataSource, ScraperConfig } from './types/index.js';
import ShodanScraper from './scrapers/shodan-scraper.js';
import XScraper from './scrapers/x-scraper.js';
import DataProcessor from './processors/data-processor.js';
import LLMAnalyzer from './llm/analyzer.js';
import DashboardGenerator from './dashboard/generate-dashboard.js';

const OUTPUT_DIR = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
const COMMANDS = ['scrape', 'process', 'analyze', 'dashboard', 'all'] as const;
type Command = typeof COMMANDS[number];

async function saveData(filename: string, data: unknown): Promise<void> {
  await fs.mkdir(OUTPUT_DIR, { recursive: true });
  await fs.writeFile(path.join(OUTPUT_DIR, filename), JSON.stringify(data, null, 2));
}

async function runScrapers(): Promise<void> {
  console.log('\n========== SCRAPERS ==========\n');
  
  const baseConfig: Omit<ScraperConfig, 'source'> = {
    enabled: true,
    rateLimit: { requestsPerMinute: 5, cooldownMs: 2000 },
    cache: { enabled: true, ttlHours: 24 },
    queries: []
  };

  // Shodan
  if (process.env.SHODAN_API_KEY) {
    const shodan = new ShodanScraper({ ...baseConfig, source: DataSource.SHODAN });
    const result = await shodan.execute();
    if (result.success) {
      await saveData('shodan-data.json', result.data);
      console.log(`[Shodan] ✓ ${result.data.hosts.length} hosts, cache=${result.fromCache}`);
    } else {
      console.log(`[Shodan] ✗ ${result.error}`);
    }
  } else {
    console.log('[Shodan] Skipped (no API key)');
  }

  // X.com
  if (process.env.X_COOKIES_PATH) {
    const xScraper = new XScraper({ ...baseConfig, source: DataSource.X_COM });
    const result = await xScraper.execute();
    if (result.success) {
      await saveData('x-data.json', result.data);
      console.log(`[X.com] ✓ ${result.data.posts.length} posts, cache=${result.fromCache}`);
    } else {
      console.log(`[X.com] ✗ ${result.error}`);
    }
  } else {
    console.log('[X.com] Skipped (no cookies path)');
  }
}

async function runProcessor(): Promise<void> {
  console.log('\n========== PROCESSOR ==========\n');
  const processor = new DataProcessor();
  const result = await processor.process();
  console.log(`[Processor] ✓ ${result.threats.length} threats, ${result.indicators.length} IOCs`);
}

async function runAnalyzer(): Promise<void> {
  console.log('\n========== LLM ANALYZER ==========\n');
  const analyzer = new LLMAnalyzer();
  const result = await analyzer.analyze();
  console.log(`[LLM] ✓ Analysis complete (${result.model})`);
}

async function runDashboard(): Promise<void> {
  console.log('\n========== DASHBOARD ==========\n');
  const generator = new DashboardGenerator();
  const dashboard = await generator.generate();
  console.log(`[Dashboard] ✓ Generated - Risk: ${dashboard.status.riskLevel}, Signals: ${dashboard.metrics.totalSignals}`);
}

async function main(): Promise<void> {
  const command = (process.argv[2] as Command) || 'all';
  
  if (!COMMANDS.includes(command)) {
    console.error(`Unknown command: ${command}`);
    console.error(`Available: ${COMMANDS.join(', ')}`);
    process.exit(1);
  }

  console.log(`\n🔐 CTI Pipeline - ${command.toUpperCase()}`);
  console.log(`   Time: ${new Date().toISOString()}\n`);

  const startTime = Date.now();

  try {
    switch (command) {
      case 'scrape':
        await runScrapers();
        break;
      case 'process':
        await runProcessor();
        break;
      case 'analyze':
        await runAnalyzer();
        break;
      case 'dashboard':
        await runDashboard();
        break;
      case 'all':
        await runScrapers();
        await runProcessor();
        await runAnalyzer();
        await runDashboard();
        break;
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n✅ Pipeline complete in ${elapsed}s\n`);
  } catch (error) {
    console.error('\n❌ Pipeline failed:', error);
    process.exit(1);
  }
}

main();
