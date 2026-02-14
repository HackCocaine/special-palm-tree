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
import ShodanScraper, { setContextualQueries } from './scrapers/shodan-scraper.js';
import XScraper from './scrapers/x-scraper.js';
import DataProcessor from './processors/data-processor.js';
import LLMAnalyzer from './llm/analyzer.js';
import DashboardGenerator from './dashboard/generate-dashboard.js';
import QueryGenerator from './llm/query-generator.js';
import CTIAgentSystem from './llm/cti-agents.js';

const OUTPUT_DIR = process.env.CTI_OUTPUT_DIR || './DATA/cti-output';
const COMMANDS = ['scrape', 'process', 'analyze', 'agents', 'dashboard', 'query', 'smart', 'all'] as const;
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

/**
 * Run CTI analysis system (v2 - efficient single-pass analysis)
 * Extracts indicators in code, single LLM call for narrative
 */
async function runCTIAgents(): Promise<void> {
  console.log('\n========== CTI ANALYSIS SYSTEM ==========\n');
  const agents = new CTIAgentSystem();
  const analysis = await agents.analyze();
  console.log(`[CTI-Agents] ✓ Analysis complete`);
  console.log(`  - IPs: ${analysis.extraction.iocs.ips.length}`);
  console.log(`  - CVEs: ${analysis.extraction.iocs.cves.length}`);
  console.log(`  - TTPs: ${analysis.extraction.ttps.length}`);
  console.log(`  - Risk: ${analysis.analysis.riskAssessment.level} (score: ${analysis.analysis.riskAssessment.score})`);
  console.log(`  - Findings: ${analysis.report.keyFindings.length}`);
}

async function runDashboard(): Promise<void> {
  console.log('\n========== DASHBOARD ==========\n');
  const generator = new DashboardGenerator();
  const dashboard = await generator.generate();
  console.log(`[Dashboard] ✓ Generated - Risk: ${dashboard.status.riskLevel}, Signals: ${dashboard.metrics.totalSignals}`);
}

/**
 * Run LLM-driven query generation from X.com social intel
 */
async function runQueryGenerator(): Promise<void> {
  console.log('\n========== QUERY GENERATOR ==========\n');
  const generator = new QueryGenerator();
  const result = await generator.generateQueries();
  console.log(`[QueryGen] ✓ Generated ${result.queries.length} queries from ${result.sourcePostsAnalyzed} posts`);
  
  if (result.queries.length > 0) {
    console.log('\n[QueryGen] Suggested Shodan Queries:');
    for (const q of result.queries) {
      console.log(`  [${q.priority}] ${q.query}`);
      console.log(`    └─ ${q.rationale}`);
    }
  }
}

/**
 * Smart pipeline: X.com -> LLM Query Generation -> Contextual Shodan -> Analysis
 * This is the main pipeline that provides context-aware infrastructure discovery
 */
async function runSmartPipeline(): Promise<void> {
  console.log('\n========== CONTEXT-AWARE CTI PIPELINE ==========\n');
  console.log('[CTI] Phase 1: Collecting social intelligence from X.com...');
  
  const baseConfig: Omit<ScraperConfig, 'source'> = {
    enabled: true,
    rateLimit: { requestsPerMinute: 3, cooldownMs: 5000 },
    cache: { enabled: true, ttlHours: 24 },
    queries: []
  };

  // Phase 1: X.com scraping - understand current threat landscape
  if (process.env.X_COOKIES_PATH) {
    const xScraper = new XScraper({ ...baseConfig, source: DataSource.X_COM });
    const result = await xScraper.execute();
    if (result.success) {
      await saveData('x-data.json', result.data);
      console.log(`[CTI] Social intel: ${result.data.posts.length} posts collected`);
    }
  } else {
    console.log('[CTI] WARNING: No X.com cookies - social context unavailable');
  }

  // Phase 2: LLM generates contextual Shodan queries based on social intel
  console.log('[CTI] Phase 2: Generating context-aware Shodan queries...');
  const queryGen = new QueryGenerator();
  const queryResult = await queryGen.generateQueries(false); // Don't use cache for fresh queries
  
  if (queryResult.queries.length > 0) {
    console.log(`[CTI] Generated ${queryResult.queries.length} contextual queries:`);
    for (const q of queryResult.queries.slice(0, 3)) {
      console.log(`  → ${q.query}`);
      console.log(`    (${q.rationale.substring(0, 80)}...)`);
    }
    
    // Pass contextual queries to Shodan scraper
    setContextualQueries(queryResult.queries.map(q => q.query));
  } else {
    console.log('[CTI] No contextual queries generated - Shodan will use fallback');
  }
  
  // Phase 3: Shodan with context-aware queries from social intel
  if (process.env.SHODAN_API_KEY) {
    console.log('[CTI] Phase 3: Running context-aware infrastructure discovery...');
    const shodan = new ShodanScraper({ 
      ...baseConfig, 
      source: DataSource.SHODAN,
      rateLimit: { requestsPerMinute: 5, cooldownMs: 2000 }
    });
    const result = await shodan.execute();
    if (result.success) {
      await saveData('shodan-data.json', result.data);
      console.log(`[CTI] Infrastructure: ${result.data.hosts.length} hosts found`);
    }
  } else {
    console.log('[CTI] WARNING: No Shodan API key - infrastructure intel unavailable');
  }

  // Phase 4: Process and correlate data
  console.log('[CTI] Phase 4: Processing and correlating data...');
  await runProcessor();
  
  // Phase 5: CTI Analysis with temporal correlation
  console.log('[CTI] Phase 5: Running CTI analysis with temporal correlation...');
  await runCTIAgents();
  
  // Phase 6: Generate dashboard
  console.log('[CTI] Phase 6: Generating dashboard...');
  await runDashboard();
  
  console.log('\n[CTI] ✓ Context-aware pipeline complete!');
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
      case 'agents':
        await runCTIAgents();
        break;
      case 'dashboard':
        await runDashboard();
        break;
      case 'query':
        await runQueryGenerator();
        break;
      case 'smart':
        await runSmartPipeline();
        break;
      case 'all':
        // Smart pipeline: Context-aware infrastructure discovery
        // 1. First collect social intelligence from X.com
        // 2. Generate contextual Shodan queries based on social intel
        // 3. Run Shodan with context-aware queries
        // 4. Process, analyze, and generate dashboard
        await runSmartPipeline();
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
