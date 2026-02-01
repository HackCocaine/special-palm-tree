# Agentic Coding Guidelines for Special Palm Tree

This document provides essential information for AI agents operating in the `special-palm-tree` repository.

## 🚀 Commands

The core application is located in the `eccentric-equator` directory. All development commands should be executed from within that directory.

| Task | Command | Directory |
|------|---------|-----------|
| **Install** | `npm install` | `eccentric-equator` |
| **Build** | `npm run build` | `eccentric-equator` |
| **Development** | `npm run dev` | `eccentric-equator` |
| **Preview** | `npm run preview` | `eccentric-equator` |
| **Type Check** | `npx astro check` | `eccentric-equator` |
| **Lighthouse** | `npx lhci collect --local-build-directory=dist` | `eccentric-equator` |

### Testing & Verification
There is currently no automated unit test suite (Jest/Vitest) configured. Verification is performed via:
1. **Manual Verification**: Run `npm run dev` and verify UI changes in the browser.
2. **Type Checking**: Run `npx astro check` to ensure TypeScript safety across `.astro` and `.ts/tsx` files.
3. **Lighthouse CI**: Used in GitHub Actions for performance, accessibility, and SEO audits. Configured in `lighthouserc.js`.

To run a single verification (if tests are added later):
`npm test path/to/file.test.ts` (Standard pattern to follow if adding Vitest/Jest).

## 🛠️ Technology Stack
- **Framework**: [Astro](https://astro.build/) (v5+) - Handles routing and static generation.
- **UI Library**: [React](https://react.dev/) (v19+) - Powering the interactive Dashboard Builder.
- **Flow Engine**: [@xyflow/react](https://reactflow.dev/) (React Flow) - Used for the node-based strategy mapping.
- **Backend**: [Supabase](https://supabase.com/) - Authentication and data persistence (WIP).
- **State Management**: React Hooks + Context API (e.g., `AuthContext`).
- **Persistence**: `localStorage` is primary for drafts; Supabase for authenticated/public data.

## 🏗️ Architecture Overview
The project is structured as an Astro site with heavy React integration.
- **Pages**: Located in `src/pages/`, using `.astro` for layout and routing.
- **Components**: Found in `src/components/`, predominantly `.tsx` for complex logic.
- **Lib**: `src/lib/` contains singleton clients like the Supabase client.
- **Styles**: Plain CSS files imported directly into relevant components.

## 🎨 Code Style & Conventions

### 1. Naming Conventions
- **Components**: PascalCase (e.g., `DashboardBuilder.tsx`, `StrategyNode.tsx`).
- **Files**: PascalCase for components, camelCase for utilities/types (e.g., `dashboardStorage.ts`, `types.ts`).
- **Variables/Functions**: camelCase (e.g., `const [nodes, setNodes] = useNodesState([])`).
- **Constants**: UPPER_SNAKE_CASE (e.g., `const CATEGORY_CONFIG = { ... }`).
- **CSS Classes**: Kebab-case, often prefixed to prevent leakage (e.g., `.builder-nav`, `.modal-overlay`).

### 2. Imports
- Group imports: React/Third-party first, then local components, then types, then styles.
- Use named imports where possible.
- Example:
  ```tsx
  import React, { useState, useCallback } from 'react';
  import { ReactFlow, useNodesState } from '@xyflow/react';
  import StrategyNode from './StrategyNode';
  import type { StrategyNodeData } from './types';
  import './styles.css';
  ```

### 3. TypeScript usage
- **Strict Mode**: The project extends `astro/tsconfigs/strict`. Avoid `any` at all costs.
- **Interfaces**: Prefer `interface` for object shapes, `type` for unions/aliases.
- **Component Props**: Define props using `React.FC<Props>` or destructuring with inline types.
- **Data Models**: Use `src/components/DashboardBuilder/types.ts` as the source of truth for dashboard schemas.

### 4. Component Structure
- **Logic & Presentation**: Keep them together if small, or split into specialized hooks if complex.
- **Performance**: Use `useCallback` for functions passed to React Flow (onConnect, onNodesChange) to avoid unnecessary re-renders.
- **Layout**: Use `useMemo` for expensive calculations (like calculating node bounds or filtered lists).

### 5. Styling
- Use plain CSS files imported directly into components.
- Follow a "scoped-like" approach by prefixing classes or using unique class names (e.g., `.builder-panel`, `.palette-item`).
- Avoid inline styles unless dynamic (e.g., setting CSS variables or specific colors from config).
- **Theme**: Stick to the dark "Neon/Cyber" aesthetic (Colors: `#00D26A`, `#3b82f6`, `#1a1a1a`).

### 6. Error Handling
- Use `try...catch` blocks for asynchronous operations (Supabase calls, PDF export, JSON parsing).
- Throw descriptive errors in utility functions to facilitate debugging.
- Context hooks (like `useAuth`) must throw if used outside their providers to catch implementation errors early.

## 💾 Storage Pattern
- **Drafts**: Stored as JSON in `localStorage` under `hackfluency_dashboards`.
- **Versioning**: Each save creates a version in `hackfluency_dashboard_versions` (limits to last 10 per dashboard).
- **Public**: Served via `view.astro`, which fetches data via the `id` query parameter from the store.

## 📂 Directory Structure

```text
eccentric-equator/
├── src/
│   ├── assets/             # Static assets (images, SVGs, sample data)
│   ├── components/
│   │   ├── Auth/           # Supabase Auth components and context
│   │   └── DashboardBuilder/ # Main React Flow based editor components
│   ├── layouts/            # Astro layouts
│   ├── lib/                # Shared utilities (Supabase client)
│   └── pages/              # Astro pages (routing)
├── public/                 # Public static files
└── astro.config.mjs        # Astro configuration
```

## 🛠️ Useful Patterns and Utilities

### 1. Dashboard Persistence (`dashboardStorage.ts`)
The application uses a hybrid storage approach. Drafts are local-first, while shared dashboards can be fetched via IDs.
- `getAllDashboards()`: Returns all saved dashboards from `localStorage`.
- `saveDashboard(name, desc, nodes, edges)`: Creates a new entry with version 1.
- `updateDashboard(id, updates)`: Updates content and increments version.
- `getVersionsForDashboard(id)`: Retrieves history (max 10).

### 2. PDF Export (`pdfExport.ts`)
Uses `html2canvas` and `jspdf` to generate high-quality captures of the strategy map.
- `exportDashboardToPDF(selector, options)`: Captures the element matching the selector.
- Use the `.builder-canvas` class for the full strategy map export.

### 3. Dynamic Layout
Nodes are constrained to their respective "Quarter" columns.
- `getQuarterBounds(quarter)`: Calculates X-axis boundaries for a quarter.
- `constrainToQuarter(x, quarter)`: Forces a node to stay within its column during drag.
- Always use `useCallback` when defining these helpers inside components to maintain stability in React Flow's event system.

## 🚀 Feature Implementation Checklist
When adding new node types or categories:
1. Update `NodeCategory` union in `src/components/DashboardBuilder/types.ts`.
2. Add configuration to `CATEGORY_CONFIG` (label, icon, color).
3. Ensure `StrategyNode.tsx` correctly renders the new category icon/style.
4. Add the new category to the `PaletteItem` sidebar list in `DashboardBuilder.tsx`.
5. Verify that edges/connections behave correctly with the new node type.

## 🤖 Rules & Instructions
- **Cursor/Copilot**: No specific rules files found (`.cursorrules` or `.github/copilot-instructions.md`).
- **Proactiveness**: If adding a new feature, ensure it respects the existing dashboard layout (Quarter-based logic).
- **Security**: NEVER commit Supabase secret keys. The `supabaseKey` in `src/lib/supabase.ts` is the *publishable* key.
- **Accessibility**: Ensure all new UI elements have appropriate ARIA labels and keyboard support (e.g., Delete key to remove nodes).
- **Commits**: Follow the project's commit message style (e.g., "feat: add PDF export", "fix: node drag boundary").

---
*This file is maintained for AI agents. Update it when project conventions evolve.*
