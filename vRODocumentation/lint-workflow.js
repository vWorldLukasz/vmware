#!/usr/bin/env node

// Lints every JavaScript Scriptable Task embedded in vRO workflow XML files.
// -------------------------------------------------------------------------
// • Searches the entire branch for "*.workflow.xml" (override via VRO_GLOB).
// • Lists all Scriptable Tasks discovered per workflow.
// • Runs ESLint on each script and summarises the outcome.
// -------------------------------------------------------------------------

import { ESLint } from 'eslint';
import fg from 'fast-glob';
import path from 'node:path';
import { loadXml, extractScripts } from './parse-vro.js';

// Search pattern – can be overridden by setting the VRO_GLOB env variable.
const PATTERN = process.env.VRO_GLOB || '**/*workflow.xml';

const files = await fg(PATTERN, { dot: true });

console.log(`🔍  Looking for XML files with pattern: ${PATTERN}`);
console.log(`    ➜  found ${files.length} file(s)\n`);

if (files.length === 0) {
  console.error('No workflow files found – check the glob pattern or repository structure.');
  process.exit(1);
}

const eslint = new ESLint();
let errorCount = 0;

for (const file of files) {
  const wf = await loadXml(file);
  const scripts = extractScripts(wf);

  console.log(`${file}`);
  if (scripts.length === 0) {
    console.log('    (no Scriptable Tasks found)\n');
    continue;
  }

  scripts.forEach(({ name }, idx) => console.log(`    ${idx + 1}. ${name}`));

  // Lint each embedded script separately so we get precise file/line numbers.
  for (const { name, code } of scripts) {
    const results = await eslint.lintText(code, {
      filePath: `${path.relative('.', file)}#${name}.js`,
    });
    const output = (await eslint.loadFormatter('stylish')).format(results);
    if (output) console.log(output);
    errorCount += results.reduce((sum, r) => sum + r.errorCount, 0);
  }
  console.log(''); // blank line between workflows
}

if (errorCount > 0) {
  console.error(`ESLint reported ${errorCount} error(s)`);
  process.exit(1);
} else {
  console.log('All embedded scripts passed ESLint');
}
