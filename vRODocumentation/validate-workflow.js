// validate-workflow.js – vRO‑specific validator for variable naming & descriptions
// -----------------------------------------------------------------------------
// • Scans every *.workflow.xml (pattern from env VRO_GLOB or fallback)
// • Validates that input/output/attribute names follow naming conventions:
//     – lowerCamelCase  for regular variables / functions
//     – UPPER_CASE      for constants (heuristic: attribute read‑only="true")
// • Ensures <input>/<output>/<attrib> have a non‑empty <description>.
// • Ensures each <workflow-item> (except start/end/link) has a valid <description>.
// • Validates main workflow description length & content.
// • Reports all violations and exits with code 1 if any were found.
// -----------------------------------------------------------------------------

import fg from 'fast-glob';
import path from 'node:path';
import { loadXml } from './parse-vro.js';

const GLOB = process.env.VRO_GLOB || '**/*workflow.xml';

// RegEx helpers
const CAMEL_CASE_RE = /^[a-z]+(?:[A-Z][a-z0-9]*)*$/;      // e.g., myVariable
const UPPER_CASE_RE = /^[A-Z0-9_]+$/;                    // e.g., MY_CONST

function isConstant(attr) {
  return (
    attr['read-only'] === 'true' ||
    attr.readOnly === true ||
    attr['readOnly'] === 'true'
  );
}

function validateName(name, constant) {
  return constant ? UPPER_CASE_RE.test(name) : CAMEL_CASE_RE.test(name);
}

// Description validators ------------------------------------------------------
function isSameChar(text) {
  return /^(\w)\1*$/.test(text);
}
function isSameWord(text) {
  return /^(\b\w+\b)( \1)*$/.test(text);
}

function validateWorkflowDescription(desc) {
  if (!desc) return 'Workflow description missing';
  if (desc.length < 50) return 'Workflow description too short (<50 chars)';
  if (isSameChar(desc) || isSameWord(desc)) return 'Workflow description invalid (repetitions)';
  return 'valid';
}

const INVALID_DEFAULT_TEXTS = new Set([
  'Simple task with custom script capability.',
  'Custom decision based on a custom script.',
  'Decision activity based on a workflow or an action.',
  'Use this element to set up a user interaction.',
  'Add a note to the workflow schema.',
  'Start an asynchronous workflow.',
  'Schedule a workflow and create a task.',
  'Basic switch activity based on a workflow attribute or parameter.',
  'Sleep a given number of seconds.',
  'Change current execution credential.',
  'Wait until date.',
  'Wait for custom event.',
  'Send a custom event.',
  'Log the input text to the console log with the level "log".',
  'Log the input text to the console log with the level "warn".',
  'Log the input text to the console log with the level "error".',
  'Log the input text to the server log with the level "log".',
  'Log the input text to the server log with the level "warn".',
  'Log the input text to the server log with the level "error".',
  'Log the input text to the console and the server log with the level "log".',
  'Log the input text to the console and the server log with the level "warn".',
  'Log the input text to the console and the server log with the level "error".',
]);

function validateItemDescription(desc, itemName) {
  if (!desc) return 'No description text found';
  if (desc === itemName) return 'Description equals the item name';
  if (INVALID_DEFAULT_TEXTS.has(desc)) return 'Default template description';
  if (desc.length < 15) return 'Schema description too short (<15 chars)';
  if (isSameChar(desc) || isSameWord(desc)) return 'Invalid description text (repetitions)';
  return 'valid';
}

// Main validation -------------------------------------------------------------
let violations = 0;
const files = await fg(GLOB, { dot: true });
console.log(`🔍  Validating variables & descriptions: pattern = ${GLOB}`);
console.log(`    ➜  ${files.length} workflow file(s) found\n`);

for (const file of files) {
  const wfObj = await loadXml(file);
  const rootKey = Object.keys(wfObj)[0]; // handle namespace prefix
  const wf = wfObj[rootKey];
  const fileRel = path.relative('.', file);

  if (!wf) {
    console.error(`${fileRel}: cannot find <workflow> root element`);
    violations++;
    continue;
  }

  // 1) Main workflow description --------------------------------------------
  const mainDesc = wf.description?._ ?? wf.description;
  const mainCheck = validateWorkflowDescription(mainDesc?.trim());
  if (mainCheck !== 'valid') {
    console.error(`${fileRel}: ${mainCheck}`);
    violations++;
  }

  // Helper to normalise collections
  const collect = (node) => (Array.isArray(node) ? node : node ? [node] : []);

  // 2) Variables (inputs / outputs / attribs) --------------------------------
  const inputs = collect(wf.input?.param);
  const outputs = collect(wf.output?.param);
  const attribs = collect(wf.attrib);

  for (const entry of [...inputs, ...outputs, ...attribs]) {
    const name = entry?.name;
    if (!name) continue;

    const constant = isConstant(entry);
    if (!validateName(name, constant)) {
      console.error(`${fileRel}: variable "${name}" violates naming convention (expected ${constant ? 'UPPER_CASE' : 'camelCase'})`);
      violations++;
    }

    const descText = entry.description?._ ?? entry.description;
    if (!descText || descText.trim().length === 0) {
      console.error(`${fileRel}: variable "${name}" is missing <description>`);
      violations++;
    }
  }

  // 3) Schema items -----------------------------------------------------------
  const items = collect(wf['workflow-item']);
  for (const item of items) {
    const type = item.type ?? item['type'];
    if (type === 'end' || type === 'start' || type === 'link') continue; // skip technical nodes

    const itemName = item['display-name']?._ ?? item.name ?? 'unknown';
    const itemDesc = item.description?._ ?? item.description;
    const itemCheck = validateItemDescription(itemDesc?.trim(), itemName);

    if (itemCheck !== 'valid') {
      console.error(`${fileRel}: workflow-item "${itemName}" invalid description – ${itemCheck}`);
      violations++;
    }
  }
}

if (violations > 0) {
  console.error(`\n❌  Validation failed with ${violations} violation(s).`);
  process.exit(1);
} else {
  console.log('✅  All variables & descriptions are valid.');
}
