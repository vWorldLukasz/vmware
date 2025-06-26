// scripts/parse-vro.js 
import { promises as fs } from 'node:fs';
import { parseStringPromise } from 'xml2js';


export async function loadXml(file) {
  const xml = await fs.readFile(file, 'utf8');
  return parseStringPromise(xml, { explicitArray: false, mergeAttrs: true, explicitCharkey: true });
}


export function extractScripts(workflowObj) {
  const rootKey = Object.keys(workflowObj)[0];
  const root = workflowObj[rootKey];
  const rawItems = root['workflow-item'] ?? root['workflowItem'] ?? [];
  const items = Array.isArray(rawItems) ? rawItems : [rawItems];

  return items
    .filter((i) => i.type === 'task' && i.script?._)
    .map((i) => ({
      name: i['display-name']?._ ?? i.name ?? 'unknown',
      code: i.script._.replace(/^<!\[CDATA\[|\]\]>$/g, ''),
    }));
}


export function meta(workflowObj) {
  const wf = workflowObj.workflow;
  return {
    id: wf.id,
    name: wf['display-name']?._ ?? wf['object-name'],
    version: wf.version,
    inParams: wf.input?.param ?? [],
    outParams: wf.output?.param ?? [],
    attrib: wf.attrib ?? [],
  };
}
