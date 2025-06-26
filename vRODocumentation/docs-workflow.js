// docs-workflow.js — generate Markdown docs purely from XML + local form JSON
// -----------------------------------------------------------------------------
import fg from 'fast-glob';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { loadXml } from './parse-vro.js';


const GLOB = process.env.VRO_GLOB || '**/*workflow.xml';
const OUT_DIR = 'docs/workflows';

await fs.mkdir(OUT_DIR, { recursive: true });

const collect = (x) => (Array.isArray(x) ? x : x ? [x] : []);
const fence = (code, lang = 'javascript') => `\`\`\`${lang}\n${code}\n\`\`\``;
const txt = (node) => {
  if (!node) return '';
  if (Array.isArray(node)) return txt(node[0]);   // <── nowa linia
  return typeof node === 'string' ? node : node._ ?? '';
};


function table(arr, cols) {
  if (!arr.length) return '';
  const header =
    `| ${cols.map((c) => c.header).join(' | ')} |\n` +
    `| ${cols.map(() => '---').join(' | ')} |\n`;
  const rows = arr
    .map((row) => `| ${cols.map((c) => row[c.key] ?? '').join(' | ')} |`)
    .join('\n');
  return header + rows + '\n';
}

// -----------------------------------------------------------------------------
// MAIN
// -----------------------------------------------------------------------------
const files = await fg(GLOB, { dot: true });
console.log(`📝  Generating docs for ${files.length} workflow(s)\n`);

for (const xmlFile of files) {
  // ---------- parse XML ------------------------------------------------------
  const wfObj = await loadXml(xmlFile);
  const root = wfObj[Object.keys(wfObj)[0]]; // handle namespace prefix

  const wfName =
    root['display-name']?._ ?? root['object-name'] ?? path.basename(xmlFile);
  const wfId = root.id ?? 'n/a';
  const wfVersion = root.version ?? 'n/a';
  const wfDesc =
    root.description?._ ?? root.description ?? '_No description provided_';

  const attribs = collect(root.attrib);
  const inputs = collect(root.input?.param);
  const outputs = collect(root.output?.param);
  const items = collect(root['workflow-item']);
  const errorHandlers = collect(root['error-handler']);

  // gather linked modules / wf
  const linkedWorkflows = [];
  const linkedModules = [];
  for (const el of items) {
    if (el.type === 'link' && el['linked-workflow-id']) {
      linkedWorkflows.push({
        id: el['linked-workflow-id'],
        name: txt(el['display-name']) || el.name,
      });
    }
    if (el['script-module']) linkedModules.push(el['script-module']);
  }

// ---------- parse FORM JSON ----------------------------------------------
let formProps = [];
const formDir = path.join(path.dirname(xmlFile), 'forms');
try {
  const raw       = await fs.readFile(path.join(formDir, '_.json'), 'utf8');
  const formJson  = JSON.parse(raw);
  const schema    = formJson.schema || {};

  
  const fieldStates = {};
  (formJson.layout?.pages || []).forEach(page => {
    (page.sections || []).forEach(section => {
      (section.fields || []).forEach(field => {
        fieldStates[field.id] = field.state || {};
      });
    });
  });

  
  formProps = Object.values(schema).map(p => {
   
    let typeDesc = p.type.dataType;
    if (p.type.isMultiple) typeDesc += '[]';

    
    let requiredDesc = 'Optional';
    const req = p.constraints?.required;
    if (Array.isArray(req)) {
      requiredDesc = req
        .map(cond => {
          const opKey  = Object.keys(cond).find(k => k !== 'value');
          const detail = cond[opKey];
          const [field, exp] = Object.entries(detail)[0];
          return `Required if ${field} ${opKey} ${exp}`;
        })
        .join('; ');
    } else if (req === true) {
      requiredDesc = 'Required';
    }

    
    let patternDesc = '';
    if (p.constraints?.pattern) {
      const rawPatternDesc =  p.constraints.pattern.value;
      const escapedPatterDesc = rawPatternDesc.replace(/\|/g, '\\|');
      patternDesc = `\`${escapedPatterDesc}\``;
    }

    
    let defaultDesc = 'n/a';
    let defaultParams = '';
    if (p.default) {
      if (p.default.type === 'scriptAction') {
        defaultDesc   = `Action: ${p.default.id}`;
        
        defaultParams = p.default.parameters
          .map(par => {
            const key = Object.keys(par).find(k => k !== '$type');
            const val = par[key];
            return `${key}→${val}`;
          })
          .join(', ');
      } else {
        defaultDesc = JSON.stringify(p.default);
      }
    }

    
    let listDesc = 'n/a';
    if (Array.isArray(p.valueList)) {
      listDesc = p.valueList.map(v => v.label || v.value).join(', ');
    } else if (p.valueList?.type === 'scriptAction') {
      listDesc = `Action: ${p.valueList.id}`;
    }

    
    const signpost = (p.signpost || '').trim();

    
    const state = fieldStates[p.id] || {};

    return {
      id:          p.id,
      label:       p.label,
      type:        typeDesc,
      required:    requiredDesc,
      pattern:     patternDesc,
      default:     defaultDesc,
      params:      defaultParams,
      valueList:   listDesc,
      signpost,
      state:       JSON.stringify(state)
    };
  });

} catch {

}

  // ---------- build markdown -------------------------------------------------
  let md = `# ${wfName} - Workflow Documentation\n\n`;

  // details
  md += `<details>\n<summary><h2>Workflow Details</h2></summary>\n\n`;
  md += `- **Workflow Name:** ${wfName}\n`;
  md += `- **Workflow ID:** \`${wfId}\`\n`;
  md += `- **Version:** ${wfVersion}\n`;
  md += `- **Description:** ${wfDesc}\n`;
  md += `</details>\n\n`;

  if (attribs.length)
    md += `<details>\n<summary><h2>Workflow Variables</h2></summary>\n\n` +
      table(attribs, [
        { key: 'name', header: 'Name' },
        { key: 'type', header: 'Type' },
      ]) +
      `</details>\n\n`;

  if (inputs.length)
    md += `<details>\n<summary><h2>Workflow Inputs</h2></summary>\n\n` +
      table(inputs, [
        { key: 'name', header: 'Name' },
        { key: 'type', header: 'Type' },
      ]) +
      `</details>\n\n`;

  if (outputs.length)
    md += `<details>\n<summary><h2>Workflow Outputs</h2></summary>\n\n` +
      table(outputs, [
        { key: 'name', header: 'Name' },
        { key: 'type', header: 'Type' },
      ]) +
      `</details>\n\n`;

  if (formProps.length)
    md += `<details>\n<summary><h2>Workflow Form</h2></summary>\n\n` +
      table(formProps, [
        { key: 'id',       header: 'ID' },
        { key: 'label',    header: 'Label' },
        { key: 'type',     header: 'Type' },
        { key: 'required', header: 'Required' },
        { key: 'pattern',  header: 'Pattern' },
        { key: 'default',  header: 'Default' },
        { key: 'params',   header: 'Params' },
        { key: 'valueList', header: 'Value List' },
        { key: 'signpost', header: 'Signpost' },
        { key: 'state',    header: 'State' },
      ]) +
      `</details>\n\n`;

  // elements
  md += `<details>\n<summary><h2>Workflow Elements</h2></summary>\n\n`;
  for (const el of items) {
    const elName = txt(el['display-name']) || el.name || 'unknown';
    md += `#### Element: ${elName}\n`;
    md += `- **Type:** ${el.type}\n`;
    md += `- **Description:** ${txt(el.description) || '_No description provided_'}\n`;
    md += `- **Element ID:** ${el.name}\n`;
    
    const inB = collect(el['in-binding']?.bind);
    if (inB.length)
      md += `\n**Input Bindings:**\n\n` +
        table(inB, [
          { key: 'name', header: 'Variable Name' },
          { key: 'type', header: 'Type' },
          { key: 'export-name', header: 'Workflow Variable' },
        ]);

    const outB = collect(el['out-binding']?.bind);
    if (outB.length)
      md += `\n**Output Bindings:**\n\n` +
        table(outB, [
          { key: 'name', header: 'Variable Name' },
          { key: 'type', header: 'Type' },
          { key: 'export-name', header: 'Workflow Variable' },
        ]);

    if (el.script?._)
      md += `\n**Script:**\n\n${fence(el.script._.trim())}\n\n`;

    md += '\n\n---\n\n';
  }
  md += `</details>\n\n`;

  // error handlers
  md += `<details>\n<summary><h2>Error Handlers</h2></summary>\n\n`;
  if (errorHandlers.length) {
    for (const eh of errorHandlers)
      md += `- **Element Name:** ${eh.name} (throws: ${eh['throw-bind-name'] ?? '_None_'})\n`;
  } else md += '_No error handlers defined._\n';
  md += `</details>\n\n`;

  // linked
  md += `<details>\n<summary><h2>Linked Workflows</h2></summary>\n\n`;
  if (linkedWorkflows.length)
    linkedWorkflows.forEach((lw) =>
      (md += `- **Name:** ${lw.name}, **ID:** \`${lw.id}\`\n`));
  else md += '_No linked workflows defined._\n';
  md += `</details>\n\n`;

  if (linkedModules.length) {
    md += `<details>\n<summary><h2>Linked Actions (script modules)</h2></summary>\n\n`;
    linkedModules.forEach((m) => (md += `- \`${m}\`\n`));
    md += `</details>\n\n`;
  }

// ——— Mermaid diagram ———
  md += '## Workflow Diagram\n\n';
  md += '```mermaid\n';
  md += 'flowchart LR\n';  

 
  items.forEach(el => {
    const id    = el.name;                          
    const label = txt(el['display-name']) || el.name;
    md += `  ${id}["${label}"]\n`;
  });

  md += '\n'; 


items.forEach(el => {
  const src = el.name;

  if (el.type === 'switch') {
    const conds = collect(el.condition);
    conds.forEach(c => {
      const test = (typeof c._ === 'string' && c._.trim()) || c.name || '';
      md += `  ${src} -- "${test}" --> ${c.label}\n`;
    });
  } else {
    if (el['out-name'])     md += `  ${src} --> ${el['out-name']}\n`;
    if (el['alt-out-name']) md += `  ${src} -.-> ${el['alt-out-name']}\n`;
  }


  if (el['catch-name']) {
    md += `  ${src} -. "catch" .-> ${el['catch-name']}\n`;
  }
});

  md += '```\n\n';


  
  // ---------- write file -----------------------------------------------------
  const outPath = path.join(
    OUT_DIR,
    `${wfName.replace(/\\s+/g, '_')}.md`
  );
  await fs.writeFile(outPath, md, 'utf8');
  console.log(`✔  ${outPath}`);
}

console.log('\\n✅  Documentation generated (XML + local form JSON)');
