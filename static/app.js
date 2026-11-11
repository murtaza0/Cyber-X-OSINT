const state = { page: 'dashboard', investigationId: null, apiToken: sessionStorage.getItem('cyberx-api-token') || '', revealed: {}, currentInvestigation: null, module: null };
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const MODULES = [
  ['username','Username Intelligence','Public username references and supported profile discovery.'],
  ['email','Email Intelligence','Email normalization, domain DNS posture and public reference searches.'],
  ['phone','Phone Intelligence','Number normalization and public numbering-prefix context.'],
  ['credential','Credential Intelligence','Encrypted analyst-entered records, offline weak-password screening and owner-authorized direct PostgreSQL checks.'],
  ['domain','Domain Intelligence','DNS posture and public certificate-transparency HTML scraping.'],
  ['ip','IP Intelligence','IP classification, reverse DNS and public routing-page HTML collection.'],
  ['social','Social Media Intelligence','Public social profile search entry points and references.'],
  ['website','Website Intelligence','Public page metadata, headers, technology hints and links.'],
  ['image','Image Intelligence','Local image metadata, EXIF and integrity hashes.'],
  ['document','Document Intelligence','Local document metadata and text extraction.'],
  ['github','GitHub & Code Intelligence','Public GitHub profile and repository page scraping; no provider API.'],
  ['network','Network Intelligence','Passive DNS and public routing-page references; no active scanning.'],
  ['threat','Threat Intelligence','Public threat-reference links; no automatic malicious verdicts.'],
  ['breach','Public Incident Intelligence','HTML search for publicly indexed breach and incident disclosures; references require analyst verification.'],
  ['search','Search Engine Intelligence','Scrape public HTML search results without third-party search APIs.'],
  ['attack_surface','Attack Surface Intelligence','Passive public domain and website posture collection.'],
  ['digital_footprint','Digital Footprint','Cross-module public identity and infrastructure correlation.'],
  ['correlation','Entity Correlation','Evidence-linked entities and relationship graph.']
];

function esc(value) { return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
function toast(message, type='ok') { const node=document.createElement('div'); node.className='toast'+(type==='error'?' error':''); node.textContent=message; $('#toastStack').append(node); setTimeout(()=>node.remove(),3800); }
function setPage(page, module=null) { Object.keys(state.revealed).forEach(id=>state.revealed[id]=null); state.page=page; state.module=module; $$('.nav-item[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===page && (page!=='module'||b.dataset.module===module))); renderPage(); }
function apiHeaders(extra={}) { const h={...extra}; if(state.apiToken) h['X-API-Token']=state.apiToken; return h; }
async function api(path, options={}) {
  const headers=apiHeaders(options.headers||{});
  if(options.body && !(options.body instanceof FormData) && !headers['Content-Type']) headers['Content-Type']='application/json';
  const response=await fetch(path,{...options,headers});
  const type=response.headers.get('content-type')||'';
  const payload=type.includes('application/json')?await response.json():await response.text();
  if(!response.ok) { const error=new Error(payload?.detail || payload?.message || `Request failed (${response.status})`); error.status=response.status; throw error; }
  return payload;
}
function fmtDate(value){ if(!value)return '—'; const d=new Date(value); return Number.isNaN(d.getTime())?value:d.toLocaleString(); }
function statusPill(status){ const c=status==='completed'?'green':status==='failed'?'red':status==='partial'?'amber':status==='running'?'blue':status==='queued'?'amber':''; return `<span class="pill ${c}">${esc(status||'unknown')}</span>`; }
function empty(title, body){return `<div class="empty-state"><strong>${esc(title)}</strong>${esc(body)}</div>`;}
function heading(kicker,title,sub,action=''){return `<div class="page-heading"><div><div class="eyebrow">${esc(kicker)}</div><h1 class="page-title">${esc(title)}</h1><div class="page-subtitle">${esc(sub)}</div></div>${action}</div>`;}

async function renderPage(){
  $('#pageCrumb').textContent = state.page==='module' ? (MODULES.find(m=>m[0]===state.module)?.[1]||'Intelligence') : ({dashboard:'Command Center',investigations:'Investigations',framework:'OSINT Framework',sources:'Source Manager',audit:'Audit Trail',settings:'Settings',exposure:'Exposure Dataset Lab'}[state.page]||'Workspace');
  const root=$('#pageContent'); root.innerHTML='<div class="loading-state">Loading workspace…</div>';
  try {
    if(state.page==='dashboard') root.innerHTML=await renderDashboard();
    else if(state.page==='investigations') root.innerHTML=await renderInvestigations();
    else if(state.page==='investigation') root.innerHTML=await renderInvestigation(state.investigationId);
    else if(state.page==='framework') root.innerHTML=renderFramework();
    else if(state.page==='sources') root.innerHTML=await renderSources();
    else if(state.page==='audit') root.innerHTML=await renderAudit();
    else if(state.page==='settings') root.innerHTML=renderSettings();
    else if(state.page==='exposure') root.innerHTML=await renderExposureLab();
    else if(state.page==='module') root.innerHTML=await renderModulePage(state.module);
  } catch(error) { if(error.status===401 || error.status===503) { root.innerHTML=renderAuthGate(error.message); return; } root.innerHTML=`<div class="panel">${empty('Unable to load this view',error.message)}</div>`; toast(error.message,'error'); }
}

function renderAuthGate(message){return `${heading('SECURE WORKSPACE','Access required','This deployment is protected by an operator-configured access token. Enter the token shared by the project owner.')}<div class="auth-gate panel"><div class="auth-lock">⌑</div><div class="panel-title">Cyber X protected access</div><p class="page-subtitle">The token is sent only to this deployment and held in this browser tab session. It is not written to local storage.</p><div class="field"><label>Workspace access token</label><input id="apiTokenInput" type="password" autocomplete="current-password" placeholder="Paste API_TOKEN" /></div><div class="field-help">${esc(message||'Access token required.')}</div><button class="primary-button" data-action="save-token">Unlock workspace →</button><div class="footer-note">No public registration. Configure API_TOKEN in the Vercel project environment variables.</div></div>`;}

async function renderDashboard(){
  const [stats,cases]=await Promise.all([api('/api/v1/dashboard'),api('/api/v1/investigations')]);
  $('#apiStatus').textContent='BACKEND ONLINE';
  const recent=(stats.recent_findings||[]).slice(0,7).map(f=>`<tr><td>${esc(f.module)}</td><td>${esc(f.finding_type)}</td><td>${esc(f.value).slice(0,100)}</td><td>${statusPill(f.verification_status)}</td><td>${fmtDate(f.collected_at)}</td></tr>`).join('');
  const caseRows=cases.slice(0,6).map(c=>`<tr><td><button class="link-button" data-action="open-case" data-id="${c.id}">${esc(c.name)}</button></td><td>${c.target_count}</td><td>${c.finding_count}</td><td>${statusPill(c.status)}</td><td>${fmtDate(c.created_at)}</td></tr>`).join('');
  return `${heading('INTELLIGENCE OVERVIEW','Command Center','A unified workspace for public-source investigations, evidence collection and entity correlation.','<button class="primary-button" data-action="new-case">＋ New Investigation</button>')}
    <div class="quick-search"><input id="quickTarget" placeholder="Enter a username, email, domain, IP, phone number or URL…" /><button class="primary-button" data-action="quick-search">Run Unified Search →</button></div>
    <div class="grid stats-grid">
      ${stat('INVESTIGATIONS',stats.investigations,'Case workspaces')}${stat('TARGETS',stats.targets,'Tracked identifiers')}${stat('FINDINGS',stats.findings,'Collected observations')}${stat('EVIDENCE',stats.evidence,'Integrity records')}${stat('ACTIVE JOBS',stats.active_jobs,'Queued or running')}
    </div>
    <div class="grid two-col">
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Recent Findings</div><div class="panel-note">Latest observations across investigations</div></div><span class="pill blue">LIVE DATABASE</span></div>
        <div class="table-wrap"><table><thead><tr><th>Module</th><th>Finding Type</th><th>Observation</th><th>Status</th><th>Collected</th></tr></thead><tbody>${recent||'<tr><td colspan="5">No findings yet. Start an investigation to begin collection.</td></tr>'}</tbody></table></div>
      </div>
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Collection Pulse</div><div class="panel-note">Background job state</div></div></div>
        ${pulse('Completed jobs',stats.completed_jobs,'#2dd4bf')}${pulse('Active jobs',stats.active_jobs,'#06b6d4')}${pulse('Failed jobs',stats.failed_jobs,'#ef4444')}
        <div class="footer-note">Collector results are source-dependent. Unavailable services and failures are retained as visible status records.</div>
      </div>
    </div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Recent Investigations</div><div class="panel-note">Select a case to open its targets, findings, evidence and graph.</div></div><button class="small-button" data-page="investigations">View all →</button></div><div class="table-wrap"><table><thead><tr><th>Investigation</th><th>Targets</th><th>Findings</th><th>Status</th><th>Created</th></tr></thead><tbody>${caseRows||'<tr><td colspan="5">No investigations created yet.</td></tr>'}</tbody></table></div></div>
    <div class="footer-note">AUTHORIZED USE ONLY · Public-source collection is subject to source availability, access rules and configured rate limits. Confidence is not proof.</div>`;
}
function stat(label,value,foot){return `<div class="stat-card"><div class="stat-label">${label}</div><div class="stat-value">${value??0}</div><div class="stat-foot">${foot}</div></div>`;}
function pulse(label,value,color){return `<div style="margin:15px 0"><div class="job-line"><span>${label}</span><b>${value??0}</b></div><div class="bar-track"><div class="bar-fill" style="width:${Math.min(100,(value||0)*10)}%;background:${color}"></div></div></div>`;}

async function renderInvestigations(){
  const cases=await api('/api/v1/investigations');
  const cards=cases.map(c=>`<div class="case-card" data-action="open-case" data-id="${c.id}"><div class="case-title">${esc(c.name)}</div><div class="section-caption">${esc(c.description||'No description')}</div><div class="case-meta"><span class="pill">${c.target_count} targets</span><span class="pill blue">${c.finding_count} findings</span>${statusPill(c.status)}<span class="pill">${fmtDate(c.created_at)}</span></div></div>`).join('');
  return `${heading('CASE MANAGEMENT','Investigations','Create and manage separate investigations with independent targets, collection jobs, credentials and evidence.','<button class="primary-button" data-action="new-case">＋ New Investigation</button>')}<div class="case-list">${cards||empty('No investigations yet','Create your first investigation to begin.')}</div>`;
}

async function renderInvestigation(id){
  if(!id) return renderInvestigations();
  const inv=await api(`/api/v1/investigations/${id}`); state.currentInvestigation=inv;
  const credentials=await api(`/api/v1/investigations/${id}/credentials`);
  const graph=await api(`/api/v1/investigations/${id}/graph`);
  const targets=inv.targets.map(t=>`<div class="target-card"><div><div class="target-value">${esc(t.value)}</div><div class="target-type">${esc(t.type.toUpperCase())} · ${esc(t.id.slice(0,8))}</div></div><div class="target-actions"><button class="small-button" data-action="collect" data-target="${t.id}">Run Modules</button></div></div>`).join('');
  const jobs=inv.jobs.slice(0,7).map(j=>`<div class="job-line"><span><b>${esc(j.modules.join(', '))}</b><br><span class="section-caption">${fmtDate(j.started_at||j.finished_at)}</span></span><span>${statusPill(j.status)} <span class="section-caption">${j.findings_count||0} findings</span></span></div>`).join('');
  const findings=inv.findings.slice(0,100).map(f=>`<tr><td>${esc(f.module)}</td><td>${esc(f.finding_type)}</td><td style="max-width:390px;word-break:break-word">${esc(f.value).slice(0,260)}</td><td>${Math.round((f.confidence||0)*100)}%</td><td>${f.source_url?`<a class="link" href="${esc(f.source_url)}" target="_blank" rel="noreferrer">Open source ↗</a>`:'—'}</td><td>${statusPill(f.verification_status)}</td></tr>`).join('');
  return `${heading('INVESTIGATION WORKSPACE',inv.name,inv.description||'Targets, collection jobs, findings, evidence and intelligence relationships.','<button class="secondary-button" data-action="report-json">JSON</button> <button class="secondary-button" data-action="report-html">HTML</button> <button class="primary-button" data-action="report-pdf">PDF Report</button>')}
    <div class="kpi-row" style="margin-bottom:16px"><div class="kpi"><b>${inv.targets.length}</b> Targets</div><div class="kpi"><b>${inv.findings.length}</b> Findings</div><div class="kpi"><b>${inv.jobs.length}</b> Collection Jobs</div><div class="kpi"><b>${graph.nodes.length}</b> Graph Entities</div></div>
    <div class="grid two-col">
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Investigation Targets</div><div class="panel-note">Run the automatically recommended modules or choose a custom collection set.</div></div><button class="small-button" data-action="add-target">＋ Add Target</button></div>
        ${targets||empty('No targets added','Add an email, username, domain, IP, phone number or URL.')}
        <div class="panel-header" style="margin-top:18px"><div><div class="panel-title">Bulk Target Import</div><div class="panel-note">Paste one target per line. Maximum 500 per import.</div></div></div>
        <textarea id="bulkTargets" class="field" style="width:100%;min-height:78px;background:#0b1422;color:#e6eef9;border:1px solid #2b3d55;border-radius:8px;padding:10px;font:11px inherit" placeholder="example.com&#10;analyst@example.com&#10;@sampleuser"></textarea><button class="small-button" data-action="bulk-import">Import Targets</button>
      </div>
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Collection Jobs</div><div class="panel-note">Background collection state</div></div><button class="small-button" data-action="refresh-case">↻ Refresh</button></div>${jobs||empty('No collection jobs','Run modules for a target to create a job.')}</div>
    </div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Entity Relationship Graph</div><div class="panel-note">Relationships are generated from entities observed in collected findings.</div></div><div class="target-actions"><button class="small-button" data-action="view-timeline">Investigation Timeline</button><button class="small-button" data-action="view-evidence">Evidence Vault</button><span class="pill blue">${graph.nodes.length} NODES · ${graph.edges.length} EDGES</span></div></div>${renderGraph(graph)}</div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Credential Intelligence</div><div class="panel-note">Authorized analyst-entered records. Passwords are encrypted at rest and hidden by default.</div></div><button class="small-button" data-action="add-credential">＋ Add Credential</button></div>
      <div class="warning-box"><strong>AUTHORIZED USE ONLY — SENSITIVE CREDENTIAL WARNING</strong>Passwords are confidential. Reveal or handle them only with explicit authorization. Viewing a password is recorded in the audit trail.</div>
      ${renderCredentialRows(credentials)}
    </div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Evidence Upload</div><div class="panel-note">Inspect metadata from authorized images and documents. Files are not executed.</div></div></div><form id="uploadForm"><div class="form-row"><div class="field"><label>Select File</label><input type="file" id="evidenceFile" accept=".jpg,.jpeg,.png,.tiff,.webp,.pdf,.docx,.xlsx,.pptx,.txt,.md,.csv,.json,.xml,.log,.bin" required /></div><div class="field"><label>Attach to Target</label><select id="uploadTarget"><option value="">Investigation only</option>${inv.targets.map(t=>`<option value="${t.id}">${esc(t.value)}</option>`).join('')}</select></div></div><button class="small-button" type="submit">Upload & Extract Metadata</button></form></div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Findings</div><div class="panel-note">${inv.findings.length} stored observations · newest first</div></div></div><div class="table-wrap"><table><thead><tr><th>Module</th><th>Finding Type</th><th>Observation</th><th>Confidence</th><th>Source</th><th>Status</th></tr></thead><tbody>${findings||'<tr><td colspan="6">No findings collected yet.</td></tr>'}</tbody></table></div></div>
    <div class="footer-note">Created ${fmtDate(inv.created_at)} · Collection results are snapshots. Re-run modules to refresh observations. Credentials are excluded from all exports.</div>`;
}
function renderCredentialRows(rows){if(!rows.length)return empty('No credential records','Add only credentials that were provided for an authorized assessment.');return rows.map(r=>{const pass=state.revealed[r.id];const visible=typeof pass==='string';return `<div class="credential-row"><div><div class="credential-identifier">${esc(r.identifier_reference)}</div><div class="credential-kind">${esc(r.identifier_type.toUpperCase())} · ${visible?'VISIBLE':'ENCRYPTED / HIDDEN'} · ${fmtDate(r.created_at)}</div></div><div class="credential-secret" id="secret-${r.id}">${visible?esc(pass):'••••••••••••'}</div><div class="target-actions"><button class="small-button" data-action="${visible?'hide-password':'show-password'}" data-id="${r.id}">${visible?'Hide':'Show'}</button><button class="small-button" data-action="delete-credential" data-id="${r.id}">Delete</button></div></div>`;}).join('');}
function renderGraph(graph){if(!graph.nodes.length)return `<div class="graph-box">${empty('No correlated entities yet','Collect findings that contain related domains, IP addresses or email references to populate the graph.')}</div>`;const nodes=graph.nodes.slice(0,55),w=900,h=320,cx=w/2,cy=h/2,rad=Math.min(125,35+nodes.length*3);const pos={};nodes.forEach((n,i)=>{const a=2*Math.PI*i/nodes.length-Math.PI/2;pos[n.id]={x:cx+Math.cos(a)*rad,y:cy+Math.sin(a)*rad};});const lines=graph.edges.filter(e=>pos[e.source]&&pos[e.target]).map(e=>`<line x1="${pos[e.source].x}" y1="${pos[e.source].y}" x2="${pos[e.target].x}" y2="${pos[e.target].y}" stroke="#365c7b" stroke-width="1.3" opacity=".8"/>`).join('');const circles=nodes.map(n=>{const p=pos[n.id],label=String(n.label).slice(0,19);return `<g><circle cx="${p.x}" cy="${p.y}" r="17" fill="${n.type==='domain'?'#164c72':n.type==='ip'?'#4b347c':n.type==='email'?'#275b52':'#253b58'}" stroke="#66c9e8" stroke-opacity=".7"/><text x="${p.x}" y="${p.y+31}" fill="#b9cce2" font-size="10" text-anchor="middle">${esc(label)}</text></g>`;}).join('');return `<div class="graph-box"><svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Entity relationship graph">${lines}${circles}</svg></div><div class="footer-note">Graph displays up to 55 entities in this view. Relationship evidence and confidence are stored in the investigation database.</div>`;}

function renderFramework(){const cards=MODULES.map((m,i)=>`<div class="module-card" data-action="module-open" data-module="${m[0]}"><span class="module-symbol">⌁</span><div class="module-number">MODULE ${(i+1).toString().padStart(2,'0')}</div><div class="module-name">${esc(m[1])}</div><div class="module-description">${esc(m[2])}</div></div>`).join('');return `${heading('INTELLIGENCE TREE','OSINT Framework','Explore the 18 intelligence modules. Select a module to review its capabilities and supported collection workflow.')}<div class="grid module-grid">${cards}</div>`;}
async function renderModulePage(module){
  const item=MODULES.find(m=>m[0]===module);const cases=await api('/api/v1/investigations');
  const caseOptions=cases.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
  const base=`<div class="field"><label>Investigation</label><select id="toolCase"><option value="">Select case</option>${caseOptions}</select></div>`;
  if(module==='breach') return `${heading('INTELLIGENCE MODULE','Public Incident Intelligence','Scrape publicly indexed HTML references for incident disclosures and breach notifications. These are leads, not proof of compromise.')}<div class="panel"><div class="panel-title">Public incident reference search</div><p class="page-subtitle">Queries public HTML search results for an email target. Cyber X does not call a breach-provider API, retrieve leaked datasets, access stealer logs or attempt private account access.</p><div class="warning-box"><strong>ANALYST SCOPE REQUIRED</strong>Only search an address you own or have written authorization to assess. Results may be incomplete, stale, unrelated or absent from search indexes.</div>${base}<div class="field"><label>Email target</label><select id="breachTarget"><option value="">Select an investigation first</option></select></div><div class="field"><label>Authorization context</label><textarea id="breachAuthorization" placeholder="Account owner approval, client engagement ID or assessment scope…"></textarea></div><button class="primary-button" data-action="run-public-breach-check">Scrape public incident references</button><div class="footer-note">HTML-only collection via publicly accessible search results. The target email is included in the search query and is therefore sent to the public search-engine website; do not use this workflow for identifiers you are not authorized to disclose. A result must be independently verified against the original disclosure source.</div></div>`;
  if(module==='credential'){
    let databases=[];try{databases=await api('/api/v1/authorized-databases');}catch{}
    const dbOptions=databases.flatMap(db=>db.tables.flatMap(table=>table.columns.map(col=>`<option value="${esc(JSON.stringify({connector:db.name,table:table.name,column:col}))}">${esc(db.name)} · ${esc(table.name)}.${esc(col)}</option>`))).join('');
    return `${heading('INTELLIGENCE MODULE','Credential & Exposure Intelligence','Local password hygiene and direct owner-authorized PostgreSQL lookups. No credential-provider APIs or leaked password downloads.')}<div class="panel"><div class="panel-title">Offline weak-password screening</div><p class="page-subtitle">Checks a candidate against built-in weak-password strings and predictable patterns. The password is never written to the database or sent to an external service. This is not a leaked-password corpus check.</p><div class="warning-box"><strong>ONLY CHECK CREDENTIALS YOU OWN OR ARE AUTHORIZED TO ASSESS.</strong>Candidate is sent to this application backend over HTTPS for one local calculation, then discarded.</div>${base}<div class="field"><label>Password candidate</label><input id="exposurePassword" type="password" autocomplete="off" maxlength="4096" /></div><div class="field"><label>Authorization context</label><textarea id="exposureAuthorization" placeholder="This is my password / supplied for an authorized password hygiene audit…"></textarea></div><button class="primary-button" data-action="run-password-exposure">Run local password hygiene check</button><div class="footer-note">A clean result means only that the candidate missed this small local weak-password list; it does not mean the password has never been breached.</div></div>
      <div class="panel"><div class="panel-title">Owner-authorized private database lookup</div><p class="page-subtitle">Direct PostgreSQL connection using a server-side read-only account. This is a database-driver connection, not a third-party API. Only configured allowlisted identifiers can be queried.</p><div class="warning-box"><strong>OWNER-CONFIGURED ACCESS ONLY</strong>Do not connect to databases without explicit owner authorization. Credentials remain in server environment variables; exact-match COUNT results only are returned.</div>${base.replaceAll('toolCase','dbCase')}<div class="field"><label>Target identifier</label><select id="dbTarget"><option value="">Select an investigation first</option></select></div><div class="field"><label>Allowed table and column</label><select id="dbChoice"><option value="">${dbOptions?'Select configured field':'No authorized database connector configured'}</option>${dbOptions}</select></div><div class="field"><label>Authorization context</label><textarea id="dbAuthorization" placeholder="Database owner, approved scope, ticket or engagement reference…"></textarea></div><button class="primary-button" data-action="run-db-lookup" ${dbOptions?'':'disabled'}>Run read-only lookup</button><div class="footer-note">${databases.length?`${databases.length} server-configured connector(s) available.`:'No authorized database connector configured. Add an owner-approved PostgreSQL connector to AUTHORIZED_DATABASES_JSON.'}</div></div>`;
  }
  return `${heading('INTELLIGENCE MODULE',item?.[1]||module,item?.[2]||'Module overview')}<div class="panel"><div class="panel-title">Module Status</div><p class="page-subtitle">This module is integrated into the shared investigation workflow where supported. Collection results are stored against an investigation target and retain source evidence.</p><div class="warning-box"><strong>AUTHORIZED USE ONLY</strong>Run investigations only against targets and records you are authorized to assess.</div><div class="field"><label>Choose an investigation</label><select id="moduleCase"><option value="">Select case</option>${caseOptions}</select></div><button class="primary-button" data-action="go-case">Open Investigation</button></div><div class="panel"><div class="panel-title">Module Capabilities</div><ul style="font-size:11px;color:#9aacc3;line-height:2">${(item?.[2]||'').split('. ').filter(Boolean).map(x=>`<li>${esc(x)}</li>`).join('')}</ul><div class="footer-note">Some modules rely on local uploads or analyst-operated public search references. The application labels unsupported adapters explicitly and does not fabricate results.</div></div>`;
}
async function renderExposureLab(){
  const [datasets,cases]=await Promise.all([api('/api/v1/exposure-datasets'),api('/api/v1/investigations')]);
  const rows=datasets.map(d=>`<tr><td><strong>${esc(d.name)}</strong><div class="section-caption">${esc(d.source_label)}</div></td><td>${Number(d.row_count).toLocaleString()}</td><td class="mono">${esc(d.sha256.slice(0,18))}…</td><td>${fmtDate(d.created_at)}</td><td><button class="small-button danger-button" data-action="delete-exposure-dataset" data-id="${d.id}">Delete</button></td></tr>`).join('');
  const options=cases.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');
  const totalRows=datasets.reduce((n,d)=>n+Number(d.row_count||0),0);
  return `${heading('BREACH & EXPOSURE INTELLIGENCE','Exposure Dataset Lab','Import redacted, analyst-provided incident indexes and match authorized email, username or domain indicators. Raw secrets are rejected and identifiers are keyed-HMACed before storage.')}\n    <div class="grid stats-grid exposure-stats">${stat('INDEXED DATASETS',datasets.length,'Analyst-provided datasets')}${stat('INDEX ROWS',totalRows.toLocaleString(),'Redacted index rows')}${stat('RAW PASSWORDS','0','Never ingested')}${stat('EXTERNAL API KEYS','0','No third-party API dependency')}${stat('MATCH MODE','HMAC','Keyed identifier matching')}</div>
    <div class="grid two-col">
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Import a redacted exposure index</div><div class="panel-note">CSV ingestion · 5 MB · 20,000 rows maximum</div></div><span class="pill green">LOCAL PARSER</span></div>
        <form id="exposureImportForm">
          <div class="field"><label>Dataset name</label><input name="name" required minlength="2" maxlength="180" placeholder="Example: Synthetic breach disclosure index" /></div>
          <div class="field"><label>Source / provenance label</label><input name="source_label" required minlength="2" maxlength="180" placeholder="Example: University synthetic dataset" /></div>
          <div class="field"><label>Description (optional)</label><textarea name="description" maxlength="1000" placeholder="Collection period, provenance, validation notes…"></textarea></div>
          <div class="field"><label>CSV file</label><input name="file" type="file" accept=".csv,text/csv" required /></div>
          <div class="warning-box"><strong>REDACTED DATA ONLY</strong>Accepted columns: <code>email</code>, <code>username</code>, <code>domain</code>, <code>breach_name</code>, <code>breach_date</code>, <code>source_reference</code>. Passwords, hashes, tokens, cookies, credential pairs and raw dump columns are rejected.</div>
          <button class="primary-button" type="submit">Import & index dataset →</button>
        </form>
        <div class="footer-note"><a class="link" href="/static/exposure-index-template.csv" target="_blank" rel="noreferrer">Download CSV schema</a> · Raw upload bytes are parsed in memory and discarded after indexing. The source dataset itself is not retained.</div>
      </div>
      <div class="panel"><div class="panel-header"><div><div class="panel-title">Match an investigation target</div><div class="panel-note">Exact keyed-HMAC lookup · no raw index identifiers stored</div></div><span class="pill blue">DEFENSIVE ANALYSIS</span></div>
        <div class="field"><label>Investigation</label><select id="exposureCaseSelect"><option value="">Select investigation</option>${options}</select></div>
        <div class="field"><label>Target identifier</label><select id="exposureTargetSelect" disabled><option value="">Select an investigation first</option></select></div>
        <div class="field"><label>Authorization context</label><textarea id="exposureAuthorization" placeholder="Account owner consent, client engagement, class project scope…"></textarea></div>
        <button class="primary-button" data-action="run-exposure-check">Check imported indexes →</button>
        <div class="footer-note">Results disclose only masked identifiers, dataset provenance, incident labels and dates. A match is an analyst lead, not proof of compromise.</div>
      </div>
    </div>
    <div class="panel"><div class="panel-header"><div><div class="panel-title">Imported exposure indexes</div><div class="panel-note">${datasets.length} dataset(s) · ${totalRows.toLocaleString()} normalized source rows</div></div><span class="pill">HASHED AT REST</span></div>
      <div class="table-wrap"><table><thead><tr><th>Dataset</th><th>Rows</th><th>SHA-256 fingerprint</th><th>Imported</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="5">No datasets imported. Start with the supplied synthetic sample CSV.</td></tr>'}</tbody></table></div>
    </div>
    <div class="panel"><div class="panel-title">How the privacy-preserving index works</div><div class="grid module-grid exposure-steps"><div class="module-card"><div class="module-number">01 · INGEST</div><div class="module-name">Validate</div><div class="module-description">Strict CSV schema, UTF-8, row limits and forbidden-secret column rejection.</div></div><div class="module-card"><div class="module-number">02 · NORMALIZE</div><div class="module-name">Canonicalize</div><div class="module-description">Email, username and domain identifiers are normalized before processing.</div></div><div class="module-card"><div class="module-number">03 · PROTECT</div><div class="module-name">Keyed HMAC</div><div class="module-description">Identifiers become HMAC-SHA256 digests. Plain identifiers are not persisted.</div></div><div class="module-card"><div class="module-number">04 · CORRELATE</div><div class="module-name">Exact match</div><div class="module-description">Investigation targets are matched against indexed digests and audited.</div></div></div></div>`;
}

async function importExposureDataset(event){
  event.preventDefault();
  const form=event.target;
  const file=form.elements.file.files[0];
  if(!file)throw new Error('Choose a CSV file.');
  const body=new FormData(form);
  const result=await api('/api/v1/exposure-datasets',{method:'POST',body});
  toast(`Dataset indexed: ${result.row_count} rows, ${result.indicator_count} indicators.`);
  renderPage();
}

async function renderSources(){const rows=await api('/api/v1/sources');return `${heading('COLLECTION REGISTRY','Source Manager','Configured public sources and integration entry points. Status indicates configuration, not guaranteed availability.','<button class="secondary-button" data-action="add-source">＋ Add Source</button>')}<div class="panel"><div class="table-wrap"><table><thead><tr><th>Source</th><th>Category</th><th>Endpoint</th><th>Status</th><th>Description</th></tr></thead><tbody>${rows.map(s=>`<tr><td>${esc(s.name)}</td><td>${esc(s.category)}</td><td>${s.source_url?`<a class="link" href="${esc(s.source_url)}" target="_blank" rel="noreferrer">${esc(s.source_url)}</a>`:'—'}</td><td>${statusPill(s.status)}</td><td>${esc(s.description||'')}</td></tr>`).join('')||'<tr><td colspan="5">No sources configured.</td></tr>'}</tbody></table></div><div class="footer-note">Source Manager currently records endpoints and descriptions. Source-specific adapters are implemented where shown in the module results; adding a URL here does not automatically create a parser.</div></div>`;}
async function renderAudit(){const rows=await api('/api/v1/audit?limit=200');return `${heading('ACCOUNTABILITY','Audit Trail','Actions such as investigation creation, file uploads, credential creation and password reveal are recorded. Secret values are never written to audit entries.')}<div class="panel"><div class="table-wrap"><table><thead><tr><th>Action</th><th>Object</th><th>Object ID</th><th>Detail</th><th>Timestamp</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.action)}</td><td>${esc(r.object_type)}</td><td class="mono">${esc((r.object_id||'').slice(0,12))}</td><td>${esc(r.detail||'')}</td><td>${fmtDate(r.created_at)}</td></tr>`).join('')||'<tr><td colspan="5">No audit events yet.</td></tr>'}</tbody></table></div></div>`;}
function renderSettings(){return `${heading('SYSTEM CONFIGURATION','Settings','Deployment, access control and data-retention configuration.')}<div class="panel"><div class="panel-title">Workspace Access</div><div class="field"><label>Workspace Access Token (optional in local development)</label><input id="apiTokenInput" type="password" placeholder="Paste API_TOKEN configured by the deployment owner" autocomplete="off"/><div class="field-help">Token is held in sessionStorage for this browser tab only. Closing the tab clears it.</div></div><button class="primary-button" data-action="save-token">Apply Token</button></div><div class="panel"><div class="panel-title">Credential Protection</div><div class="warning-box"><strong>AUTHORIZED USE ONLY</strong>Credential records are encrypted at rest. Passwords are hidden by default, revealed only on explicit user action, and reveal events are audited. Keep the encryption key separate from database backups.</div><p class="page-subtitle">For network deployment, configure a strong API_TOKEN, set CREDENTIAL_ENCRYPTION_KEY, use HTTPS, restrict network access, and protect storage backups.</p></div><div class="panel"><div class="panel-title">System Paths</div><div class="kpi-row"><div class="kpi">Backend <b>FastAPI</b></div><div class="kpi">Database <b>SQLite default</b></div><div class="kpi">Collection <b>Async HTTP</b></div><div class="kpi">Build <b>1.5.0</b></div></div></div>`;}

function openModal(title,body,submitLabel='Save'){ $('#modalContent').innerHTML=`<div class="modal-head"><div class="modal-title">${esc(title)}</div><button class="close-button" data-action="close-modal">×</button></div>${body}<div class="modal-actions"><button class="secondary-button" data-action="close-modal">Cancel</button><button class="primary-button" data-action="modal-submit">${esc(submitLabel)}</button></div>`;$('#modalBackdrop').classList.remove('hidden'); }
function closeModal(){ $('#modalBackdrop').classList.add('hidden'); $('#modalContent').innerHTML=''; }
function newCaseModal(){openModal('Create Investigation',`<div class="field"><label>Investigation Name</label><input id="caseName" maxlength="180" placeholder="e.g. Lab Domain Assessment" required /></div><div class="field"><label>Description</label><textarea id="caseDescription" placeholder="Scope, objectives and notes"></textarea></div><div class="warning-box"><strong>AUTHORIZED USE ONLY</strong>Only submit public targets and assets that are within your authorized investigation scope.</div>`,'Create Case');$('#modalContent').dataset.form='new-case';}
function addTargetModal(){openModal('Add Investigation Target',`<div class="field"><label>Target Value</label><input id="targetValue" placeholder="example.com, email, username, IP, phone or URL" required /></div><div class="field"><label>Target Type</label><select id="targetType"><option value="">Auto-detect</option><option value="domain">Domain</option><option value="url">Website URL</option><option value="email">Email</option><option value="username">Username</option><option value="phone">Phone</option><option value="ip">IP Address</option><option value="name">Name</option></select></div>`,'Add Target');$('#modalContent').dataset.form='add-target';}
function credentialModal(){const inv=state.currentInvestigation;openModal('Add Authorized Credential',`<div class="warning-box"><strong>AUTHORIZED USE ONLY — SENSITIVE CREDENTIAL WARNING</strong>Only enter credentials explicitly provided for an authorized assessment. Passwords will be encrypted at rest and will not be written to logs or reports.</div><div class="field"><label>Identifier Type</label><select id="credentialType"><option value="email">Email</option><option value="username">Username</option></select></div><div class="field"><label>Email / Username</label><input id="credentialIdentifier" placeholder="analyst@example.com" required /></div><div class="field"><label>Password</label><div class="password-entry"><input id="credentialPassword" type="password" autocomplete="new-password" required /><button type="button" class="small-button" data-action="toggle-entry-password">Show</button></div><div class="field-help">Use Show only when your screen is private. The value is encrypted before storage and never included in reports.</div></div><div class="field"><label>Authorization Context</label><textarea id="credentialAuthorization" placeholder="Describe who supplied this credential and the authorized test context." required></textarea></div><div class="field"><label>Associated Target (optional)</label><select id="credentialTarget"><option value="">None</option>${(inv?.targets||[]).map(t=>`<option value="${t.id}">${esc(t.value)}</option>`).join('')}</select></div>`,'Encrypt & Save');$('#modalContent').dataset.form='add-credential';}
function sourceModal(){openModal('Add Public Source',`<div class="field"><label>Source Name</label><input id="sourceName" required /></div><div class="field"><label>Category</label><input id="sourceCategory" placeholder="search, domain, threat, code…" required /></div><div class="field"><label>Source URL</label><input id="sourceUrl" placeholder="https://example.org/" /></div><div class="field"><label>Description</label><textarea id="sourceDescription"></textarea></div><div class="field-help">This registers a source reference. A compatible collector/parser adapter is still required before automated extraction can use it.</div>`,'Add Source');$('#modalContent').dataset.form='add-source';}

async function modalSubmit(){const form=$('#modalContent').dataset.form;try{
  if(form==='new-case'){
    const name=$('#caseName').value.trim();if(name.length<2)throw new Error('Enter an investigation name.');const res=await api('/api/v1/investigations',{method:'POST',body:JSON.stringify({name,description:$('#caseDescription').value.trim()||null})});closeModal();state.investigationId=res.id;setPage('investigation');toast('Investigation created.');
  } else if(form==='add-target'){
    const value=$('#targetValue').value.trim();if(!value)throw new Error('Enter a target.');const typ=$('#targetType').value||null;const res=await api(`/api/v1/investigations/${state.investigationId}/targets`,{method:'POST',body:JSON.stringify({value,target_type:typ})});closeModal();toast(res.existing?'Target already exists.':'Target added.');renderPage();
  } else if(form==='add-credential'){
    const body={identifier_type:$('#credentialType').value,identifier_reference:$('#credentialIdentifier').value.trim(),password:$('#credentialPassword').value,authorization_context:$('#credentialAuthorization').value.trim(),target_id:$('#credentialTarget').value||null};if(!body.identifier_reference||!body.password||body.authorization_context.length<8)throw new Error('Complete all required fields and provide at least 8 characters of authorization context.');await api(`/api/v1/investigations/${state.investigationId}/credentials`,{method:'POST',body:JSON.stringify(body)});closeModal();toast('Credential encrypted and saved.');renderPage();
  } else if(form==='add-source'){
    const body={name:$('#sourceName').value.trim(),category:$('#sourceCategory').value.trim(),source_url:$('#sourceUrl').value.trim()||null,description:$('#sourceDescription').value.trim()||null};await api('/api/v1/sources',{method:'POST',body:JSON.stringify(body)});closeModal();toast('Source reference added.');renderPage();
  } else if(form==='collect'){
    const selected=$$('.collect-module:checked').map(x=>x.value);if(!selected.length)throw new Error('Select at least one module.');const targetId=$('#modalContent').dataset.targetId;closeModal();await runCollection(targetId,selected);
  }
}catch(e){toast(e.message,'error');}}

async function runCollection(targetId,modules=null){if(!confirm('CYBER X — AUTHORIZED USE ONLY\n\nCollection may query public sources and the target systems you selected. Continue only if you have permission and the target is within scope. Do not use private, stolen, leaked, or access-controlled data. Source availability and accuracy are not guaranteed. Continue?'))return;try{const r=await api(`/api/v1/investigations/${state.investigationId}/targets/${targetId}/collect`,{method:'POST',body:JSON.stringify({modules})});toast(`Collection queued: ${r.modules.length} modules.`);renderPage();pollJob(r.job_id);}catch(e){toast(e.message,'error');}}
function openCollectionModal(targetId,targetType){const defaults={email:['email','breach','search','digital_footprint','correlation'],username:['username','github','social','search','digital_footprint','correlation'],phone:['phone','search','digital_footprint','correlation'],domain:['domain','website','network','attack_surface','threat','search','correlation'],url:['website','domain','search','attack_surface','correlation'],ip:['ip','network','threat','correlation'],cidr:['network','threat','search','correlation'],file_hash:['threat','search','correlation'],name:['search','social','digital_footprint','correlation']};const selected=defaults[targetType]||['search','correlation'];const choices=MODULES.filter(m=>!['credential','image','document'].includes(m[0])).map(m=>`<label class="module-check"><input type="checkbox" class="collect-module" value="${m[0]}" ${selected.includes(m[0])?'checked':''}><span><b>${esc(m[1])}</b><small>${esc(m[2])}</small></span></label>`).join('');openModal('Select Collection Modules',`<div class="section-caption" style="margin-bottom:12px">Recommended modules are preselected for this target type. Credential, image and document workflows use manual records or uploads.</div><div class="module-check-grid">${choices}</div>`,'Run Collection');$('#modalContent').dataset.form='collect';$('#modalContent').dataset.targetId=targetId;}
function pollJob(jobId){let tries=0;const timer=setInterval(async()=>{tries++;try{const j=await api(`/api/v1/jobs/${jobId}`);if(j.status==='completed'||j.status==='partial'||j.status==='failed'){clearInterval(timer);toast(`Collection ${j.status}: ${j.findings_count} findings.`);if(state.page==='investigation')renderPage();}else if(tries>50){clearInterval(timer);}}catch(e){clearInterval(timer);}},1800);}
async function quickSearch(){const val=$('#quickTarget')?.value.trim();if(!val)throw new Error('Enter a target first.');const inv=await api('/api/v1/investigations',{method:'POST',body:JSON.stringify({name:`Quick Search — ${val.slice(0,80)}`,description:'Unified search investigation created from the command center.'})});const target=await api(`/api/v1/investigations/${inv.id}/targets`,{method:'POST',body:JSON.stringify({value:val})});state.investigationId=inv.id;setPage('investigation');setTimeout(()=>runCollection(target.id),250);}
async function bulkImport(){const lines=$('#bulkTargets').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);if(!lines.length)throw new Error('Paste at least one target.');const r=await api(`/api/v1/investigations/${state.investigationId}/bulk-targets`,{method:'POST',body:JSON.stringify(lines)});toast(`Imported ${r.added.length}; skipped ${r.skipped.length}; errors ${r.errors.length}.`);renderPage();}
async function showPassword(id){if(!confirm('SENSITIVE PASSWORD WARNING\n\nReveal this stored password only if you are authorized to view it. The reveal is recorded in the audit trail and will auto-hide after 30 seconds. Keep your screen private. Continue?'))return;try{const r=await api(`/api/v1/credentials/${id}/reveal`,{method:'POST'});if(state.page!=='investigation'){return;}state.revealed[id]=r.password;toast('Password revealed. Handle only within authorized scope.');renderPage();setTimeout(()=>{if(state.revealed[id]){state.revealed[id]=null;if(state.page==='investigation')renderPage();}},30000);}catch(e){toast(e.message,'error');}}
function hidePassword(id){state.revealed[id]=null;renderPage();}
async function downloadReport(format){try{let blob;if(format==='pdf'){const response=await fetch(`/api/v1/investigations/${state.investigationId}/report?format=pdf`,{headers:apiHeaders()});if(!response.ok){let body={};try{body=await response.json();}catch{}throw new Error(body.detail||`Request failed (${response.status})`);}blob=await response.blob();}else{const data=await api(`/api/v1/investigations/${state.investigationId}/report?format=${format}`);blob=new Blob([format==='json'?JSON.stringify(data,null,2):data],{type:format==='json'?'application/json':'text/html'});}const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`cyber-x-${state.investigationId}.${format}`;a.click();URL.revokeObjectURL(url);toast(`${format.toUpperCase()} report exported. Credentials are excluded.`);}catch(e){toast(e.message,'error');}}
function openInfoModal(title,body){$('#modalContent').innerHTML=`<div class="modal-head"><div class="modal-title">${esc(title)}</div><button class="close-button" data-action="close-modal">×</button></div>${body}<div class="modal-actions"><button class="primary-button" data-action="close-modal">Close</button></div>`;$('#modalBackdrop').classList.remove('hidden');}
async function showEvidenceVault(){const rows=await api(`/api/v1/investigations/${state.investigationId}/evidence`);const body=`<div class="table-wrap"><table><thead><tr><th>Type</th><th>SHA-256</th><th>Source</th><th>Collected</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${esc(x.evidence_type)}</td><td class="mono">${esc(x.sha256)}</td><td>${x.source_url?`<a class="link" href="${esc(x.source_url)}" target="_blank" rel="noreferrer">Open</a>`:'Local/derived evidence'}</td><td>${fmtDate(x.collected_at)}</td></tr>`).join('')||'<tr><td colspan="4">No evidence recorded.</td></tr>'}</tbody></table></div>`;openInfoModal(`Evidence Vault · ${rows.length} Records`,body);}
async function showTimeline(){const rows=await api(`/api/v1/investigations/${state.investigationId}/timeline`);const body=`<div>${rows.map(x=>`<div class="timeline-event"><div class="timeline-dot"></div><div class="timeline-time">${fmtDate(x.timestamp)} · ${esc(x.module)}</div><div class="timeline-title">${esc(x.event)}</div><div class="timeline-summary">${esc(x.summary)}</div>${x.source_url?`<a class="link" href="${esc(x.source_url)}" target="_blank" rel="noreferrer">Source ↗</a>`:''}</div>`).join('')||empty('No timeline events','Collect findings to build the investigation timeline.')}</div>`;openInfoModal(`Investigation Timeline · ${rows.length} Events`,body);}
async function uploadEvidence(event){event.preventDefault();const file=$('#evidenceFile').files[0];if(!file)throw new Error('Choose a file.');const fd=new FormData();fd.append('file',file);if($('#uploadTarget').value)fd.append('target_id',$('#uploadTarget').value);const r=await api(`/api/v1/investigations/${state.investigationId}/uploads`,{method:'POST',body:fd});toast(`Evidence stored. SHA-256: ${r.sha256.slice(0,16)}…`);renderPage();}

$('#pageContent').addEventListener('click',async e=>{const b=e.target.closest('[data-action],[data-page]');if(!b)return;const action=b.dataset.action;try{
  if(b.dataset.page){setPage(b.dataset.page);return;}
  if(action==='new-case')newCaseModal();
  else if(action==='close-modal')closeModal();
  else if(action==='modal-submit')await modalSubmit();
  else if(action==='open-case'){state.investigationId=b.dataset.id;setPage('investigation');}
  else if(action==='add-target')addTargetModal();
  else if(action==='add-credential')credentialModal();
  else if(action==='add-source')sourceModal();
  else if(action==='collect'){const target=state.currentInvestigation?.targets?.find(t=>t.id===b.dataset.target);openCollectionModal(b.dataset.target,target?.type||'name');}
  else if(action==='bulk-import')await bulkImport();
  else if(action==='refresh-case')renderPage();
  else if(action==='show-password')await showPassword(b.dataset.id);
  else if(action==='hide-password')hidePassword(b.dataset.id);
  else if(action==='delete-credential'){if(confirm('Delete this encrypted credential record?')){await api(`/api/v1/credentials/${b.dataset.id}`,{method:'DELETE'});delete state.revealed[b.dataset.id];toast('Credential record deleted.');renderPage();}}
  else if(action==='delete-exposure-dataset'){
    if(confirm('Delete this imported exposure index and all its keyed indicators?')){await api(`/api/v1/exposure-datasets/${b.dataset.id}`,{method:'DELETE'});toast('Exposure index deleted.');renderPage();}
  }
  else if(action==='run-exposure-check'){
    const caseId=$('#exposureCaseSelect').value,target_id=$('#exposureTargetSelect').value,authorization_context=$('#exposureAuthorization').value.trim();
    if(!caseId||!target_id||authorization_context.length<12)throw new Error('Select an investigation and target, then provide authorization context (at least 12 characters).');
    const r=await api(`/api/v1/investigations/${caseId}/exposure-check`,{method:'POST',body:JSON.stringify({target_id,authorization_context})});
    const body=r.matches.length?r.matches.map(m=>`<div class="target-card"><div><div class="target-value">${esc(m.breach_name||'Unspecified incident')}</div><div class="target-type">${esc(m.source_label)} · ${esc(m.masked_identifier)} · ${esc(m.breach_date||'Date not supplied')}</div>${m.source_reference?`<div class="section-caption"><a class="link" href="${esc(m.source_reference)}" target="_blank" rel="noreferrer">Open provenance reference ↗</a></div>`:''}</div></div>`).join(''):'<div class="empty-state"><strong>No indexed match</strong>This target did not match the currently imported redacted datasets. This does not prove absence from other breaches.</div>';
    openInfoModal(`Exposure Index Results · ${r.match_count} Match(es)`,`${body}<div class="footer-note">${esc(r.interpretation)}</div>`);
    toast(`Exposure index check complete: ${r.match_count} match(es).`);
  }
  else if(action==='run-public-breach-check'){
    const caseId=$('#toolCase').value,targetId=$('#breachTarget').value,authorization_context=$('#breachAuthorization').value.trim();
    if(!caseId||!targetId||authorization_context.length<12)throw new Error('Select an email target and provide an authorization context (at least 12 characters).');
    const r=await api(`/api/v1/investigations/${caseId}/targets/${targetId}/breach-check`,{method:'POST',body:JSON.stringify({authorization_context})});
    toast(`Public HTML search complete: ${r.reference_count} reference(s). Verify each source independently.`);renderPage();
  }
  else if(action==='run-password-exposure'){
    const caseId=$('#toolCase').value,password=$('#exposurePassword').value,authorization_context=$('#exposureAuthorization').value.trim();
    if(!caseId||!password||authorization_context.length<12)throw new Error('Select an investigation, enter a password candidate and provide authorization context.');
    const r=await api(`/api/v1/investigations/${caseId}/password-exposure-check`,{method:'POST',body:JSON.stringify({password,authorization_context})});
    $('#exposurePassword').value='';toast(r.is_common?'Matches the local weak-password checks. Change it.':'No match in this small local weak-password list.');renderPage();
  }
  else if(action==='run-db-lookup'){
    const caseId=$('#dbCase').value,target_id=$('#dbTarget').value,authorization_context=$('#dbAuthorization').value.trim(),selected=$('#dbChoice').value;
    if(!caseId||!target_id||!selected||authorization_context.length<12)throw new Error('Select case, target, allowed database field and authorization context.');
    const cfg=JSON.parse(selected);const r=await api(`/api/v1/investigations/${caseId}/database-lookups`,{method:'POST',body:JSON.stringify({...cfg,target_id,authorization_context})});
    toast(`Read-only lookup: ${r.match_count} exact match(es). No rows returned.`);renderPage();
  }
  else if(action==='report-json')await downloadReport('json');
  else if(action==='report-html')await downloadReport('html');
  else if(action==='report-pdf')await downloadReport('pdf');
  else if(action==='view-evidence')await showEvidenceVault();
  else if(action==='view-timeline')await showTimeline();
  else if(action==='quick-search')await quickSearch();
  else if(action==='module-open'){setPage('module',b.dataset.module);}
  else if(action==='go-case'){const id=$('#moduleCase').value;if(!id)throw new Error('Select an investigation.');state.investigationId=id;setPage('investigation');}
  else if(action==='save-token'){state.apiToken=$('#apiTokenInput').value.trim();if(!state.apiToken)throw new Error('Enter the workspace access token.');sessionStorage.setItem('cyberx-api-token',state.apiToken);toast('Workspace token applied to this tab.');renderPage();}
}catch(err){toast(err.message,'error');}});

async function populateTargetSelect(caseId, selectId, emailOnly=false){
  const select=$(`#${selectId}`);if(!select)return;
  select.innerHTML='<option value="">Loading targets…</option>';
  if(!caseId){select.innerHTML='<option value="">Select an investigation first</option>';return;}
  try{const inv=await api(`/api/v1/investigations/${caseId}`);const rows=(inv.targets||[]).filter(t=>!emailOnly||t.type==='email');select.innerHTML=`<option value="">Select target</option>${rows.map(t=>`<option value="${esc(t.id)}">${esc(t.value)} (${esc(t.type)})</option>`).join('')}`;if(!rows.length)select.innerHTML=`<option value="">${emailOnly?'No email targets in this investigation':'No targets in this investigation'}</option>`;}catch(e){select.innerHTML='<option value="">Unable to load targets</option>';}
}
$('#pageContent').addEventListener('change',e=>{
  if(e.target.id==='toolCase')populateTargetSelect(e.target.value,'breachTarget',true);
  if(e.target.id==='dbCase')populateTargetSelect(e.target.value,'dbTarget',false);
  if(e.target.id==='exposureCaseSelect')populateTargetSelect(e.target.value,'exposureTargetSelect',false);
});

$('#modalContent').addEventListener('click',e=>{const action=e.target.closest('[data-action]')?.dataset.action;if(action==='close-modal')closeModal();if(action==='modal-submit')modalSubmit();if(action==='toggle-entry-password'){const input=$('#credentialPassword');if(input){const show=input.type==='password';input.type=show?'text':'password';e.target.textContent=show?'Hide':'Show';}}});
$('#modalContent').addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT')e.preventDefault();});
$('#pageContent').addEventListener('submit',async e=>{if(e.target.id==='uploadForm'){try{await uploadEvidence(e);}catch(err){toast(err.message,'error');}}if(e.target.id==='exposureImportForm'){try{await importExposureDataset(e);}catch(err){toast(err.message,'error');}}});
$('#newCaseBtn').addEventListener('click',newCaseModal);$('#refreshBtn').addEventListener('click',()=>{Object.keys(state.revealed).forEach(id=>state.revealed[id]=null);renderPage();});
function hideAllRevealed(){const has=Object.values(state.revealed).some(Boolean);if(has){Object.keys(state.revealed).forEach(id=>state.revealed[id]=null);if(state.page==='investigation')renderPage();}}
window.addEventListener('blur',hideAllRevealed);document.addEventListener('visibilitychange',()=>{if(document.hidden)hideAllRevealed();});
$('#modalBackdrop').addEventListener('click',e=>{if(e.target.id==='modalBackdrop')closeModal();});

document.addEventListener('click',e=>{const b=e.target.closest('.nav-item[data-page]');if(b)setPage(b.dataset.page,b.dataset.module||null);});

(async()=>{try{await api('/health');$('#apiStatus').textContent='BACKEND ONLINE';}catch(e){$('#apiStatus').textContent='BACKEND OFFLINE';}await renderPage();})();
