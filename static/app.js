const state = {
  page: 'dashboard',
  module: null,
  token: sessionStorage.getItem('cyberx-api-token') || '',
  result: null,
  selected: []
};

const $ = (selector, root=document) => root.querySelector(selector);
const $$ = (selector, root=document) => [...root.querySelectorAll(selector)];

const MODULES = [
  ['username','Username Intelligence','Public profile references across supported sites.'],
  ['email','Email Intelligence','Email syntax context and domain DNS posture.'],
  ['phone','Phone Intelligence','Calling-prefix context; no subscriber lookup.'],
  ['domain','Domain Intelligence','DNS records and public certificate-transparency pages.'],
  ['ip','IP Intelligence','IP classification, reverse DNS and public routing references.'],
  ['social','Social Media Intelligence','Publicly indexed social profile references.'],
  ['website','Website Intelligence','Public page metadata, headers and technology hints.'],
  ['github','GitHub & Code Intelligence','Public GitHub profile and repository pages.'],
  ['network','Network Intelligence','Passive DNS and routing-page context; no port scanning.'],
  ['threat','Threat Intelligence','Public threat-reference pages; no automatic malicious verdict.'],
  ['breach','Public Incident References','Public incident disclosures only; no credential dumps.'],
  ['search','Search Engine Intelligence','Public HTML search results.'],
  ['attack_surface','Passive Attack Surface','Passive domain and website posture observations.'],
  ['digital_footprint','Digital Footprint','Cross-module public identity and infrastructure context.'],
  ['correlation','Entity Correlation','Lightweight result grouping within the current scan.']
];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  }[ch]));
}
function toast(message, error=false) {
  const stack=$('#toastStack');
  if(!stack) return;
  const node=document.createElement('div');
  node.className='toast'+(error?' error':'');
  node.textContent=message;
  stack.append(node);
  setTimeout(()=>node.remove(),3500);
}
function setStatus(text, online=false) {
  const node=$('#apiStatus');
  if(node) node.textContent=text;
  const dot=$('.status-dot');
  if(dot) dot.style.background=online?'#2dd4bf':'#ef4444';
}
function headers(extra={}) {
  const result={...extra};
  if(state.token) result['X-API-Token']=state.token;
  return result;
}
async function api(path, options={}) {
  const response=await fetch(path,{...options,headers:headers(options.headers||{})});
  const type=response.headers.get('content-type')||'';
  const data=type.includes('application/json')?await response.json():await response.text();
  if(!response.ok) {
    const error=new Error(data?.detail || data?.message || `Request failed (${response.status})`);
    error.status=response.status;
    throw error;
  }
  return data;
}
function heading(kicker,title,subtitle,action='') {
  return `<div class="page-heading"><div><div class="eyebrow">${esc(kicker)}</div><h1 class="page-title">${esc(title)}</h1><div class="page-subtitle">${esc(subtitle)}</div></div>${action}</div>`;
}
function authGate(message) {
  return `${heading('SECURE WORKSPACE','Access required','This deployment requires an operator access token.')}
    <div class="panel auth-gate"><div class="panel-title">Cyber X protected access</div>
      <p class="page-subtitle">Enter the API_TOKEN configured in the Vercel project environment variables.</p>
      <div class="field"><label>Workspace access token</label><input id="tokenInput" type="password" autocomplete="current-password" placeholder="Paste API_TOKEN"></div>
      <button class="primary-button" data-action="unlock">Unlock workspace →</button>
      <div class="footer-note">${esc(message||'Token required.')}</div>
    </div>`;
}
function selectedModules() {
  return state.selected.length ? state.selected : (state.module ? [state.module] : []);
}
function scanPanel() {
  const checks=MODULES.map(([id,name,desc])=>`
    <label class="module-card scan-module">
      <input type="checkbox" value="${id}" ${selectedModules().includes(id)?'checked':''}>
      <span><strong>${esc(name)}</strong><small>${esc(desc)}</small></span>
    </label>`).join('');
  return `
    <div class="panel scan-panel">
      <div class="panel-header"><div><div class="panel-title">Live Public-Source Scan</div><div class="panel-note">One target per scan · up to 8 modules · results are not saved.</div></div><span class="pill blue">MEMORY ONLY</span></div>
      <div class="quick-search"><input id="targetInput" value="${esc($('#targetInput')?.value||'')}" placeholder="Username, email, domain, IP, phone number or URL…"><button class="primary-button" data-action="scan">Run Scan →</button></div>
      <div class="panel-note" style="margin:8px 0 12px">Choose modules (leave all unchecked to use recommended modules).</div>
      <div class="module-grid">${checks}</div>
      <div class="footer-note">Only publicly accessible sources are queried. No login bypass, private databases, credential dumps, CAPTCHA evasion or active port scanning.</div>
    </div>`;
}
function renderDashboard() {
  const result=state.result;
  return `${heading('PUBLIC-SOURCE INTELLIGENCE','Command Center','Run a live OSINT collection and inspect source-linked observations.','<button class="secondary-button" data-action="clear">Clear results</button>')}
    ${scanPanel()}
    ${result?renderResults(result):`
      <div class="grid two-col">
        <div class="panel"><div class="panel-title">Stateless by design</div><p class="page-subtitle">Cyber X fetches permitted public pages, normalizes results in memory and returns them to this browser. It does not create accounts, investigations, history or a database.</p></div>
        <div class="panel"><div class="panel-title">Evidence discipline</div><p class="page-subtitle">Each observation includes its source when available. A missing result is not proof of absence, and public incident references are not proof of account compromise.</p></div>
      </div>`}`;
}
function renderResults(result) {
  const rows=(result.findings||[]).map((item,index)=>`
    <tr><td>${esc(item.module)}</td><td>${esc(item.finding_type)}</td>
      <td style="max-width:520px;white-space:pre-wrap;word-break:break-word">${esc(item.value)}</td>
      <td>${Math.round((item.confidence||0)*100)}%</td>
      <td>${safeLink(item.source_url)}</td><td>${esc(item.verification_status)}</td></tr>`).join('');
  const modules=(result.modules||[]).map(m=>`
    <div class="job-line"><span>${esc(m.label)}</span><span class="pill ${m.status==='completed'?'green':'amber'}">${esc(m.status)}</span></div>`).join('');
  return `
    <div class="panel results-panel">
      <div class="panel-header"><div><div class="panel-title">Scan Results</div><div class="panel-note">${esc(result.normalized_target)} · ${esc(result.target_type)} · ${esc(new Date(result.collected_at).toLocaleString())}</div></div>
        <div class="target-actions"><button class="secondary-button" data-action="export-json">JSON</button><button class="secondary-button" data-action="export-html">HTML</button></div>
      </div>
      <div class="grid stats-grid">
        ${stat('MODULES',result.summary.modules_requested,'Requested')}
        ${stat('COMPLETED',result.summary.modules_completed,'Collectors')}
        ${stat('UNAVAILABLE',result.summary.modules_unavailable,'Source errors/timeouts')}
        ${stat('FINDINGS',result.summary.findings,'Observations')}
      </div>
      <div class="panel-header"><div class="panel-title">Collector status</div></div>${modules}
      <div class="panel-header" style="margin-top:18px"><div><div class="panel-title">Observed findings</div><div class="panel-note">Source references are shown where available.</div></div></div>
      <div class="table-wrap"><table><thead><tr><th>Module</th><th>Finding</th><th>Observation</th><th>Confidence</th><th>Source</th><th>Status</th></tr></thead><tbody>${rows||'<tr><td colspan="6">No observations returned by selected sources.</td></tr>'}</tbody></table></div>
      <div class="warning-box"><strong>INTERPRETATION</strong><ul>${(result.limitations||[]).map(x=>'<li>'+esc(x)+'</li>').join('')}</ul></div>
    </div>`;
}
function safeLink(url) {
  if(!url) return '—';
  try {
    const parsed=new URL(url);
    if(!['http:','https:'].includes(parsed.protocol)) return '—';
    return `<a class="link" href="${esc(parsed.href)}" target="_blank" rel="noopener noreferrer">Open source ↗</a>`;
  } catch { return '—'; }
}
function stat(label,value,foot) {
  return `<div class="stat-card"><div class="stat-label">${esc(label)}</div><div class="stat-value">${esc(value)}</div><div class="stat-foot">${esc(foot)}</div></div>`;
}
function renderFramework() {
  return `${heading('COLLECTION CATALOG','OSINT Framework','Supported modules and their public-source collection boundaries.')}
    <div class="module-grid">${MODULES.map(([id,name,desc])=>`
      <button class="module-card" data-action="choose-module" data-module="${id}"><strong>${esc(name)}</strong><small>${esc(desc)}</small><span class="pill blue">Select module</span></button>`).join('')}</div>`;
}
function renderInfo(page) {
  const pages={
    investigations:['NO PERSISTENCE','Investigations removed','This version does not save investigation records or scan history. Run a scan from the Command Center and export results locally if needed.'],
    sources:['SOURCE POLICY','Public source collection','Collectors use public HTML pages and DNS lookups where supported. Source availability, robots.txt, rate limits and access restrictions are respected.'],
    audit:['NO SERVER HISTORY','Audit trail removed','No scan history or audit records are persisted by this stateless deployment.'],
    exposure:['NOT INCLUDED','Exposure Dataset Lab removed','This stateless version does not import datasets or query breach/password dumps. It only displays public incident references.'],
    settings:['WORKSPACE SETTINGS','Session controls','The access token is held in this browser tab session only. Clearing it locks the workspace again.']
  };
  const [kicker,title,body]=pages[page]||pages.settings;
  return `${heading(kicker,title,body)}<div class="panel"><div class="panel-title">Session</div><button class="secondary-button" data-action="lock">Clear access token</button></div>`;
}
async function renderPage() {
  const root=$('#pageContent');
  const labels={dashboard:'Command Center',framework:'OSINT Framework',investigations:'Investigations',sources:'Source Manager',audit:'Audit Trail',exposure:'Exposure Dataset Lab',settings:'Settings',module:MODULES.find(m=>m[0]===state.module)?.[1]||'Intelligence'};
  $('#pageCrumb').textContent=labels[state.page]||'Workspace';
  if(state.page==='dashboard'||state.page==='module') root.innerHTML=renderDashboard();
  else if(state.page==='framework') root.innerHTML=renderFramework();
  else root.innerHTML=renderInfo(state.page);
  $$('.nav-item[data-page]').forEach(node=>node.classList.toggle('active',node.dataset.page===state.page&&(state.page!=='module'||node.dataset.module===state.module)));
  if(state.page==='module') {
    state.selected=[state.module];
    const input=$('#targetInput');
    if(input) input.focus();
  }
}
function download(name,content,type) {
  const blob=new Blob([content],{type});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement('a');
  anchor.href=url; anchor.download=name; anchor.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function exportHtml(result) {
  const rows=(result.findings||[]).map(f=>`<tr><td>${esc(f.module)}</td><td>${esc(f.finding_type)}</td><td>${esc(f.value)}</td><td>${esc(f.source_url||'')}</td></tr>`).join('');
  return `<!doctype html><html><meta charset="utf-8"><title>Cyber X OSINT Report</title><body><h1>Cyber X OSINT Report</h1><p>Target: ${esc(result.normalized_target)} (${esc(result.target_type)})</p><p>Collected: ${esc(result.collected_at)}</p><table border="1" cellpadding="6"><thead><tr><th>Module</th><th>Finding</th><th>Observation</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table><p>Generated locally. Results are transient and not server-stored.</p></body></html>`;
}
async function runScan() {
  const target=$('#targetInput')?.value.trim();
  if(!target) { toast('Enter a target first.',true); return; }
  const checks=$$('#pageContent input[type="checkbox"]:checked').map(x=>x.value);
  const button=$('[data-action="scan"]');
  if(button) { button.disabled=true; button.textContent='Collecting…'; }
  try {
    const result=await api('/api/v1/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,modules:checks.length?checks:undefined})});
    state.result=result;
    state.page='dashboard'; state.module=null; state.selected=[];
    setStatus('BACKEND ONLINE',true);
    renderPage();
    toast(`Scan complete: ${result.summary.findings} finding(s).`);
  } catch(error) {
    if(error.status===401||error.status===503) $('#pageContent').innerHTML=authGate(error.message);
    else toast(error.message,true);
  } finally {
    const current=$('[data-action="scan"]');
    if(current) { current.disabled=false; current.textContent='Run Scan →'; }
  }
}

document.addEventListener('click',async event=>{
  const nav=event.target.closest('.nav-item[data-page]');
  if(nav) {
    state.page=nav.dataset.page; state.module=nav.dataset.module||null;
    if(state.page==='module') state.selected=[state.module];
    renderPage(); return;
  }
  const button=event.target.closest('[data-action]');
  if(!button) return;
  const action=button.dataset.action;
  if(action==='scan') return runScan();
  if(action==='unlock') {
    const token=$('#tokenInput')?.value.trim();
    if(!token) return toast('Enter the workspace token.',true);
    state.token=token; sessionStorage.setItem('cyberx-api-token',token);
    try { await api('/api/v1/modules'); setStatus('BACKEND ONLINE',true); renderPage(); toast('Workspace unlocked.'); }
    catch(error) { state.token='';sessionStorage.removeItem('cyberx-api-token');$('#pageContent').innerHTML=authGate(error.message); }
  }
  if(action==='clear') { state.result=null;state.selected=[];renderPage(); }
  if(action==='choose-module') { state.page='module';state.module=button.dataset.module;state.selected=[state.module];renderPage(); }
  if(action==='export-json'&&state.result) download('cyber-x-osint-report.json',JSON.stringify(state.result,null,2),'application/json');
  if(action==='export-html'&&state.result) download('cyber-x-osint-report.html',exportHtml(state.result),'text/html');
  if(action==='lock') { state.token='';sessionStorage.removeItem('cyberx-api-token');$('#pageContent').innerHTML=authGate('Session token cleared.'); }
});

$('#refreshBtn')?.addEventListener('click',()=>renderPage());
$('#newCaseBtn')?.addEventListener('click',()=>{state.page='dashboard';state.module=null;state.result=null;state.selected=[];renderPage();});
document.addEventListener('keydown',event=>{
  if(event.key==='Enter'&&event.target.id==='targetInput') runScan();
});

(async()=>{
  try {
    await fetch('/health').then(r=>{if(!r.ok)throw new Error('offline');return r.json();});
    setStatus('BACKEND ONLINE',true);
  } catch { setStatus('BACKEND OFFLINE',false); }
  try { await renderPage(); }
  catch(error) { $('#pageContent').innerHTML=authGate(error.message); }
})();
