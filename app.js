'use strict';
const $=s=>document.querySelector(s);
let findings=[],evidence=[],attentionFlags=[],vulnerabilityMatches=[],vulnerabilityCatalog=null,toolCatalog=[],map={targets:[],candidates:[]},previewPayload=null,toastTimer;
const runResults=new Map();
let currentSuggestions=[];
let autoPlan=null,autoRunning=false,autoStop=false,autoCurrentCheck='',autoStartedAt=null;
const autoKinds=['ping','nmap-ports','nmap-service','http-headers','ssh-hostkey','dns-ptr'];
function checkOutcome(result){return result.outcome==='no-response'?'No response':result.outcome==='completed'?'Completed':result.outcome==='failed'?'Failed':result.ok?'Completed':'Failed';}
let emailContacts=[],emailDrafts=[],activeDraft=null,draftDirty=false,draftBusy=false;
const views={drafts:'Prepare, review, and save email drafts. Sender infrastructure can be configured later.',scope:'Define and save the authorized target ranges and domains before working with evidence or checks.',briefing:'Review what the saved evidence supports and ask grounded follow-up questions.',review:'Import output, inspect linked evidence, and correct findings.',checks:'Review grounded checks, then run a check against an authorized local target.',autonomy:'See exactly what the AI chose, what Yagura executed, and why it stopped.',triage:'Choose a host for deeper investigation from saved, linked evidence.'};
const viewTitles={scope:'Scope',briefing:'Briefing',review:'Findings',checks:'Next checks',drafts:'Email drafts',autonomy:'AI investigation',triage:'Deep-dive candidates'};
const aiViews=new Set(['autonomy','triage','briefing']),manualViews=new Set(['checks','drafts']);
let workflowMode='ai';
try{workflowMode=localStorage.getItem('yagura-workflow-mode')==='manual'?'manual':'ai';}catch{}
function applyWorkflowMode(){document.body.dataset.workflowMode=workflowMode;document.querySelectorAll('[data-workflow-switch]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.workflowSwitch===workflowMode)));$('#workflowModeHint').textContent=(workflowMode==='ai'?'Yagura chooses follow-up checks within the saved scope. You approve each run. Validated catalog commands run automatically; unlisted tools need review.':'Choose and review each check yourself. Optional AI suggestions and a previewed short sequence are available.')+' Switching modes does not stop an active run.';}
function switchWorkflowMode(mode){if(mode!==workflowMode){workflowMode=mode;try{localStorage.setItem('yagura-workflow-mode',mode);}catch{}}location.hash=mode==='ai'?'#autonomy':'#checks';showView();}
document.querySelectorAll('[data-workflow-switch]').forEach(button=>button.onclick=()=>switchWorkflowMode(button.dataset.workflowSwitch));
let latestAnalysis=null,briefingMessages=[],briefingContextKey='',briefingBusy=false,briefingSavedCandidates=[],briefingSavedResults={};
let autonomyInventoryReady=false,autonomyModelRequired=false,autonomyMode='group',autonomyLimits={maxSeconds:600,groupMaxSeconds:900};
const autonomySelectedHosts=new Set();
const emptyScope=()=>({cidrs:[],domains:[],matchMode:'and'});
let savedScope=emptyScope(),scopeLoaded=false,scopeLoadError='';
let stopDiscovery=false;
const scopeLabel=()=>[savedScope.cidrs.join(', '),savedScope.domains.length?`${(savedScope.matchMode||'and').toUpperCase()} domains: `+savedScope.domains.join(', '):''].filter(Boolean).join(' · ');
function showView(){const hash=location.hash.slice(1);const view=hash==='recon'?'scope':hash==='analysis'?'triage':hash;const selected=views[view]?view:'scope';if(selected!=='autonomy'&&$('#autonomyNewRun')?.open)$('#autonomyNewRun').close();if(selected!=='triage'&&$('#analysisNewDialog')?.open)$('#analysisNewDialog').close();if(aiViews.has(selected))workflowMode='ai';else if(manualViews.has(selected))workflowMode='manual';try{localStorage.setItem('yagura-workflow-mode',workflowMode);}catch{}applyWorkflowMode();document.body.dataset.view=selected;$('#viewTitle').textContent=viewTitles[selected];document.title=viewTitles[selected]+' · Yagura';$('#viewIntro').textContent=views[selected];document.querySelectorAll('.nav a,.mobile-nav a').forEach(a=>{const active=a.hash==='#'+selected;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});updateScopeGate();window.scrollTo(0,0);if(selected==='briefing')requestAnimationFrame(boxScroll);}
function updateScopeGate(){
  const ready=scopeLoaded&&savedScope.cidrs.length>0;
  document.body.dataset.scopeState=ready?'ready':scopeLoaded?'required':scopeLoadError?'error':'loading';
  $('#scopeGate').hidden=document.body.dataset.view==='scope'||ready;
  $('#scopeGateTitle').textContent=scopeLoadError?'Target scope could not be loaded':!scopeLoaded?'Loading target scope…':'Define the target scope first';
  $('#scopeGateMessage').textContent=scopeLoadError?'The saved scope could not be verified. Open Scope and refresh to retry. '+scopeLoadError:!scopeLoaded?'Checking the saved engagement scope.':`Save an authorized target range to continue in ${workflowMode==='ai'?'AI investigation':'Next checks'}. This server’s network is not the target network.`;
  $('#savedScopeDisplay').textContent=scopeLabel()||'Not defined';
  $('#scanBtn').disabled=!ready;
  $('#seedBtn').disabled=!ready||savedScope.matchMode!=='or'||!savedScope.domains.length;
  const scanState=$('#scanState');if(!ready||scanState.textContent.startsWith('Save the target scope')||scanState.textContent.startsWith('Saved scope:'))scanState.textContent=ready?'Saved scope: '+scopeLabel()+'. Select a discovery action to review and confirm it.':'Save the target scope before running discovery.';
}
window.addEventListener('hashchange',showView);showView();
const reviewTabs=[...document.querySelectorAll('.review-tabs [role="tab"]')];
function setReviewTab(name,focus=false){
  const requested=name==='hosts'?'web':name;
  const selected=reviewTabs.some(tab=>tab.dataset.reviewTab===requested)?requested:'overview';
  reviewTabs.forEach(tab=>{const active=tab.dataset.reviewTab===selected;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;if(active&&focus)tab.focus();});
  document.querySelectorAll('[data-review-panel]').forEach(panel=>{panel.hidden=panel.dataset.reviewPanel!==selected;});
  try{sessionStorage.setItem('yagura-review-tab',selected);}catch{}
}
let initialReviewTab='overview';try{initialReviewTab=sessionStorage.getItem('yagura-review-tab')||'overview';}catch{}
setReviewTab(initialReviewTab);
reviewTabs.forEach((tab,index)=>{tab.onclick=()=>setReviewTab(tab.dataset.reviewTab);tab.onkeydown=event=>{let next;if(event.key==='ArrowRight')next=(index+1)%reviewTabs.length;else if(event.key==='ArrowLeft')next=(index+reviewTabs.length-1)%reviewTabs.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=reviewTabs.length-1;else return;event.preventDefault();setReviewTab(reviewTabs[next].dataset.reviewTab,true);};});
function openImport(){location.hash='#review';showView();setReviewTab('findings');if(!checkScope()||!scopeLoaded)return;renderToolImportHost();if(!$('#importPanel').open)$('#importPanel').showModal();$('#importTool').focus();}
document.addEventListener('click',event=>{if(event.target.closest('[data-open-import]'))openImport();});
$('#importNewOpen').onclick=openImport;$('#importClose').onclick=()=>$('#importPanel').close();
$('#discoveryNewOpen').onclick=()=>$('#discoveryNewDialog').showModal();$('#discoveryNewClose').onclick=()=>$('#discoveryNewDialog').close();
let workspaceReady=false;
function updatePrerequisites(){
  const hasFindings=workspaceReady&&scopeLoaded&&!!checkScope()&&findings.length>0;
  $('#analyzeBtn').disabled=!hasFindings;
  $('#analysisPrerequisite').hidden=hasFindings;
  $('#analysisPrerequisite').innerHTML=workspaceReady?'No findings to analyze yet. <button class="ref" data-open-import>Import output</button> or <a href="#scope">discover hosts</a> first.':'Findings are unavailable. Refresh the workspace to retry.';
  const eligible=workspaceReady&&checkScope()&&map.candidates.length>0;
  $('#suggestBtn').disabled=!eligible;
  $('#checksPrerequisite').hidden=!!eligible;
  $('#checksPrerequisite').innerHTML=!workspaceReady?'Check prerequisites are unavailable. Refresh the workspace to retry.':!checkScope()?'Set an <a href="#scope">authorized range in Scope</a> before selecting checks.':!findings.length?'No findings recorded. <button class="ref" data-open-import>Import output</button> or <a href="#scope">discover hosts</a> first.':'No checks are available for the recorded hosts in this range. Review <a href="#review">target evidence</a> or <a href="#scope">change the range</a>.';
}
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.classList.remove('show'),3500);}
async function api(url,options={}){const r=await fetch(url,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});const d=await r.json().catch(()=>null);if(!r.ok){const missingApi=r.status===404&&(!d||d.error==='Not found.');const error=new Error(missingApi?`Yagura API is unavailable at ${location.origin}. Run python3 main.py on the machine serving this page and open its configured app address.`:d?.error||`Request failed (HTTP ${r.status}).`);error.message+=` (${url})`;error.status=r.status;throw error;}if(!d)throw new Error('The server returned an invalid API response. Check that this page is served by Yagura.');return d;}
const post=(url,data)=>api(url,{method:'POST',body:JSON.stringify(data)});
const checkScope=()=>savedScope.cidrs.length?savedScope:null;
const showScope=()=>{$('#checksScopeDisplay').textContent=scopeLabel()||'No range set';};
let scopeSave=Promise.resolve();
async function saveScope(clear=false){
  const split=value=>value.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean);
  const value=clear?emptyScope():{cidrs:split($('#cidrs').value),domains:split($('#domains').value),matchMode:$('#matchMode').value};
  if(!clear&&!value.cidrs.length)throw new Error('Enter at least one authorized target IPv4 range.');
  scopeSave=scopeSave.catch(()=>{}).then(()=>api('/api/scope',{method:'PUT',body:JSON.stringify(value)}));
  const result=await scopeSave;
  savedScope=result;scopeLoaded=true;scopeLoadError='';$('#cidrs').value=savedScope.cidrs.join('\n');$('#domains').value=savedScope.domains.join('\n');$('#matchMode').value=savedScope.matchMode||'and';$('#scanTarget').value=savedScope.cidrs[0]||'';
  $('#scanResults').innerHTML='';
  showScope();if($('#scopeEditor').open)$('#scopeEditor').close();updateScopeGate();updatePrerequisites();clearAutoPlan('Target scope changed. Preview checks again.');
  $('#scopeState').textContent=checkScope()?'Saved target scope: '+scopeLabel()+'. Other workflow sections are now available.':'Scope cleared. Save a target range to continue.';
  if(checkScope()){location.hash=workflowMode==='ai'?'#autonomy':'#checks';showView();}
  await refreshFindings();if(checkScope())await loadPendingDiscovery();return result;
}
async function persistScope(clear=false){const split=value=>value.split(/[\s,]+/).filter(Boolean);const description=clear?'Clear the saved target scope and disable target checks.':`Save these approved ranges: ${esc(split($('#cidrs').value).join(', ')||'None')} · Domains: ${esc(split($('#domains').value).join(', ')||'None')} · Match: ${esc($('#matchMode').value.toUpperCase())}.`;if(!await confirmAction(clear?'Clear target scope?':'Save target scope?',`<p>${description}</p>`,clear?'Clear scope':'Save scope'))return;const button=$('#saveScope');button.disabled=true;$('#clearScope').disabled=true;try{await saveScope(clear);toast(clear?'Target scope cleared':'Target scope saved');}catch(e){$('#scopeState').textContent=e.message;}finally{button.disabled=false;$('#clearScope').disabled=false;}}
$('#scopeEditOpen').onclick=()=>$('#scopeEditor').showModal();$('#scopeEditClose').onclick=()=>$('#scopeEditor').close();
$('#saveScope').onclick=()=>persistScope();$('#clearScope').onclick=()=>persistScope(true);

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function date(s){return s?new Date(s).toLocaleString():'';}
function ref(id,label){return `<button class="ref" data-ref="${esc(id)}">${esc(label)}</button>`;}
function evidenceLinks(ids){return (ids||[]).map(id=>ref(id,evidence.find(e=>e.id===id)?.command || 'Source evidence')).join(' · ');}
function recordLabel(f){const h=findings.find(x=>x.id===f.hostId);return f.kind==='host'?`${f.ip}${f.name?' · '+f.name:''}`:f.kind==='service'?`${h?.ip||'Host'} · ${f.port}/${f.protocol} ${f.name||''}`:f.title;}
function wireRefs(parent){parent.querySelectorAll('[data-ref]').forEach(b=>b.onclick=()=>showRecord(b.dataset.ref));}
function showDialog(title,body){$('#dialogTitle').textContent=title;$('#dialogBody').innerHTML=body;if(!$('#reviewDialog').open)$('#reviewDialog').showModal();wireRefs($('#dialogBody'));}
function confirmAction(title,details,confirmLabel='Confirm'){
  const dialog=$('#actionConfirmDialog');
  if(dialog.open)return Promise.resolve(false);
  $('#actionConfirmTitle').textContent=title;
  $('#actionConfirmDetails').innerHTML=details;
  $('#actionConfirmAccept').textContent=confirmLabel;
  return new Promise(resolve=>{
    let accepted=false;
    $('#actionConfirmAccept').onclick=()=>{accepted=true;dialog.close();};
    $('#actionConfirmCancel').onclick=()=>dialog.close();
    dialog.onclose=()=>{dialog.onclose=null;resolve(accepted);};
    dialog.showModal();
    $('#actionConfirmCancel').focus();
  });
}
function confirmScopedAction(title,description,confirmLabel='Confirm',showScope=true){
  return confirmAction(title,`<p>${description}</p>${showScope?`<p class="status">Scope: ${esc(scopeLabel()||'Not defined')}</p>`:''}`,confirmLabel);
}
$('#closeDialog').onclick=()=>$('#reviewDialog').close();
function showRecord(id){
  const e=evidence.find(x=>x.id===id);
  if(e){showDialog('Source evidence',`<p class="mono">${esc(e.command)}</p><p class="notice">${esc(e.tool)} · ${esc(e.format)} · Observed ${esc(date(e.observedAt))} · Imported ${esc(date(e.importedAt))}</p><pre>${esc(e.output)}</pre>`);return;}
  const f=findings.find(x=>x.id===id);if(!f)return;
  showDialog(recordLabel(f),`<p class="notice">${esc(f.kind)} · ${esc(f.reviewStatus)} · First seen ${esc(date(f.firstSeen))} · Last seen ${esc(date(f.lastSeen))}</p><pre>${esc(f.detail||JSON.stringify(Object.fromEntries(Object.entries(f).filter(([k])=>!['id','evidenceIds','createdAt','updatedAt'].includes(k))),null,2))}</pre><p>${f.hostId?ref(f.hostId,'Linked host'):''} ${f.serviceId?ref(f.serviceId,'Linked service'):''}</p><p>${evidenceLinks(f.evidenceIds)}</p><button class="btn" id="detailEdit">Edit / mark reviewed</button>`);
  $('#detailEdit').onclick=()=>editRecord(f.id);
}
const findingTreeOpen=new Set();
let findingTreeInitialized=false;
function rememberFindingTree(){
  $('#findingList').querySelectorAll('details[data-tree-id]').forEach(node=>{
    if(node.open)findingTreeOpen.add(node.dataset.treeId);
    else findingTreeOpen.delete(node.dataset.treeId);
  });
}
function findingRecord(f,showLabel=true){
  const summary=f.kind==='service'?`${f.state||'unknown'} · ${f.product||''} ${f.version||''}`:f.kind==='host'?`${f.state||'unknown'}${f.local?' · local interface':''}`:(f.detail||'').slice(0,180);
  return `<div class="finding-record"><div class="item-left">${showLabel?`<strong>${ref(f.id,recordLabel(f))}</strong>`:`<strong>${ref(f.id,'View details & evidence')}</strong>`}<small>${esc(summary)}</small><small>${esc(date(f.lastSeen))} · <span class="${f.reviewStatus==='reviewed'?'reviewed':''}">${esc(f.reviewStatus||'unreviewed')}</span> · ${(f.evidenceIds||[]).length} source(s)</small></div><span class="kind">${esc(f.kind)}</span><details class="record-actions"><summary aria-label="Actions for ${esc(recordLabel(f))}" title="Actions">⋯</summary><div class="record-actions-menu"><button class="btn" data-edit="${esc(f.id)}">Edit</button><button class="btn" data-merge="${esc(f.id)}">Merge</button><button class="btn" data-delete="${esc(f.id)}">Delete</button></div></details></div>`;
}
function renderFindings(){
  rememberFindingTree();
  const box=$('#findingList'),filter=$('#findingFilter').value,query=$('#findingSearch').value.trim().toLocaleLowerCase();
  const byId=new Map(findings.map(f=>[f.id,f]));
  const hosts=findings.filter(f=>f.kind==='host').sort((a,b)=>String(a.ip||a.name||'').localeCompare(String(b.ip||b.name||''),undefined,{numeric:true}));
  const services=findings.filter(f=>f.kind==='service').sort((a,b)=>Number(a.port||0)-Number(b.port||0)||String(a.protocol||'').localeCompare(String(b.protocol||'')));
  const observations=findings.filter(f=>f.kind==='observation').sort((a,b)=>String(b.lastSeen||'').localeCompare(String(a.lastSeen||'')));
  const textMatch=f=>[f.ip,f.name,f.port,f.protocol,f.product,f.version,f.title,f.detail,f.state].some(v=>String(v??'').toLocaleLowerCase().includes(query));
  const parentOf=f=>{
    const service=byId.get(f.serviceId),host=byId.get(f.hostId);
    return f.kind==='observation'?(service?.kind==='service'?service:host?.kind==='host'?host:null):f.kind==='service'&&host?.kind==='host'?host:null;
  };
  const matches=f=>{
    if(filter==='unreviewed'&&f.reviewStatus==='reviewed')return false;
    if(filter!=='all'&&filter!=='unreviewed'&&f.kind!==filter)return false;
    if(!query)return true;
    const seen=new Set();
    for(let node=f;node&&!seen.has(node.id);node=parentOf(node)){if(textMatch(node))return true;seen.add(node.id);}
    return false;
  };
  const selected=findings.filter(matches),visible=new Set(selected.map(f=>f.id));
  for(const f of selected){const seen=new Set([f.id]);for(let parent=parentOf(f);parent&&!seen.has(parent.id);parent=parentOf(parent)){visible.add(parent.id);seen.add(parent.id);}}
  if(!findingTreeInitialized&&findings.length){
    const first=hosts.find(h=>visible.has(h.id));
    if(first){findingTreeOpen.add(`host:${first.id}`);const service=services.find(s=>s.hostId===first.id&&visible.has(s.id));if(service)findingTreeOpen.add(`service:${service.id}`);}
    findingTreeInitialized=true;
  }
  const expanded=Boolean(query)||filter==='observation'||filter==='service'||filter==='unreviewed';
  const branch=(key,title,count,content)=>`<details class="finding-branch" data-tree-id="${esc(key)}" ${expanded||findingTreeOpen.has(key)?'open':''}><summary><span class="finding-name">${esc(title)}</span><span class="finding-summary-count">${esc(count)}</span></summary><div class="finding-children">${content}</div></details>`;
  const observationRows=parent=>observations.filter(o=>visible.has(o.id)&&(o.serviceId&&byId.get(o.serviceId)?.kind==='service'?o.serviceId===parent.id:parent.kind==='host'&&o.hostId===parent.id));
  const countLabel=(n,word)=>`${n} ${word}${n===1?'':'s'}`;
  const serviceTree=s=>{const obs=observationRows(s);return branch(`service:${s.id}`,`${s.port}/${s.protocol} · ${s.name||'unknown'}`,countLabel(obs.length,'observation'),findingRecord(s,false)+obs.map(o=>findingRecord(o)).join(''));};
  const hostTree=h=>{const childServices=services.filter(s=>visible.has(s.id)&&s.hostId===h.id),obs=observationRows(h);return branch(`host:${h.id}`,recordLabel(h),`${countLabel(childServices.length,'service')} · ${countLabel(obs.length+childServices.reduce((n,s)=>n+observationRows(s).length,0),'observation')}`,findingRecord(h,false)+childServices.map(serviceTree).join('')+obs.map(o=>findingRecord(o)).join(''));};
  const linkedServices=new Set(services.filter(s=>byId.get(s.hostId)?.kind==='host').map(s=>s.id));
  const orphans=[...services.filter(s=>visible.has(s.id)&&!linkedServices.has(s.id)),...observations.filter(o=>visible.has(o.id)&&!parentOf(o))];
  const orphanTree=orphans.length?branch('unlinked','Unlinked records',countLabel(orphans.length,'record'),orphans.map(f=>f.kind==='service'?serviceTree(f):findingRecord(f)).join('')):'';
  $('#findingCount').textContent=`${selected.length} shown / ${findings.length} records · ${findings.filter(f=>f.reviewStatus!=='reviewed').length} need review`;
  box.innerHTML=selected.length?hosts.filter(h=>visible.has(h.id)).map(hostTree).join('')+orphanTree:findings.length?'<div class="empty">No matching findings. Change the search or filter.</div>':'<div class="empty">No findings yet. <button class="ref" data-open-import>Import command output</button> or <a href="#scope">discover hosts in Scope</a>.</div>';
  wireRefs(box);box.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editRecord(b.dataset.edit));box.querySelectorAll('[data-merge]').forEach(b=>b.onclick=()=>mergeRecord(b.dataset.merge));box.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>deleteRecord(b.dataset.delete));
}
function renderAttention(){
  $('#attentionCount').textContent=`${attentionFlags.length} flag${attentionFlags.length===1?'':'s'}`;
  const byId=new Map(findings.map(f=>[f.id,f]));
  const box=$('#attentionList');
  const grouped=new Map();for(const flag of attentionFlags){if(!grouped.has(flag.hostId))grouped.set(flag.hostId,[]);grouped.get(flag.hostId).push(flag);}
  const row=flag=>{
    const service=byId.get(flag.serviceId);
    const source=(flag.findingIds||[]).map(id=>ref(id,recordLabel(byId.get(id)||{title:id}))).join(' · ');
    return `<div class="finding-record"><div class="item-left"><strong>${esc(flag.title)}</strong>${service?`<small>${ref(service.id,recordLabel(service))}</small>`:''}<p>${esc(flag.reason)}</p><small>Findings: ${source}</small><small>Evidence: ${evidenceLinks(flag.evidenceIds)}</small></div><span class="kind">${esc(flag.kind)}</span></div>`;
  };
  box.innerHTML=attentionFlags.length?[...grouped].map(([hostId,flags])=>{const host=byId.get(hostId);return `<details class="finding-branch"><summary><span class="finding-name">${esc(recordLabel(host||{title:hostId}))}</span><span class="finding-summary-count">${flags.length} flag${flags.length===1?'':'s'}</span></summary><div class="finding-children">${host?`<p>${ref(host.id,'Open host evidence')}</p>`:''}${flags.map(row).join('')}</div></details>`;}).join(''):'<div class="empty">No evidence-linked review flags in the approved scope.</div>';
  wireRefs(box);
}
function renderVulnerabilities(){
  $('#vulnerabilityCount').textContent=`${vulnerabilityMatches.length} candidate${vulnerabilityMatches.length===1?'':'s'}`;
  $('#vulnerabilityCatalogStatus').textContent=vulnerabilityCatalog?`Curated vendor snapshot: ${vulnerabilityCatalog.asOf}. ${vulnerabilityCatalog.coverage}`:'Catalog unavailable.';
  const byId=new Map(findings.map(f=>[f.id,f])),grouped=new Map();
  for(const match of vulnerabilityMatches){if(!grouped.has(match.hostId))grouped.set(match.hostId,[]);grouped.get(match.hostId).push(match);}
  $('#vulnerabilityList').innerHTML=vulnerabilityMatches.length?[...grouped].map(([hostId,matches])=>{
    const host=byId.get(hostId);
    const rows=matches.map(match=>`<div class="finding-record"><div class="item-left"><strong><a href="${esc(match.source)}" target="_blank" rel="noopener noreferrer">${esc(match.cveId)}</a> · ${esc(match.title)}</strong><small>${ref(match.serviceId,recordLabel(byId.get(match.serviceId)||{title:match.serviceId}))} · ${esc(match.product)} ${esc(match.observedVersion)}</small><p>Condition to verify: ${esc(match.condition)}</p><small>Observed in: ${(match.findingIds||[]).map(id=>ref(id,recordLabel(byId.get(id)||{title:id}))).join(' · ')}</small><small>Evidence: ${evidenceLinks(match.evidenceIds)}</small></div><span class="kind">possible</span></div>`).join('');
    return `<details class="finding-branch"><summary><span class="finding-name">${esc(recordLabel(host||{title:hostId}))}</span><span class="finding-summary-count">${matches.length} candidate${matches.length===1?'':'s'}</span></summary><div class="finding-children">${rows}</div></details>`;
  }).join(''):'<div class="empty">No version matches in this limited catalog. This does not establish that the recorded software is safe.</div>';
  wireRefs($('#vulnerabilityList'));
}
function renderWebSurvey(){const id=$('#webSurveyHost').value,box=$('#webSurvey'),previous=$('#burpService').value;const services=findings.filter(s=>s.kind==='service'&&s.hostId===id&&s.protocol==='tcp'&&s.state==='open'&&(s.name?.toLowerCase().startsWith('http')||[80,443,8080,8443].includes(s.port)));$('#burpService').innerHTML='<option value="">Choose an open web service</option>'+services.map(s=>`<option value="${esc(s.id)}" ${s.id===previous?'selected':''}>${esc(s.port+'/tcp '+(s.name||'web'))}</option>`).join('');if(!id){box.innerHTML='<div class="empty">Choose a recorded web host to compare its saved survey results.</div>';return;}const host=findings.find(f=>f.id===id),rows=evidence.filter(e=>e.tool==='web-inventory'&&findings.some(f=>f.hostId===id&&f.evidenceIds.includes(e.id)));box.innerHTML=rows.length?rows.map(e=>{let r;try{r=JSON.parse(e.output);}catch{return '';}return `<div class="cmd"><strong>${esc(r.url)} · ${esc(date(e.observedAt))}</strong><p>${esc(r.coverage||'')}</p><p>Pages: ${(r.pages||[]).map(p=>`${esc(p.url)} → ${esc(p.status)}${p.looksLikeNotFound?' (resembles missing page)':''}`).join(' · ')||'none'}</p><p>Redirects: ${(r.redirects||[]).map(x=>`${esc(x.status)} ${esc(x.fromUrl)} → ${esc(x.toUrl)}${x.followed?'':' (blocked)'}`).join(' · ')||'none'}</p><p>Forms: ${(r.forms||[]).map(x=>`${esc(x.method)} ${esc(x.action)} [${x.fields.map(f=>esc(f.name+':'+f.type)).join(', ')}]`).join(' · ')||'none'}</p><p>Routes: ${(r.routes||[]).map(esc).join(' · ')||'none'}</p><p>Discovery hints: ${(r.discoveryHints||[]).map(h=>`${esc(h.source)} ${esc(h.directive)} ${esc(h.url)}`).join(' · ')||'none'}</p><p>Not-found baseline: ${r.notFoundBaseline?`HTTP ${esc(r.notFoundBaseline.status)} · ${esc(r.notFoundBaseline.title)}`:'not recorded'}</p><p>${evidenceLinks([e.id])}</p></div>`;}).join(''):'<div class="empty">No web inventory recorded for this host. Run its scoped “Inventory web pages and routes” check in Next checks.</div>';wireRefs(box);}
function renderTechnologySurvey(){const id=$('#webSurveyHost').value,box=$('#technologySurvey');if(!id){box.innerHTML='<div class="empty">Choose a recorded web host.</div>';return;}const rows=evidence.filter(e=>e.tool==='web-fingerprint'&&findings.some(f=>f.hostId===id&&f.evidenceIds.includes(e.id)));box.innerHTML=rows.length?rows.map(e=>{let report;try{report=JSON.parse(e.output);}catch{return '';}return `<div class="cmd"><strong>${esc(report.url)} · HTTP ${esc(report.status)}</strong><p>${(report.technologies||[]).map(t=>`${esc(t.name)}${t.version?' '+esc(t.version):''} <small>(${esc(t.source)} · ${esc(t.confidence)})</small>`).join(' · ')||'No curated signals detected'}</p><p>${evidenceLinks([e.id])}</p></div>`;}).join(''):'<div class="empty">No technology check recorded. Run “Identify web technologies” in Next checks or AI investigation.</div>';wireRefs(box);}
$('#webSurveyHost').onchange=()=>{renderWebSurvey();renderTechnologySurvey();};
$('#burpRun').onclick=async()=>{const host=findings.find(f=>f.id===$('#webSurveyHost').value),service=findings.find(f=>f.id===$('#burpService').value),state=$('#burpRunState'),button=$('#burpRun');if(!host||!service||!checkScope()){state.textContent='Choose an approved host and recorded open web service.';return;}const scheme=service.tunnel==='ssl'||service.name?.toLowerCase().includes('https')||[443,8443].includes(service.port)?'https':'http',name=host.name||host.ip,url=`${scheme}://${name}:${service.port}/`;if(!await confirmScopedAction('Run Burp MCP check?',`<p>GET / on ${esc(url)} pinned to ${esc(host.ip)}. Burp may request its own approval. Only HTTP status and content type will be saved.</p>`,'Run with Burp'))return;button.disabled=true;state.textContent='Waiting for Burp MCP…';try{const result=await post('/api/tools/burp/run',{hostId:host.id,serviceId:service.id,authorizedScope:checkScope(),authorized:true});state.textContent=`HTTP ${result.status} · ${result.mime||'content type unknown'} · Findings updated.`;await refreshFindings();}catch(e){state.textContent=e.message;}finally{button.disabled=false;}};
function copyButtons(box){box.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{try{await navigator.clipboard.writeText(b.dataset.copy);toast(b.dataset.template==='true'?'Template copied; replace placeholders before running.':'Command copied');}catch{toast('Clipboard access unavailable; select the command to copy.');}});}
function renderCatalog(){const box=$('#catalog');$('#catalogCount').textContent=`${toolCatalog.length} installed tools`;box.innerHTML=toolCatalog.length?toolCatalog.map(t=>`<div class="cmd catalog-item"><strong>${esc(t.id)}</strong><p>${esc(t.purpose)}</p></div>`).join(''):'<div class="empty">No catalog tools are installed on this server.</div>';}

let showAllSuggestions=false;
function renderSuggestions(items){
  currentSuggestions=items;
  const box=$('#suggestions'),query=$('#suggestionFilter').value.trim().toLowerCase();
  const filtered=query?items.filter(s=>[s.title,s.reason,s.command,recordLabel(findings.find(f=>f.id===s.hostId)||{title:''})].some(value=>String(value||'').toLowerCase().includes(query))):items;
  const visible=showAllSuggestions?filtered:filtered.slice(0,5);
  $('#suggestionsCount').textContent=`${filtered.length} of ${items.length} checks match${visible.length<filtered.length?' · showing first '+visible.length:''}`;
  box.innerHTML=visible.length?visible.map(s=>{const result=runResults.get(s.id),host=findings.find(f=>f.id===s.hostId);return `<div class="cmd"><div class="cmdtop"><div><strong>${esc(s.title)}</strong><div class="check-target">${esc(recordLabel(host||{title:s.hostId||''}))}</div></div><button class="btn primary" data-run="${esc(s.id)}">Run</button></div><details class="check-details"><summary>Command &amp; evidence</summary><p>${esc(s.reason)}</p><code>${esc(s.command)}</code><p>Based on ${s.findingIds.map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:id}))).join(' · ')}</p><p>${evidenceLinks(s.evidenceIds)}</p><div class="toolbar"><button class="btn" data-copy="${esc(s.command)}">Copy</button><button class="btn" data-edit-run="${esc(s.id)}">Edit &amp; run</button></div></details>${result?`<details class="check-details"><summary>${checkOutcome(result)}${result.imported?' · Findings updated':''}</summary><div class="run-output"><code>${esc(result.command)}</code><pre>${esc(result.output||result.stderr||'No output.')}</pre></div></details>`:''}</div>`;}).join(''):'<div class="empty">'+(query?'No checks match this search.':'No checks are available for recorded hosts in the current scope.')+'</div>';
  if(filtered.length>5)box.insertAdjacentHTML('beforeend',`<button class="btn" id="suggestionsMore" type="button">${showAllSuggestions?'Show first five':'Show all '+filtered.length+' matching checks'}</button>`);
  $('#suggestionsMore')?.addEventListener('click',()=>{showAllSuggestions=!showAllSuggestions;renderSuggestions(currentSuggestions);});
  copyButtons(box);wireRefs(box);
  box.querySelectorAll('[data-run]').forEach(b=>b.onclick=()=>runCheck(b,items.find(s=>s.id===b.dataset.run)));
  box.querySelectorAll('[data-edit-run]').forEach(b=>b.onclick=()=>editAndRun(items.find(s=>s.id===b.dataset.editRun)));
}
$('#suggestionFilter').oninput=()=>{showAllSuggestions=false;renderSuggestions(currentSuggestions);};
function clearAutoPlan(message){if(autoRunning)return;autoPlan=null;$('#startAuto').disabled=true;$('#autoPlan').innerHTML='';$('#autoResults').innerHTML='';$('#autoState').textContent=message||'Select a host to preview a short run.';$('#autoPreviewState').textContent=message||'Select a host, then preview its checks.';}
function updateAutoHosts(){updateAutonomyHosts();if(autoRunning)return;const select=$('#autoHost'),selected=select.value;const hosts=map.targets.filter(t=>t.eligible&&map.candidates.some(c=>c.hostId===t.host.id&&autoKinds.includes(c.catalogId))).map(t=>t.host);select.innerHTML=options(hosts,selected,'Select a scoped host');if(select.value!==selected&&autoPlan)clearAutoPlan('The selected host is no longer eligible. Preview again.');$('#previewAuto').disabled=!select.value;}
function updateAutonomyHosts(){const hosts=map.targets.filter(t=>t.eligible).map(t=>t.host);const approved=new Set(hosts.map(h=>h.id));for(const id of autonomySelectedHosts)if(!approved.has(id))autonomySelectedHosts.delete(id);renderAutonomyGroupHosts();const proposal=$('#proposalHost'),chosen=proposal.value;proposal.innerHTML=options(hosts,chosen,'Choose an approved host');}
$('#autoNewOpen').onclick=()=>$('#autoNewDialog').showModal();$('#autoNewClose').onclick=()=>$('#autoNewDialog').close();
$('#autoHost').onchange=()=>{clearAutoPlan();$('#previewAuto').disabled=!$('#autoHost').value;};
$('#previewAuto').onclick=()=>{const hostId=$('#autoHost').value;if(!hostId||!checkScope()){clearAutoPlan('Select a scoped host first.');return;}const checks=map.candidates.filter(c=>c.hostId===hostId&&autoKinds.includes(c.catalogId)).sort((a,b)=>autoKinds.indexOf(a.catalogId)-autoKinds.indexOf(b.catalogId)).slice(0,3);if(!checks.length){clearAutoPlan('No short-run checks are available for this host.');return;}autoPlan={hostId,scope:JSON.stringify(checkScope()),checks:checks.map(c=>({id:c.id,title:c.title,command:c.command}))};$('#autoPlan').innerHTML=checks.map((c,i)=>`<div class="cmd"><strong>${i+1}. ${esc(c.title)}</strong><p>${esc(c.reason)}</p><code>${esc(c.command)}</code></div>`).join('');$('#autoResults').innerHTML='';$('#autoPreviewState').textContent=`${checks.length} check(s) ready. Review the commands, then select Start to confirm.`;$('#autoState').textContent=$('#autoPreviewState').textContent;$('#startAuto').disabled=false;};
$('#stopAuto').onclick=()=>{autoStop=true;$('#stopAuto').disabled=true;$('#autoState').textContent='Stop requested. Waiting for the current check to finish.';};
$('#startAuto').onclick=async()=>{
  const plan=autoPlan;
  if(!plan||autoRunning)return;
  const host=map.targets.find(t=>t.host.id===plan.hostId)?.host;
  if(!await confirmScopedAction('Start short check sequence?',`Run ${plan.checks.length} listed checks on ${esc(host?recordLabel(host):plan.hostId)}:<pre>${esc(plan.checks.map(c=>c.command).join('\n'))}</pre>`,'Start checks'))return;
  $('#autoNewDialog').close();autoRunning=true;autoStop=false;
  autoStartedAt=new Date().toISOString();
  $('#startAuto').disabled=true;$('#previewAuto').disabled=true;$('#autoHost').disabled=true;$('#stopAuto').disabled=false;
  let completed=0,stopReason='All listed checks completed.';
  try{
    await scopeSave;
    for(const check of plan.checks){
      if(autoStop){stopReason='Stopped by user.';break;}
      if(JSON.stringify(checkScope())!==plan.scope){stopReason='Target scope changed. Stopped before the next check.';break;}
      const fresh=await api('/api/workflow');
      if(autoStop){stopReason='Stopped by user.';break;}
      if(JSON.stringify(checkScope())!==plan.scope){stopReason='Target scope changed. Stopped before the next check.';break;}
      const current=fresh.candidates.find(c=>c.id===check.id&&c.hostId===plan.hostId&&c.command===check.command);
      if(!current){stopReason='A listed check or target changed. Stopped before the next check.';break;}
      $('#autoState').textContent=`Running ${completed+1} of ${plan.checks.length}: ${check.title}…`;
      autoCurrentCheck=check.command;
      const result=await post('/api/checks/run',{candidateId:check.id,authorized:true,authorizedScope:JSON.parse(plan.scope)});
      completed++;
      $('#autoResults').innerHTML+=`<div class="cmd"><strong>${esc(check.title)} · ${checkOutcome(result)}</strong><p class="status">${result.imported?'Findings updated':'No findings imported'}${result.warning?' · '+esc(result.warning):''}</p><code>${esc(result.command)}</code><pre>${esc(result.output||result.stderr||'No output.')}</pre></div>`;
      if(result.imported)await refreshFindings();
      if(result.outcome==='no-response'){stopReason='No ICMP reply. Stopped before the next check; this does not prove the host is down.';break;}
      if(result.outcome==='failed'||!result.ok||result.warning||!result.imported){stopReason=result.warning||result.stderr||'The check failed or produced no importable findings.';break;}
    }
  }catch(e){stopReason=e.message;}
  finally{
    autoRunning=false;autoPlan=null;
    autoCurrentCheck='';
    autoStartedAt=null;
    $('#stopAuto').disabled=true;$('#startAuto').disabled=true;$('#autoHost').disabled=false;
    updateAutoHosts();
    $('#autoState').textContent=`${completed} of ${plan.checks.length} check(s) finished. ${stopReason} Preview again for another run.`;
  }
};
function editAndRun(suggestion){showDialog('Edit check command',`<p class="notice">The target, program and required options stay fixed. You can change ping count (1–5), Nmap top ports (1–1000), recorded service ports or version level, and HTTP header timeout (1–20 seconds) or same-origin path. Other checks can be rerun unchanged.</p><div class="field"><label for="editedCheckCommand">Command to run</label><textarea id="editedCheckCommand" rows="4" spellcheck="false">${esc(suggestion.command)}</textarea></div><p class="status" id="editedCheckState" role="status">Review the command, then select Run edited command to confirm.</p><button class="btn primary" id="confirmEditedCheck">Run edited command</button>`);$('#confirmEditedCheck').onclick=async()=>{const command=$('#editedCheckCommand').value.trim();const button=$('#confirmEditedCheck');if(!command){$('#editedCheckState').textContent='Enter a command.';return;}if(!checkScope()){$('#editedCheckState').textContent='Save a target scope first.';return;}button.disabled=true;$('#editedCheckState').textContent='Running edited command…';const ok=await runCheck(button,suggestion,command);if(!ok&&$('#reviewDialog').open)button.disabled=false;};$('#editedCheckCommand').focus();}
async function runCheck(button,suggestion,editedCommand){if(!checkScope()){$('#suggestState').textContent='Set an authorized scope first.';location.hash='#scope';setTimeout(()=>$('#cidrs').focus(),0);return false;}if(!await confirmScopedAction('Run this check?',`Target: ${esc(suggestion.hostName||suggestion.hostIp||suggestion.hostId||'Recorded host')}<pre>${esc(editedCommand||suggestion.command)}</pre>`,'Run check'))return false;button.disabled=true;$('#suggestState').textContent=`Running ${editedCommand||suggestion.command}…`;try{await scopeSave;const result=await post('/api/checks/run',{candidateId:suggestion.id,authorized:true,authorizedScope:checkScope(),...(editedCommand!==undefined?{editedCommand}:{})});runResults.set(suggestion.id,result);if(result.imported)await refreshFindings();else renderSuggestions(currentSuggestions);showDialog('Check output',`<p class="mono">${esc(result.command)}</p><p class="status">${checkOutcome(result)}${result.imported?' · Findings updated':''}${result.warning?' · '+esc(result.warning):''}</p><pre>${esc(result.output||result.stderr||'No output.')}</pre>`);$('#suggestState').textContent=result.outcome==='no-response'?'No ICMP reply; this does not prove the host is down.':result.ok?'Check finished. Review the output and updated findings.':`Check failed: ${result.stderr||'See output below.'}`;return true;}catch(e){$('#suggestState').textContent=e.message;if(editedCommand!==undefined&&$('#editedCheckState'))$('#editedCheckState').textContent=e.message;return false;}finally{button.disabled=false;}}
function analysisHostLabel(assessment,index){
  const linked=(assessment.findingIds||[]).map(id=>findings.find(f=>f.id===id)).filter(Boolean);
  const host=linked.find(f=>f.kind==='host')||linked.map(f=>findings.find(h=>h.id===f.hostId)).find(Boolean);
  return host?recordLabel(host):linked[0]?recordLabel(linked[0]):`Assessment ${index+1}`;
}
function renderAnalysis(result){
  const box=$('#analysisResults');
  if(!result){box.innerHTML='<div class="empty">No saved analysis. Open New analysis to analyze recorded findings.</div>';return;}
  const assessments=result.assessments||[], hypotheses=result.hypotheses||[], warnings=result.warnings||[];
  const warningItems=[...(result.error?.message?[result.error.message]:[]),...warnings];
  const warningBlock=warningItems.length?`<details class="analysis-warnings"><summary>${warningItems.length} ${warningItems.length===1?'warning':'warnings'}</summary>${warningItems.map(w=>`<p>${esc(w)}</p>`).join('')}</details>`:'';
  const source=result.source==='local model'?'AI analysis':'Recorded facts';
  box.innerHTML=`<div class="analysis-overview"><h2>${source}</h2><p>${esc(result.summary||'No summary available.')}</p>${result.message?`<p class="${result.source==='local model'?'analysis-meta':'analysis-alert'}">${esc(result.message)}</p>`:''}${result.stale?'<p class="analysis-alert">Findings changed since this analysis. Run it again for current results.</p>':''}<div class="analysis-meta">${assessments.length} ${assessments.length===1?'assessment':'assessments'} · ${hypotheses.length} ${hypotheses.length===1?'hypothesis':'hypotheses'} · ${esc(date(result.generatedAt))}${result.model?' · '+esc(result.model):''}</div>${warningBlock}</div>`;
  if(assessments.length)box.innerHTML+='<div class="analysis-list-title">Assessments</div>'+assessments.map((a,index)=>{
    const label=analysisHostLabel(a,index), refs=(a.findingIds||[]).map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:'Previous finding'}))).join(' · '), evidenceRefs=evidenceLinks(a.evidenceIds);
    return `<details class="analysis-item"><summary><span><span class="analysis-item-title">${esc(label)}</span><span class="analysis-item-preview">${esc(a.interpretation||'No interpretation')}</span></span></summary><div class="analysis-item-body"><p>${esc(a.interpretation)}</p>${(a.uncertainties||[]).map(u=>`<p class="notice">Uncertainty: ${esc(u)}</p>`).join('')}${refs?`<p><strong>Findings</strong><br>${refs}</p>`:''}${evidenceRefs?`<p><strong>Evidence</strong><br>${evidenceRefs}</p>`:''}</div></details>`;
  }).join('');
  if(hypotheses.length)box.innerHTML+='<div class="analysis-list-title">Hypotheses · review required</div>'+hypotheses.map(h=>`<details class="analysis-item"><summary><span><span class="analysis-item-title">${esc(h.title)}</span><span class="analysis-item-preview">${esc(h.summary)}</span></span></summary><div class="analysis-item-body"><p>${esc(h.summary)}</p><ol>${(h.steps||[]).map(step=>`<li><p><strong>${esc(step.status)}</strong> · ${esc(step.claim)}</p><p>${(step.findingIds||[]).map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:'Previous finding'}))).join(' · ')}</p><p>${evidenceLinks(step.evidenceIds)}</p></li>`).join('')}</ol>${[['Prerequisites',h.prerequisites||[]],['Missing evidence',h.missingEvidence||[]],['Counterevidence',h.counterevidence||[]]].map(([label,items])=>items.length?`<strong>${label}</strong><ul>${items.map(item=>`<li>${esc(item)}</li>`).join('')}</ul>`:'').join('')}${(h.investigations||[]).length?`<strong>Proposed investigations · manual review</strong>${h.investigations.map(i=>`<div class="cmd"><p>${esc(i.objective)}</p><p>${(i.hostIds||[]).map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:'Previous host'}))).join(' · ')}</p><p>Expected evidence: ${esc(i.expectedEvidence)}</p><p>Decision impact: ${esc(i.decisionImpact)}</p></div>`).join('')}`:''}</div></details>`).join('');
  wireRefs(box);
}
async function loadAnalysis(){try{const d=await api('/api/analysis/latest');latestAnalysis=d.analysis;renderAnalysis(d.analysis);renderBriefing();}catch(e){$('#analysisState').textContent=e.message;}}
function updateAnalysisScopeMode(){const mode=$('#analysisScopeMode').value;$('#analysisHostField').hidden=mode!=='single';$('#analysisGroupField').hidden=mode!=='group';}
$('#analysisScopeMode').onchange=updateAnalysisScopeMode;updateAnalysisScopeMode();
$('#analysisNewOpen').onclick=()=>{$('#analysisNewDialog').showModal();$('#analysisNewClose').focus();};
$('#analysisNewClose').onclick=()=>$('#analysisNewDialog').close();
$('#analyzeBtn').onclick=async()=>{const mode=$('#analysisScopeMode').value,hostIds=mode==='group'?[...$('#analysisGroup').selectedOptions].map(o=>o.value):[],hostId=mode==='single'?$('#analysisHost').value:'';if(mode==='single'&&!hostId||mode==='group'&&(hostIds.length<2||hostIds.length>8)){$('#analysisState').textContent=mode==='single'?'Choose a host.':'Choose 2–8 hosts.';return;}const b=$('#analyzeBtn');b.disabled=true;$('#analysisState').textContent='Analyzing recorded findings…';try{await scopeSave;const model=$('#llmModel').value;const d=await post('/api/analysis',{...(hostIds.length?{hostIds}:{hostId}),...(model?{model}:{}),...(checkScope()?{authorizedScope:checkScope()}:{})});latestAnalysis=d;renderAnalysis(d);renderBriefing();renderSuggestions(d.suggestions);$('#analysisNewDialog').close();toast('Analysis saved');$('#analysisState').textContent=`${d.source}: ${d.status}${d.stale?' · findings changed during analysis':''}`;}catch(e){$('#analysisState').textContent=e.message;}finally{updatePrerequisites();}};
async function loadModels(){const h=await api('/api/llm/health'),select=$('#llmModel'),selected=select.value;select.innerHTML='<option value="">Server default / automatic</option>'+(h.models||[]).map(id=>`<option value="${esc(id)}">${esc(id)}</option>`).join('');select.value=(h.models||[]).includes(selected)?selected:'';for(const id of ['autonomyModel','proposalModel','briefingModel']){const control=$('#'+id),chosen=control.value;control.innerHTML=select.innerHTML;control.value=(h.models||[]).includes(chosen)?chosen:'';}autonomyModelRequired=h.status==='model-required';$('#autonomyModelState').textContent=autonomyModelRequired?'Choose a model before starting; this gateway advertises several models.':h.status==='ready'?'':`Model ${h.status}: ${h.message}`;$('#analysisState').textContent=h.status==='ready'?`Model ready: ${h.model}`:h.status==='model-required'?'Choose one of the available models.':`Model ${h.status}: ${h.message}`;$('#llmBadge').textContent=h.status==='ready'||h.status==='model-required'?'LOCAL MODEL AVAILABLE':'LOCAL MODEL UNAVAILABLE';renderBriefing();}
$('#llmHealthBtn').onclick=async()=>{const b=$('#llmHealthBtn');b.disabled=true;$('#analysisState').textContent='Testing model endpoint…';try{await loadModels();}catch(e){$('#analysisState').textContent=e.message;}finally{b.disabled=false;}};
async function refreshFindings(){const scope=checkScope(),[doc,w,attention,vulnerabilities]=await Promise.all([api('/api/findings'),api('/api/workflow'),api('/api/attention'),api('/api/vulnerabilities')]);findings=doc.findings;evidence=doc.evidence;attentionFlags=attention.flags||[];vulnerabilityMatches=vulnerabilities.matches||[];vulnerabilityCatalog=vulnerabilities.catalog||null;map=w;workspaceReady=true;updatePrerequisites();const eligibleHosts=findings.filter(f=>f.kind==='host'&&w.targets.some(t=>t.host.id===f.id&&t.eligible)),selected=$('#analysisHost').value,group=[...$('#analysisGroup').selectedOptions].map(o=>o.value),web=$('#webSurveyHost').value;$('#analysisHost').innerHTML=options(eligibleHosts,selected,'All scoped findings');$('#analysisGroup').innerHTML=eligibleHosts.map(f=>`<option value="${esc(f.id)}" ${group.includes(f.id)?'selected':''}>${esc(recordLabel(f))}</option>`).join('');$('#webSurveyHost').innerHTML=options(eligibleHosts,web,'Choose a host');renderFindings();renderAttention();renderVulnerabilities();InventoryStats.update(findings,evidence,w,attentionFlags,savedScope,autonomyRuns,showRecord);renderWebSurvey();renderTechnologySurvey();renderSuggestions(w.candidates);updateAutoHosts();renderTriage();if(autonomyRuns.length)renderAutonomy();$('#suggestState').textContent=scope?'':'Enter an authorized scope to see proposed commands.';await loadAnalysis();await loadDraftContacts();}
async function load(){scopeLoaded=false;scopeLoadError='';updateScopeGate();try{const [h,c,scope]=await Promise.all([api('/api/health'),api('/api/commands'),api('/api/scope')]);savedScope=scope;scopeLoaded=true;scopeLoadError='';$('#cidrs').value=scope.cidrs.join('\n');$('#domains').value=scope.domains.join('\n');$('#matchMode').value=scope.matchMode||'and';$('#scanTarget').value=scope.cidrs[0]||'';showScope();if($('#scopeEditor').open)$('#scopeEditor').close();updateScopeGate();$('#scopeState').textContent=checkScope()?'Saved target scope: '+scopeLabel()+'.':'Save a target scope to enable the other workflow sections.';toolCatalog=c.tools||[];renderCatalog();await refreshFindings();if(checkScope())await loadPendingDiscovery();await refreshDrafts();$('#systemStatus').innerHTML=`nmap: <b>${h.nmap?'ready':'not found'}</b> · nxc: <b>${h.nxc?'ready':'not found'}</b> · nuclei: <b>${h.nuclei?'ready':'not found'}</b>`;$('#llmBadge').textContent=h.llm==='configured'?'LOCAL MODEL AVAILABLE':h.llm.startsWith('blocked')?'LLM URL BLOCKED':'LOCAL MODEL OPTIONAL';loadModels().catch(e=>{$('#analysisState').textContent=e.message;});return true;}catch(e){$('#systemStatus').textContent='Workspace API unavailable: '+e.message+' Refresh to retry.';workspaceReady=false;if(!scopeLoaded){scopeLoadError=e.message;updateScopeGate();$('#scopeState').textContent='Cannot load the target scope: '+e.message;}updatePrerequisites();return false;}}
function field(key,label,value,type='text'){return `<div class="field"><label for="edit-${key}">${esc(label)}</label><input id="edit-${key}" name="${key}" type="${type}" value="${esc(value)}"></div>`;}
function options(rows,selected,emptyLabel='Unlinked'){return `<option value="">${esc(emptyLabel)}</option>`+rows.map(f=>`<option value="${esc(f.id)}" ${f.id===selected?'selected':''}>${esc(recordLabel(f))}</option>`).join('');}
function editRecord(id){
  const f=findings.find(x=>x.id===id);let extra='';
  if(f.kind==='host')extra=field('ip','IP address',f.ip)+field('name','Hostname',f.name)+field('state','Host state (up, down, no-response, unknown)',f.state)+field('mac','MAC address',f.mac)+field('interface','Interface',f.interface)+field('prefix','Address prefix length (optional)',f.prefix,'number')+field('neighborState','Neighbor state',f.neighborState)+field('aliases','Other IP addresses (comma separated)',(f.aliases||[]).join(', '))+`<label class="check"><input name="local" type="checkbox" ${f.local?'checked':''}>Local interface address</label>`;
  if(f.kind==='service')extra=field('port','Port',f.port,'number')+`<div class="field"><label for="edit-protocol">Protocol</label><select id="edit-protocol" name="protocol">${['tcp','udp','sctp'].map(p=>`<option ${p===f.protocol?'selected':''}>${p}</option>`).join('')}</select></div>`+['state','name','product','version','tunnel'].map(k=>field(k,k[0].toUpperCase()+k.slice(1),f[k])).join('');
  if(f.kind==='observation')extra=`<div class="field"><label for="edit-hostId">Linked host</label><select id="edit-hostId" name="hostId">${options(findings.filter(x=>x.kind==='host'),f.hostId)}</select></div><div class="field"><label for="edit-serviceId">Linked service (sets host)</label><select id="edit-serviceId" name="serviceId">${options(findings.filter(x=>x.kind==='service'),f.serviceId)}</select></div>`;
  showDialog('Edit finding',`<form id="editForm">${field('title','Title',f.title)}${extra}<div class="field"><label for="edit-detail">Observation / detail</label><textarea id="edit-detail" name="detail">${esc(f.detail)}</textarea></div><p class="notice">Saving marks this finding reviewed. Future imports retain your corrected fields and add source evidence.</p><p class="status" id="editError" role="status"></p><button class="btn primary">Save & mark reviewed</button></form>`);
  $('#editForm').onsubmit=async event=>{event.preventDefault();const patch=Object.fromEntries(new FormData(event.target));if(f.kind==='host'){patch.local=event.target.elements.local.checked;patch.aliases=String(patch.aliases||'').split(',').map(x=>x.trim()).filter(Boolean);}try{await api('/api/findings/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(patch)});$('#reviewDialog').close();await refreshFindings();toast('Finding updated');}catch(e){$('#editError').textContent=e.message;}};
}
function mergeRecord(id){
  const f=findings.find(x=>x.id===id),choices=findings.filter(x=>x.id!==id&&x.kind===f.kind&&(f.kind!=='service'||x.hostId===f.hostId&&x.port===f.port&&x.protocol===f.protocol));
  showDialog('Merge duplicate findings',`<p class="notice">Keep ${esc(recordLabel(f))}. Merge source evidence and linked records from the selected duplicate into it. Host merges retain the other address as an alias and combine matching services.</p>${choices.length?`<form id="mergeForm"><div class="field"><label for="mergeSource">Duplicate to merge</label><select id="mergeSource" required>${options(choices,null,'Choose a duplicate')}</select></div><p class="status" id="mergeError" role="status"></p><button class="btn primary">Merge into this finding</button></form>`:'<div class="empty">No compatible duplicates available.</div>'}`);
  if(choices.length)$('#mergeForm').onsubmit=async e=>{e.preventDefault();try{await post('/api/findings/merge',{targetId:id,sourceId:$('#mergeSource').value});$('#reviewDialog').close();await refreshFindings();toast('Findings merged');}catch(error){$('#mergeError').textContent=error.message;}};
}
function deleteRecord(id){const f=findings.find(x=>x.id===id);showDialog('Delete finding',`<p>Delete ${esc(recordLabel(f))}?</p><p class="notice">${f.kind==='host'?'Its linked services and observations will also be removed.':f.kind==='service'?'Its linked observations will also be removed.':''} Raw source evidence remains available in the JSON export.</p><button class="btn" id="confirmDelete">Delete finding</button>`);$('#confirmDelete').onclick=async()=>{try{await api('/api/findings/'+encodeURIComponent(id),{method:'DELETE'});$('#reviewDialog').close();await refreshFindings();}catch(e){toast(e.message);}};}
$('#findingFilter').onchange=renderFindings;
$('#findingSearch').oninput=renderFindings;
$('#expandFindings').onclick=()=>{$('#findingList').querySelectorAll('details[data-tree-id]').forEach(node=>{node.open=true;findingTreeOpen.add(node.dataset.treeId);});};
$('#collapseFindings').onclick=()=>{$('#findingList').querySelectorAll('details[data-tree-id]').forEach(node=>{node.open=false;findingTreeOpen.delete(node.dataset.treeId);});};
function invalidatePreview(){previewPayload=null;$('#saveImport').disabled=true;$('#importPreview').innerHTML='';$('#importState').textContent='Preview the updated output before saving.';}
function renderToolImportHost(){const needsHost=['wappalyzer','burp'].includes($('#importTool').value),field=$('#importToolHostField'),select=$('#importToolHost'),selected=select.value;field.hidden=!needsHost;if(!needsHost)return;const hosts=map.targets.filter(t=>t.eligible).map(t=>t.host);select.innerHTML='<option value="">Choose an approved host</option>'+hosts.map(h=>`<option value="${esc(h.id)}" ${h.id===selected?'selected':''}>${esc(recordLabel(h))}</option>`).join('');}
$('#importTool').addEventListener('change',renderToolImportHost);
$('#importToolHost').addEventListener('change',invalidatePreview);
for(const id of ['importTool','importCommand','importOutput','importTime','importEvidenceTitle','importEvidenceIp','importSensitive'])$('#'+id).addEventListener('input',invalidatePreview);
$('#importFile').onchange=async()=>{const file=$('#importFile').files[0];if(!file)return;if(file.size>800000){toast('File exceeds the 800 KB limit.');return;}$('#importOutput').value=await file.text();invalidatePreview();};
$('#previewImport').onclick=async()=>{
  const b=$('#previewImport');b.disabled=true;invalidatePreview();$('#importState').textContent='Parsing output…';
  try{const tool=$('#importTool').value,input={tool,...(tool==='evidence'?{title:$('#importEvidenceTitle').value.trim()||'Imported investigation evidence',ip:$('#importEvidenceIp').value.trim(),sensitive:$('#importSensitive').checked}:{}),...(['wappalyzer','burp'].includes(tool)?{hostId:$('#importToolHost').value,authorizedScope:checkScope()}:{}),command:$('#importCommand').value,output:$('#importOutput').value,observedAt:$('#importTime').value?new Date($('#importTime').value).toISOString():undefined};const d=await post('/api/import/preview',input);input.observedAt=d.evidence[0].observedAt;previewPayload=input;$('#saveImport').disabled=false;$('#importState').textContent=`Preview only: ${d.findings.filter(f=>f.kind==='host').length} hosts · ${d.findings.filter(f=>f.kind==='service').length} services · ${d.findings.filter(f=>f.kind==='observation').length} observations. Save, then correct records in Findings. ${d.warnings.join(' ')}`;$('#importPreview').innerHTML=d.findings.slice(0,100).map(f=>`<div class="item"><div class="item-left"><strong>${esc(f.kind==='host'?f.ip:f.kind==='service'?`${f.port}/${f.protocol} ${f.name}`:f.title)}</strong><small>${esc(f.state||f.detail)} ${esc(f.product||'')} ${esc(f.version||'')}</small></div><span class="kind">${esc(f.kind)}</span></div>`).join('')+(d.findings.length>100?'<p class="notice">Showing the first 100 records. All parsed records will be saved.</p>':'');}catch(e){$('#importState').textContent=e.message;}finally{b.disabled=false;}
};
$('#saveImport').onclick=async()=>{if(!previewPayload)return;const b=$('#saveImport');b.disabled=true;try{const d=await post('/api/import',previewPayload);previewPayload=null;await refreshFindings();$('#importState').textContent=`Saved: ${d.summary.added} new records, ${d.summary.linked} existing records linked to new evidence. Review imported details below.`;$('#importPreview').innerHTML='';$('#importPanel').close();toast('Import saved');}catch(e){$('#importState').textContent=e.message;b.disabled=false;}};
$('#discoverLocal').onclick=async()=>{const b=$('#discoverLocal'),state=$('#localState');b.disabled=true;state.textContent='Reading…';try{const d=await post('/api/discovery/local',{});$('#interfaces').innerHTML=d.interfaces.length?d.interfaces.map(i=>{return `<div class="item"><div class="item-left"><strong>${esc(i.interface)}</strong><small class="mono">${esc(i.cidr)}</small><small>Yagura server context · not a target range</small></div></div>`;}).join(''):'<div class="empty">No IPv4 interfaces found.</div>';$('#neighbors').innerHTML=d.hosts.length?d.hosts.map(h=>`<div class="item"><div class="item-left"><strong class="mono">${esc(h.ip)}</strong><small>${esc(h.interface)} ${esc(h.state)} ${esc(h.mac)}</small></div></div>`).join(''):'<div class="empty">Neighbor table is empty.</div>';state.textContent=d.errors.join(' · ')||'Server context recorded; target scope unchanged';await refreshFindings();}catch(e){state.textContent=e.message;}finally{b.disabled=false;}};
function renderInventory(data){
  const rows=data.inventory||[],issues=data.inventoryIssues||[],hosts=new Map((data.hosts||[]).map(h=>[h.ip,h]));
  const ready=rows.filter(r=>r.status==='verified'&&hosts.get(r.ip)?.inventoryName===r.name&&!hosts.get(r.ip)?.approved);
  const inventoryApproved=rows.filter(r=>r.status==='verified'&&hosts.get(r.ip)?.approved).length;autonomyInventoryReady=inventoryApproved>=2;$('#autonomyInventoryCount').textContent=`${inventoryApproved} approved, DNS-verified inventory hosts. Yagura surveys all of them in batches of four.`;$('#autonomyInventoryStart').disabled=!autonomyInventoryReady;
  $('#inventoryCount').textContent=rows.length?`${rows.length} hosts · ${rows.filter(r=>r.status==='verified').length} DNS verified · ${issues.length} skipped`:'No inventory imported';
  $('#inventoryApprove').hidden=!ready.length;
  $('#inventoryApprove').textContent=`Approve ${ready.length} verified host${ready.length===1?'':'s'}`;
  const label={verified:'DNS verified', 'no-answer':'No DNS answer', 'dns-mismatch':'DNS/IP mismatch', 'dns-review-needed':'PTR/A review needed', 'host-conflict':'IP already approved for another name'};
  $('#inventoryList').innerHTML=rows.length||issues.length?rows.map(r=>`<div class="inventory-row ${r.status==='verified'?'':'bad'}"><strong>${esc(r.name)} · ${esc(r.ip)}</strong><small>${hosts.get(r.ip)?.approved?'Approved':esc(label[r.status]||r.status)}${r.addresses?.length&&r.status==='dns-mismatch'?' · DNS: '+esc(r.addresses.join(', ')):''}</small></div>`).join('')+issues.map(r=>`<div class="inventory-row bad"><strong>${esc(r.name)}</strong><small>${esc(r.reason)} · ${esc(r.address)}</small></div>`).join(''):'<div class="empty">Import an inventory to verify target names and addresses.</div>';
  $('#inventoryApprove').onclick=async()=>{const exact=ready.map(r=>({ip:r.ip,name:r.name}));if(!await confirmScopedAction('Approve verified inventory hosts?',`<p>${exact.length} exact IP/name pairs:</p><div class="inventory-list">${exact.map(h=>`<div>${esc(h.name)} · ${esc(h.ip)}</div>`).join('')}</div>`,'Approve hosts'))return;const b=$('#inventoryApprove');b.disabled=true;try{const result=await post('/api/discovery/inventory/approve',{hosts:exact,authorizedScope:checkScope(),authorized:true});await loadPendingDiscovery();await refreshFindings();$('#inventoryState').textContent=`Approved ${result.approved.length} verified hosts.`;}catch(e){$('#inventoryState').textContent=e.message;}finally{b.disabled=false;}};
}
$('#inventoryNewOpen').onclick=()=>{if(!checkScope()){$('#inventoryState').textContent='Save the target scope first.';return;}if(!$('#inventoryResolvers').value)$('#inventoryResolvers').value=$('#dnsResolvers').value;$('#inventoryDialog').showModal();};
$('#inventoryClose').onclick=()=>$('#inventoryDialog').close();
$('#inventoryImport').onclick=async()=>{const button=$('#inventoryImport'),state=$('#inventoryImportState'),file=$('#inventoryFile').files[0],scope=checkScope();if(!file||!scope){state.textContent='Choose the HTML file and save the target scope first.';return;}if(file.size>2500000){state.textContent='Choose an HTML file under 2.5 MB.';return;}const teamNumber=$('#inventoryTeam').value.trim(),suffix=$('#inventorySuffix').value.trim(),resolvers=$('#inventoryResolvers').value.split(/[\s,]+/).filter(Boolean);if(!await confirmScopedAction('Verify inventory hosts?',`File: ${esc(file.name)} · Team: ${esc(teamNumber)} · Suffix: ${esc(suffix)} · Resolvers: ${esc(resolvers.join(', '))}. This checks DNS but runs no host checks.`,'Verify hosts'))return;button.disabled=true;state.textContent='Checking names, listed IPs, and DNS…';try{const result=await post('/api/discovery/inventory',{content:await file.text(),teamNumber,suffix,resolvers,authorizedScope:scope,authorized:true});$('#inventoryDialog').close();await loadPendingDiscovery();$('#inventoryState').textContent=`${result.inventory.filter(r=>r.status==='verified').length} verified; ${result.inventory.length-result.inventory.filter(r=>r.status==='verified').length} require review; ${result.issues.length} skipped.`;}catch(e){state.textContent=e.message;}finally{button.disabled=false;}};
async function loadPendingDiscovery(){if(!checkScope())return;const data=await api('/api/discovery/pending'),box=$('#scanResults');renderInventory(data);$('#scanProgress').innerHTML=(data.runs||[]).map(r=>`<div class="notice">${esc(r.cidr)}: ${r.completed}/${r.total} parts complete · ${r.count} quarantined IP(s)${r.complete?' · Complete':r.failed?' · Failed at '+esc(r.nextCidr):' · Next '+esc(r.nextCidr)}</div>`).join('');const hostRow=h=>`<div class="cmd"><strong>${esc(h.ip)} · ${h.approved?'Approved':'Unverified'}</strong><p>Last seen ${esc(date(h.lastSeen))}${h.dns?.conflicting?' · Resolver answers conflict':''}</p>${h.seedQueries?`<details><summary>Name lookup evidence (${h.seedQueries.length} queries) · ${esc(h.seedName)}</summary><pre>${esc(h.seedQueries.map(q=>`${q.queriedAt} · ${q.resolver} · ${q.qtype} ${q.question} → ${q.records.map(r=>`${r.value} (TTL ${r.ttl})`).join(', ')||q.error||'no answer'}`).join('\n'))}</pre></details>`:''}${h.dns?`<details><summary>DNS evidence (${h.dns.queries.length} queries)</summary><pre>${esc(h.dns.queries.map(q=>`${q.queriedAt} · ${q.resolver} · ${q.qtype} ${q.question} → ${q.records.map(r=>`${r.value} (TTL ${r.ttl})`).join(', ')||q.error||'no answer'}`).join('\n'))}</pre></details>`:''}<div class="toolbar"><button class="btn" data-reviewdns="${esc(h.ip)}">Review internal DNS</button>${h.dns?.candidates?.length?`<select aria-label="Approved name for ${esc(h.ip)}" data-namefor="${esc(h.ip)}">${h.dns.candidates.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('')}</select><input aria-label="Review reason for ${esc(h.ip)}" data-reasonfor="${esc(h.ip)}" placeholder="Reason if DNS conflicts"><button class="btn primary" data-approve="${esc(h.ip)}">Approve host</button>`:''}</div></div>`;const pending=data.hosts.filter(h=>!h.approved),approved=data.hosts.filter(h=>h.approved);box.innerHTML=data.hosts.length?pending.map(hostRow).join('')+(approved.length?`<details class="approved-hosts"><summary>${approved.length} approved hosts</summary><div class="results">${approved.map(hostRow).join('')}</div></details>`:''):'<div class="empty">No discovered hosts in the current scope.</div>';box.querySelectorAll('[data-reviewdns]').forEach(button=>button.onclick=async()=>{try{const resolvers=$('#dnsResolvers').value.split(/[\s,]+/).filter(Boolean);if(!await confirmScopedAction('Review internal DNS?',`Host IP: ${esc(button.dataset.reviewdns)} · Internal resolvers: ${esc(resolvers.join(', ')||'None')}.`,'Review DNS'))return;await post('/api/discovery/dns',{ip:button.dataset.reviewdns,resolvers,authorized:true});await loadPendingDiscovery();}catch(e){$('#scanState').textContent=e.message;}});box.querySelectorAll('[data-approve]').forEach(button=>button.onclick=async()=>{try{const ip=button.dataset.approve,name=box.querySelector(`[data-namefor="${ip}"]`).value,reason=box.querySelector(`[data-reasonfor="${ip}"]`).value;if(!await confirmScopedAction('Approve discovered host?',`Approve ${esc(name)} at ${esc(ip)} for later checks.${reason?' Review reason: '+esc(reason):''}`,'Approve host'))return;await post('/api/discovery/approve',{ip,name,reason,authorized:true});await loadPendingDiscovery();await refreshFindings();$('#scanState').textContent=`Approved ${name} at ${ip}.`; }catch(e){$('#scanState').textContent=e.message;}});}
$('#stopScanBtn').onclick=()=>{stopDiscovery=true;$('#scanState').textContent='Stopping after the current part; completed parts remain saved.';};
$('#seedBtn').onclick=async()=>{const button=$('#seedBtn'),state=$('#scanState');button.disabled=true;try{const name=$('#seedName').value.trim(),resolvers=$('#dnsResolvers').value.split(/[\s,]+/).filter(Boolean);if(!await confirmScopedAction('Look up hostname?',`Name: ${esc(name)} · Internal resolvers: ${esc(resolvers.join(', ')||'None')}.`,'Look up name'))return;$('#discoveryNewDialog').close();const result=await post('/api/discovery/name',{name,resolvers,authorized:true});await loadPendingDiscovery();state.textContent=`${result.seed.addresses.length} private IP(s) quarantined for ${result.seed.name}. Review internal DNS before approval.`;}catch(e){state.textContent=e.message;}finally{updateScopeGate();}};
$('#scanBtn').onclick=async()=>{const b=$('#scanBtn'),state=$('#scanState'),stop=$('#stopScanBtn');b.disabled=true;stop.disabled=false;stopDiscovery=false;try{if(!scopeLoaded||!checkScope())throw new Error('Save the target scope first.');const cidr=$('#scanTarget').value.trim(),authorizedScope=structuredClone(savedScope);if(!await confirmScopedAction('Discover target hosts?',`CIDR: ${esc(cidr)}. The range is checked in small parts; completed parts are saved.`,'Start discovery'))return;$('#discoveryNewDialog').close();let d;do{if(JSON.stringify(savedScope)!==JSON.stringify(authorizedScope))throw new Error('Target scope changed. Review authorization before resuming.');d=await post('/api/discovery/scan',{cidr,authorized:true,authorizedScope});await loadPendingDiscovery();if(d.outcome==='failed'){state.textContent=`Discovery stopped at ${d.nextCidr}: ${d.error}. ${d.completed}/${d.total} parts saved; select Discover again to retry.`;break;}state.textContent=`${d.completed}/${d.total} parts complete in ${d.cidr}; ${d.count} IP(s) quarantined.${d.complete?' DNS review is still required.':''}`;}while(!d.complete&&!stopDiscovery);if(stopDiscovery&&!d.complete&&d.outcome!=='failed')state.textContent=`Stopped after ${d.completed}/${d.total} parts; select Discover again to resume.`;}catch(e){state.textContent=e.message;await loadPendingDiscovery().catch(()=>{});}finally{b.disabled=false;stop.disabled=true;}};
$('#newFindingOpen').onclick=()=>$('#newFindingDialog').showModal();$('#newFindingClose').onclick=()=>$('#newFindingDialog').close();
$('#addFinding').onclick=async()=>{try{await post('/api/findings',{title:$('#findingTitle').value,ip:$('#findingIp').value.trim(),detail:$('#findingDetail').value});await refreshFindings();for(const id of ['findingTitle','findingIp','findingDetail'])$('#'+id).value='';$('#newFindingDialog').close();toast('Observation saved');}catch(e){toast(e.message);}};
for(const id of ['cidrs','domains','matchMode'])$('#'+id).addEventListener(id==='matchMode'?'change':'input',()=>{$('#scopeState').textContent='Unsaved change. Select Save target scope to review it. The saved scope remains '+(scopeLabel()||'undefined')+'.';});
$('#suggestBtn').onclick=async()=>{const b=$('#suggestBtn');b.disabled=true;$('#suggestState').textContent='Selecting grounded checks…';try{await scopeSave;const model=$('#llmModel').value,d=await post('/api/suggest',{...(model?{model}:{}),...(checkScope()?{authorizedScope:checkScope()}:{})});renderSuggestions(d.suggestions);$('#suggestState').textContent=`${d.source}${d.model?' · '+d.model:''}: ${d.message}`;}catch(e){$('#suggestState').textContent=e.message;renderSuggestions([]);}finally{updatePrerequisites();}};
$('#refreshAll').onclick=async()=>{const b=$('#refreshAll');b.disabled=true;try{if(await load())toast('Workspace view refreshed');}finally{b.disabled=false;}};
const draftFields={to:'draftTo',sender:'draftSender',senderName:'draftSenderName',subject:'draftSubject',body:'draftBody',notes:'draftNotes'};
function draftValues(){return Object.fromEntries(Object.entries(draftFields).map(([key,id])=>[key,$('#'+id).value]));}
function markDraftDirty(){draftDirty=true;$('#draftState').textContent='Unsaved changes';}
function draftLock(value){draftBusy=value;$('#draftForm').querySelectorAll('input,textarea,button,select').forEach(el=>el.disabled=value);$('#draftList').querySelectorAll('button').forEach(el=>el.disabled=value);}
function showDraftSources(){const address=$('#draftTo').value.trim(),contact=emailContacts.find(c=>c.address.toLowerCase()===address.toLowerCase());$('#draftContact').value=contact?.address||'';const sources=contact?.sources||(activeDraft?.to===address?activeDraft.sourceUrls:[])||[];$('#draftSources').textContent=sources.length?'Found on: '+sources.join(' · '):'You can also enter a recipient manually.';}
async function loadDraftContacts(){const data=await api('/api/email-contacts');emailContacts=data.contacts;$('#draftContact').innerHTML='<option value="">Choose a contact or enter a recipient below</option>'+emailContacts.map(c=>`<option value="${esc(c.address)}">${esc(c.address)}</option>`).join('');showDraftSources();}
function renderDraftList(){const sorted=[...emailDrafts].sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt));$('#draftCount').textContent=`${sorted.length} ${sorted.length===1?'draft':'drafts'}`;$('#draftList').innerHTML=sorted.length?sorted.map(d=>`<div class="item"><div class="item-left"><strong>${esc(d.subject||'Untitled draft')}</strong><small>${esc(d.to||'Recipient not set')} · ${esc(date(d.updatedAt))}</small><small>${d.sender?esc(d.sender):'Sender pending'}</small></div><div class="item-actions"><button class="btn" data-open-draft="${esc(d.id)}" ${draftBusy?'disabled':''}>Open</button><button class="btn" data-delete-draft="${esc(d.id)}" ${draftBusy?'disabled':''}>Remove</button></div></div>`).join(''):'<div class="empty">No saved drafts yet.</div>';$('#draftList').querySelectorAll('[data-open-draft]').forEach(b=>b.onclick=()=>openDraft(emailDrafts.find(d=>d.id===b.dataset.openDraft)));$('#draftList').querySelectorAll('[data-delete-draft]').forEach(b=>b.onclick=()=>removeDraft(emailDrafts.find(d=>d.id===b.dataset.deleteDraft)));}
async function refreshDrafts(){emailDrafts=(await api('/api/email-drafts')).drafts;renderDraftList();}
function openDraft(draft){if(draftBusy)return;if(draftDirty&&!window.confirm('Discard unsaved changes in the current draft?'))return;activeDraft=draft||null;Object.entries(draftFields).forEach(([key,id])=>$('#'+id).value=draft?.[key]||'');draftDirty=false;showDraftSources();$('#draftState').textContent=draft?'Saved draft · '+date(draft.updatedAt):'New draft · sender can be added later.';$('#draftDialogTitle').textContent=draft?'Edit draft':'New draft';if(!$('#draftDialog').open)$('#draftDialog').showModal();$('#draftSubject').focus();}
async function saveEmailDraft(){if(draftBusy||!$('#draftForm').reportValidity())return null;draftLock(true);$('#draftState').textContent='Saving draft…';try{const payload=draftValues(),data=activeDraft?await api('/api/email-drafts/'+encodeURIComponent(activeDraft.id),{method:'PATCH',body:JSON.stringify({...payload,revision:activeDraft.revision})}):await post('/api/email-drafts',payload);activeDraft=data.draft;draftDirty=false;emailDrafts=emailDrafts.filter(d=>d.id!==activeDraft.id).concat(activeDraft);renderDraftList();$('#draftState').textContent='Saved locally · '+date(activeDraft.updatedAt);showDraftSources();if($('#draftDialog').open)$('#draftDialog').close();toast('Draft saved');return activeDraft;}catch(e){$('#draftState').textContent=e.message;if(e.status===409)await refreshDrafts().catch(()=>{});return null;}finally{draftLock(false);}}
function draftText(d){return (d.sender?`From: ${d.senderName?d.senderName+' <'+d.sender+'>':d.sender}\n`:'')+(d.to?`To: ${d.to}\n`:'')+`Subject: ${d.subject}\n\n${d.body}`;}
function previewEmailDraft(){showDialog('Email preview',`<p class="notice">${$('#draftSender').value?'Draft for review.':'Sender details are pending.'}</p><pre>${esc(draftText(draftValues()))}</pre>`);}
function removeDraft(draft){if(draftBusy)return;showDialog('Remove draft',`<p>Remove ${esc(draft.subject||'Untitled draft')}?</p>${activeDraft?.id===draft.id&&draftDirty?'<p class="notice">Unsaved changes to this draft will also be discarded.</p>':''}<p class="status" id="deleteDraftError"></p><button class="btn" id="confirmRemoveDraft">Remove draft</button>`);$('#confirmRemoveDraft').onclick=async()=>{const button=$('#confirmRemoveDraft');button.disabled=true;draftLock(true);try{await api('/api/email-drafts/'+encodeURIComponent(draft.id),{method:'DELETE',body:JSON.stringify({revision:draft.revision})});emailDrafts=emailDrafts.filter(d=>d.id!==draft.id);if(activeDraft?.id===draft.id){draftDirty=false;draftLock(false);openDraft(null);}renderDraftList();$('#reviewDialog').close();toast('Draft removed');}catch(e){$('#deleteDraftError').textContent=e.message;if(e.status===409)await refreshDrafts().catch(()=>{});button.disabled=false;}finally{draftLock(false);}};}
window.addEventListener('beforeunload',event=>{if(draftDirty){event.preventDefault();event.returnValue='';}});
Object.values(draftFields).forEach(id=>$('#'+id).addEventListener('input',()=>{markDraftDirty();if(id==='draftTo')showDraftSources();}));
$('#draftContact').onchange=()=>{if($('#draftContact').value){$('#draftTo').value=$('#draftContact').value;markDraftDirty();showDraftSources();}};
$('#draftForm').onsubmit=event=>{event.preventDefault();saveEmailDraft();};
$('#newDraft').onclick=()=>openDraft(null);
function closeDraftDialog(){if(draftBusy)return;if(draftDirty&&!window.confirm('Discard unsaved changes in this draft?'))return;draftDirty=false;$('#draftDialog').close();}
$('#draftDialogClose').onclick=closeDraftDialog;$('#draftDialog').addEventListener('cancel',event=>{event.preventDefault();closeDraftDialog();});
$('#previewDraft').onclick=previewEmailDraft;
$('#copyDraft').onclick=async()=>{try{await navigator.clipboard.writeText(draftText(draftValues()));toast('Email draft copied');}catch{previewEmailDraft();toast('Select the preview text to copy.');}};
$('#exportDraft').onclick=async()=>{const draft=await saveEmailDraft();if(draft){const link=document.createElement('a');link.href='/api/email-drafts/'+encodeURIComponent(draft.id)+'/export';link.download='email-draft.eml';document.body.append(link);link.click();link.remove();}};
$('#generateDraft').onclick=async()=>{const values=draftValues();if(!values.notes.trim()){$('#draftState').textContent='Add a drafting brief first.';$('#draftNotes').focus();return;}draftLock(true);$('#draftState').textContent='Preparing suggested wording…';try{const proposed=await post('/api/email-drafts/generate',{brief:values.notes,subject:values.subject,body:values.body,model:$('#llmModel').value});showDialog('Suggested wording',`<p class="notice">Review this suggestion before using it. Your sender and recipient details are kept as entered.</p><pre>${esc('Subject: '+proposed.subject+'\n\n'+proposed.body)}</pre><button class="btn primary" id="useDraftWording">Use this wording</button>`);$('#useDraftWording').onclick=()=>{$('#draftSubject').value=proposed.subject;$('#draftBody').value=proposed.body;markDraftDirty();$('#reviewDialog').close();};$('#draftState').textContent='Suggestion ready for review.';}catch(e){$('#draftState').textContent=e.message+' You can continue editing manually.';}finally{draftLock(false);}};
let autonomyRuns=[],autonomyCurrent='',autonomyEventFilter='key',autonomyLoaded=false;
document.querySelectorAll('[data-timeline-filter]').forEach(button=>button.onclick=()=>{autonomyEventFilter=button.dataset.timelineFilter;renderAutonomy();});
function setAutonomyMode(mode){autonomyMode=mode;for(const button of document.querySelectorAll('[data-autonomy-mode]'))button.setAttribute('aria-pressed',String(button.dataset.autonomyMode===mode));for(const name of ['group','discover','inventory'])$('#autonomy'+name[0].toUpperCase()+name.slice(1)+'Mode').hidden=name!==mode;}
document.querySelectorAll('[data-autonomy-mode]').forEach(button=>button.onclick=()=>setAutonomyMode(button.dataset.autonomyMode));
function openAutonomyNewRun(mode=autonomyMode){setAutonomyMode(mode);const dialog=$('#autonomyNewRun');if(!dialog.open)dialog.showModal();$('#autonomyNewRunClose').focus();}
$('#autonomyNewRunOpen').onclick=()=>openAutonomyNewRun();
$('#autonomyNewRunClose').onclick=()=>$('#autonomyNewRun').close();
$('#autonomyNewRun').onclose=()=>{$('#autonomyState').textContent='';};
function autonomyHostGroup(host){
  const name=String(host.name||'').toLowerCase();
  const suffix=savedScope.domains.map(domain=>domain.toLowerCase()).find(domain=>name.endsWith('.'+domain));
  if(!suffix)return 'Other / IP only';
  const prefix=name.slice(0,-suffix.length-1).split('.');
  return prefix.length>1?`${prefix[prefix.length-1]}.${suffix}`:suffix;
}
function autonomyHostChoices(){
  const hosts=map.targets.filter(t=>t.eligible).map(t=>t.host);
  const services=new Map(),flags=new Map();
  for(const finding of findings)if(finding.kind==='service'&&finding.hostId)services.set(finding.hostId,[...(services.get(finding.hostId)||[]),finding]);
  for(const flag of attentionFlags)if(flag.hostId)flags.set(flag.hostId,[...(flags.get(flag.hostId)||[]),flag]);
  return hosts.map(host=>({host,services:services.get(host.id)||[],flags:flags.get(host.id)||[],group:autonomyHostGroup(host)}));
}
function deepDiveRows(){
  const currentScope=JSON.stringify(savedScope);
  return map.targets.filter(target=>target.eligible).map(({host,services=[]})=>{
    const hostRuns=autonomyRuns.filter(run=>JSON.stringify(run.scope)===currentScope&&(run.hostId===host.id||(run.hostIds||[]).includes(host.id)));
    const checks=hostRuns.flatMap(run=>(run.events||[]).filter(event=>event.type==='check'&&(event.hostId?event.hostId===host.id:run.hostId===host.id)));
    const imported=checks.filter(event=>event.imported).length,failed=checks.filter(event=>event.outcome==='failed'||!event.imported).length;
    const aiFlags=hostRuns.flatMap(run=>(run.flags||[]).filter(flag=>flag.hostId===host.id));
    const ruleFlags=attentionFlags.filter(flag=>flag.hostId===host.id);
    const versions=vulnerabilityMatches.filter(match=>match.hostId===host.id);
    const leadCount=aiFlags.length+ruleFlags.length+versions.length;
    const gap=failed>0||imported===0;
    const latest=hostRuns.find(run=>run.hostId===host.id)||hostRuns[0];
    const next=(map.candidates||[]).find(candidate=>candidate.hostId===host.id);
    const score=(aiFlags.length?400:0)+(versions.length?300:0)+(ruleFlags.length?200:0)+(gap?100:0);
    const autoDive=hostRuns.flatMap(run=>(run.events||[]).filter(event=>event.type==='deep-dive-selection'&&event.hostId===host.id))[0];
    return {host,services,checks,imported,failed,aiFlags,ruleFlags,versions,leadCount,gap,latest,next,autoDive,score};
  }).sort((a,b)=>b.score-a.score||b.services.length-a.services.length||recordLabel(a.host).localeCompare(recordLabel(b.host),undefined,{numeric:true}));
}
function renderTriage(){
  const rows=deepDiveRows(),query=$('#triageSearch').value.trim().toLowerCase(),filter=$('#triageFilter').value;
  const shown=rows.filter(row=>(filter==='all'||filter==='leads'&&row.leadCount||filter==='gaps'&&row.gap)&&(!query||[row.host.name,row.host.ip,...row.services.map(service=>`${service.port} ${service.name||''} ${service.product||''} ${service.version||''}`)].some(value=>String(value||'').toLowerCase().includes(query))));
  $('#triageCount').textContent=`${shown.length} of ${rows.length} approved hosts`;
  const short=(value,n=180)=>String(value||'').slice(0,n);
  $('#triageList').innerHTML=shown.length?shown.map(row=>{
    const {host,services,imported,failed,aiFlags,ruleFlags,versions,leadCount,gap,latest,next,autoDive}=row;
    const tag=leadCount?`Evidence lead${gap?' · Coverage gap':''}`:gap?'Coverage gap':'Surveyed';
    const lead=aiFlags[0]?.reason||versions[0]&&`${versions[0].product} ${versions[0].observedVersion}: advisory match ${versions[0].cveId}; verify applicability.`||ruleFlags[0]?.reason||failed&&`${failed} check result${failed===1?'':'s'} failed or could not be imported.`||!imported&&'No imported AI check result yet.'||`${services.length} recorded service${services.length===1?'':'s'}; review the available checks.`;
    const serviceText=services.filter(service=>service.state==='open').slice(0,8).map(service=>`${service.port}/${service.protocol} ${service.product||service.name||'service'}${service.version?' '+service.version:''}`).join(' · ');
    const links=[...aiFlags,...ruleFlags,...versions].flatMap(item=>[...(item.findingIds||[]),...(item.evidenceIds||[])]);
    const ids=[...new Set(links)].filter(id=>findings.some(f=>f.id===id)||evidence.some(e=>e.id===id));
    const sourceLinks=ids.slice(0,8).map(id=>ref(id,findings.find(f=>f.id===id)?.title||evidence.find(e=>e.id===id)?.command||'Source evidence')).join(' · ');
    const active=autonomyRuns.some(run=>['running','awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(run.status));
    return `<article class="triage-card ${leadCount?'lead':gap?'gap':''}"><div class="triage-card-top"><h2>${esc(host.name||host.ip)}<small>${esc(host.ip)}</small></h2><span class="triage-tag">${esc(autoDive?'Auto-selected · '+tag:tag)}</span></div><p>${esc(short(lead,230))}</p><p class="triage-meta">${services.length} services · ${imported} saved AI checks${failed?` · ${failed} incomplete`:''} · ${aiFlags.length} AI flags · ${ruleFlags.length} rule leads · ${versions.length} version matches</p>${serviceText?`<p>${esc(serviceText)}</p>`:''}<details><summary>Why & sources</summary>${autoDive?`<p>Automatic deep dive: ${esc(short(autoDive.reason,300))}</p>`:''}${aiFlags.slice(0,2).map(flag=>`<p>AI flag: ${esc(short(flag.reason))}</p>`).join('')}${versions.slice(0,2).map(match=>`<p>Advisory match: ${esc(match.cveId)} · ${esc(match.product)} ${esc(match.observedVersion)}. Confirm configuration and patches.</p>`).join('')}${ruleFlags.slice(0,2).map(flag=>`<p>Rule lead: ${esc(short(flag.reason))}</p>`).join('')}${latest?`<p>Latest run: ${esc(latest.status)}${latest.stopReason?' · '+esc(short(latest.stopReason)):''}</p>`:''}${sourceLinks?`<p>Sources: ${sourceLinks}</p>`:'<p>No linked lead source yet.</p>'}${next?`<p>Available catalog check: ${esc(next.title)} · ${esc(short(next.reason))}</p>`:'<p>No catalog check currently available.</p>'}</details><div class="toolbar"><button class="btn primary" type="button" data-deep-dive="${esc(host.id)}" ${active?'disabled title="Finish the active run first"':''}>AI deep dive</button></div></article>`;
  }).join(''):'<div class="empty">No approved hosts match this view.</div>';
  wireRefs($('#triageList'));
  $('#triageList').querySelectorAll('[data-deep-dive]').forEach(button=>button.onclick=()=>{
    const id=button.dataset.deepDive;
    if(!map.targets.some(target=>target.eligible&&target.host.id===id))return;
    autonomySelectedHosts.clear();autonomySelectedHosts.add(id);$('#autonomyGroupFilter').value='all';$('#autonomyGroupSearch').value=map.targets.find(t=>t.host.id===id).host.ip;renderAutonomyGroupHosts();location.hash='#autonomy';showView();openAutonomyNewRun('group');$('#autonomyGroupSearch').focus();
  });
}
$('#triageSearch').oninput=renderTriage;
$('#triageFilter').onchange=renderTriage;
function renderAutonomyGroupHosts(){
  const choices=autonomyHostChoices(),search=$('#autonomyGroupSearch').value.trim().toLowerCase(),filter=$('#autonomyGroupFilter').value,segmentSelect=$('#autonomyGroupSegment'),segment=segmentSelect.value;
  const groups=[...new Set(choices.map(choice=>choice.group))].sort();
  segmentSelect.innerHTML='<option value="">All groups</option>'+groups.map(group=>`<option value="${esc(group)}">${esc(group)}</option>`).join('');
  segmentSelect.value=groups.includes(segment)?segment:'';
  const matches=choices.filter(choice=>{
    if(segmentSelect.value&&choice.group!==segmentSelect.value)return false;
    if(filter==='leads'&&!choice.flags.length&&!choice.services.length||filter==='flags'&&!choice.flags.length||filter==='services'&&!choice.services.length||filter==='unscanned'&&choice.services.length)return false;
    return !search||[recordLabel(choice.host),choice.group,...choice.services.map(service=>`${service.port}/${service.protocol} ${service.name||''} ${service.product||''}`),...choice.flags.map(flag=>`${flag.title||''} ${flag.reason||''}`)].some(value=>String(value).toLowerCase().includes(search));
  }).sort((a,b)=>b.flags.length-a.flags.length||b.services.length-a.services.length||recordLabel(a.host).localeCompare(recordLabel(b.host),undefined,{numeric:true}));
  const visible=matches;
  const box=$('#autonomyGroupList');
  box.innerHTML=visible.length?visible.map(({host,services,flags})=>{
    const lead=flags.length?(flags[0].reason||flags[0].title||'Review flag').slice(0,150):services.length?services.slice(0,3).map(service=>`${service.port}/${service.protocol} ${service.name||service.product||''}`).join(' · '):'No service evidence yet';
    const meta=`${flags.length} flag${flags.length===1?'':'s'} · ${services.length} service${services.length===1?'':'s'}`;
    return `<label class="autonomy-host-row"><input type="checkbox" data-autonomy-host="${esc(host.id)}" ${autonomySelectedHosts.has(host.id)?'checked':''}><span><strong>${esc(recordLabel(host))}</strong><small>${esc(meta)} · ${esc(autonomyHostGroup(host))}</small><small class="${flags.length?'host-lead':''}">${esc(lead)}</small></span></label>`;
  }).join(''):'<div class="empty">No approved host matches these filters.</div>';
  $('#autonomyGroupCount').textContent=`${visible.length} of ${choices.length} approved hosts shown`;
  const available=visible.filter(choice=>!autonomySelectedHosts.has(choice.host.id));
  $('#autonomyGroupSelectVisible').disabled=!available.length;
  $('#autonomyGroupSelectVisible').textContent='Select shown';
  $('#autonomyGroupSelectVisible').title='';
  $('#autonomyGroupClear').disabled=!autonomySelectedHosts.size;
  $('#autonomyGroupStart').disabled=!autonomySelectedHosts.size||autonomyRuns.some(run=>['running','awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(run.status));
  $('#autonomyGroupStart').textContent=autonomySelectedHosts.size===1?'Start deep dive':autonomySelectedHosts.size>1?'Start survey':'Start investigation';
  const chosen=choices.filter(choice=>autonomySelectedHosts.has(choice.host.id));
  const selectedButtons=chosen.map(({host})=>`<button type="button" data-remove-autonomy-host="${esc(host.id)}" aria-label="Remove ${esc(recordLabel(host))}">${esc(recordLabel(host))} ×</button>`).join('');
  $('#autonomyGroupSelected').innerHTML=`${chosen.length} host${chosen.length===1?'':'s'} selected`+(chosen.length>12?`<details><summary>Review selection</summary><div>${selectedButtons}</div></details>`:chosen.length?`<div>${selectedButtons}</div>`:'');
}
$('#autonomyGroupSearch').oninput=renderAutonomyGroupHosts;
$('#autonomyGroupFilter').onchange=renderAutonomyGroupHosts;
$('#autonomyGroupSegment').onchange=renderAutonomyGroupHosts;
$('#autonomyGroupSelectVisible').onclick=()=>{for(const input of $('#autonomyGroupList').querySelectorAll('[data-autonomy-host]:not(:checked)'))autonomySelectedHosts.add(input.dataset.autonomyHost);renderAutonomyGroupHosts();};
$('#autonomyGroupClear').onclick=()=>{autonomySelectedHosts.clear();renderAutonomyGroupHosts();};
$('#autonomyGroupSelected').onclick=event=>{const button=event.target.closest('[data-remove-autonomy-host]');if(button){autonomySelectedHosts.delete(button.dataset.removeAutonomyHost);renderAutonomyGroupHosts();}};
$('#autonomyGroupList').onchange=event=>{const input=event.target.closest('[data-autonomy-host]');if(!input)return;if(input.checked)autonomySelectedHosts.add(input.dataset.autonomyHost);else autonomySelectedHosts.delete(input.dataset.autonomyHost);renderAutonomyGroupHosts();};
function requireAutonomyModel(){if(autonomyModelRequired&&!$('#autonomyModel').value){$('#autonomyModelState').textContent='Choose one of the available models before starting.';$('#autonomyModel').focus();return false;}return true;}
$('#autonomyModel').onchange=()=>{if($('#autonomyModel').value)$('#autonomyModelState').textContent='';};
function briefingModelOptions(){const select=$('#briefingModel'),selected=select.value,known=new Set([...select.options].map(o=>o.value));for(const model of autonomyRuns.map(r=>r.model).filter(m=>typeof m==='string'&&m.length<=200&&m!=='server default')){if(!known.has(model)){select.insertAdjacentHTML('beforeend',`<option value="${esc(model)}">Previously used: ${esc(model)}</option>`);known.add(model);}}select.value=known.has(selected)?selected:'';}
function briefingApprovedHosts(){return map.targets.filter(t=>t.eligible).map(t=>t.host);}
function briefingHostIds(){return briefingApprovedHosts().map(h=>h.id);}
function briefingTurn(role,html){return `<div class="briefing-turn ${role}"><span class="briefing-speaker">${role==='user'?'You':'Yagura'}</span><div class="briefing-bubble">${html}</div></div>`;}
function briefingSources(findingIds,evidenceIds){const fids=(findingIds||[]).filter(id=>findings.some(f=>f.id===id)),eids=(evidenceIds||[]).filter(id=>evidence.some(e=>e.id===id));if(!fids.length&&!eids.length)return '';const links=(fs,es)=>fs.map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)))).join('')+es.map(id=>ref(id,'Source evidence')).join('');const remaining=fids.slice(2).length+eids.slice(2).length;return `<div class="briefing-links">${links(fids.slice(0,2),eids.slice(0,2))}${remaining?`<details><summary>Show ${remaining} more source${remaining===1?'':'s'}</summary><div class="briefing-links">${links(fids.slice(2),eids.slice(2))}</div></details>`:''}</div>`;}
function briefingNearBottom(){const box=$('#briefingTranscript');return box.scrollHeight-box.scrollTop-box.clientHeight<80;}
function updateBriefingLatest(){$('#briefingLatest').hidden=briefingNearBottom();}
function briefingCandidateCard(candidate,messageIndex,result){
  const host=findings.find(f=>f.id===candidate.hostId);
  return `<div class="briefing-check"><strong>${esc(candidate.title)} · ${esc(recordLabel(host||{title:candidate.hostId}))}</strong><p>${esc(candidate.reason)}</p><button class="btn" type="button" data-briefing-review="${esc(candidate.id)}" data-briefing-message="${messageIndex}">Review command</button>${result?`<p class="status">${esc(checkOutcome(result))} · ${result.imported?'Findings updated':'Review the recorded output'}</p><button class="btn" type="button" data-briefing-result="${esc(candidate.id)}" data-briefing-message="${messageIndex}">View result</button>`:''}</div>`;
}
function renderBriefing(){
  briefingModelOptions();
  const box=$('#briefingTranscript');
  const hostIds=briefingHostIds(),selected=new Set(hostIds),latest=autonomyRuns.find(r=>r.scope&&JSON.stringify(r.scope)===JSON.stringify(savedScope)&&(r.hostIds||[r.hostId]).some(id=>selected.has(id)));
  const contextKey=JSON.stringify({scope:savedScope,hostIds});
  if(briefingContextKey!==contextKey){briefingMessages=[];briefingSavedResults={};briefingContextKey=contextKey;}
  if(!scopeLoaded||!checkScope()||!hostIds.length){box.innerHTML='<div class="empty">Save a target scope and approve hosts to see a briefing.</div>';$('#briefingUpdated').textContent='No approved hosts';$('#briefingAsk').disabled=true;return;}
  $('#briefingAsk').disabled=briefingBusy;
  const briefLabel=`Approved · ${hostIds.length} host${hostIds.length===1?'':'s'}`;
  $('#briefingUpdated').textContent=`${briefLabel} · ${findings.filter(f=>selected.has(f.id)||selected.has(f.hostId)).length} findings`;
  const flags=autonomyRuns.filter(r=>r.scope&&JSON.stringify(r.scope)===JSON.stringify(savedScope)).flatMap(r=>(r.flags||[]).map(f=>({...f,runAt:r.endedAt||r.startedAt}))).filter(f=>selected.has(f.hostId)&&f.findingIds?.some(id=>findings.some(row=>row.id===id))&&f.evidenceIds?.some(id=>evidence.some(row=>row.id===id))).filter((f,i,rows)=>rows.findIndex(row=>row.hostId===f.hostId&&row.reason===f.reason)===i);
  let found='';
  if(flags.length){found=`<p class="briefing-meta">Review flags across approved hosts · hypotheses for review</p>`+flags.slice(0,3).map(f=>`<p><strong>${esc(recordLabel(findings.find(h=>h.id===f.hostId)||{title:f.hostId}))}</strong>: ${esc(f.reason)}</p><p class="briefing-meta">Still uncertain: ${esc(f.uncertainty)}</p>${briefingSources(f.findingIds,f.evidenceIds)}`).join('');}
  else if(latestAnalysis&&!latestAnalysis.stale){const rows=(latestAnalysis.assessments||[]).filter(a=>a.findingIds?.length&&a.findingIds.every(id=>findings.some(f=>f.id===id&&(selected.has(f.id)||selected.has(f.hostId)))));found=rows.slice(0,3).map(a=>`<p>${esc(a.interpretation)}</p>${briefingSources(a.findingIds,a.evidenceIds)}`).join('');}
  if(!found){const rows=findings.filter(f=>f.kind==='observation'&&selected.has(f.hostId)&&f.evidenceIds?.length).sort((a,b)=>String(b.lastSeen||'').localeCompare(String(a.lastSeen||''))).slice(0,3);found=rows.length?rows.map(f=>`<p><strong>${esc(f.title||'Observation')}</strong> · ${esc(recordLabel(findings.find(h=>h.id===f.hostId)||{title:f.hostId}))}: ${esc(f.detail||'Recorded observation')}</p>${briefingSources([f.id],f.evidenceIds.slice(0,1))}`).join(''):'<p>No linked observations have been recorded for these hosts yet.</p>';}
  const recentCommands=new Set(evidence.filter(e=>e.command&&e.output&&Number.isFinite(Date.parse(e.observedAt))&&Date.now()-Date.parse(e.observedAt)<86400000).map(e=>e.command));
  const candidateKeys=new Set(),candidates=map.candidates.filter(c=>selected.has(c.hostId)&&!recentCommands.has(c.command)).sort((a,b)=>Number(flags.some(f=>f.hostId===b.hostId))-Number(flags.some(f=>f.hostId===a.hostId))).filter(c=>{const key=c.hostId+'|'+c.title;if(candidateKeys.has(key))return false;candidateKeys.add(key);return true;}).slice(0,3);
  briefingSavedCandidates=candidates;
  const savedResults=Object.entries(briefingSavedResults).filter(([id])=>!candidates.some(c=>c.id===id)).map(([id,result])=>`<div class="briefing-check"><strong>${esc(result.title||'Completed check')}</strong><p class="status">${esc(checkOutcome(result))}</p><button class="btn" type="button" data-briefing-result="${esc(id)}" data-briefing-message="-1">View result</button></div>`).join('');
  const next=(candidates.length?candidates.map(c=>briefingCandidateCard(c,-1,briefingSavedResults[c.id])+briefingSources(c.findingIds,c.evidenceIds)).join(''):'<p>No untried catalog check is currently available for this selection. Review the flagged findings, then describe a specific follow-up in <a href="#checks">Next checks</a> for human review.</p>')+savedResults;
  const recent=latest?`<p>${esc(date(latest.startedAt))}: ${esc(latest.status)} · ${(latest.events||[]).filter(e=>e.type==='check').length} recorded check(s).</p>${latest.stopReason?`<p>${esc(latest.stopReason)}</p>`:''}<p><a href="#autonomy">Open the full AI log →</a></p>`:'<p>No autonomous run has been recorded for these hosts yet.</p>';
  const follow=briefingNearBottom(),position=box.scrollTop;
  const openSections=new Set([...box.querySelectorAll('details[data-briefing-section][open]')].map(row=>row.dataset.briefingSection));
  const section=(id,label,content)=>`<details data-briefing-section="${id}" ${openSections.has(id)?'open':''}><summary>${label}</summary><div class="briefing-section-body">${content}</div></details>`;
  const overview=section('found','Current picture',found)+section('next',`Suggested checks · ${candidates.length}`,next)+section('recent','Latest run',recent);
  box.innerHTML=briefingTurn('assistant',`<div class="briefing-overview">${overview}</div>`)+briefingMessages.map((m,i)=>briefingTurn('user',`<p>${esc(m.question)}</p>`)+briefingTurn('assistant',`<p>${esc(m.reply.answer)}</p>${m.reply.uncertainty?`<p class="briefing-meta">Uncertainty: ${esc(m.reply.uncertainty)}</p>`:''}${m.reply.coverage?`<p class="briefing-meta">Inventory: ${esc(m.reply.coverage.inventoryHosts)}/${esc(m.reply.coverage.approvedHosts)} approved hosts · Detailed evidence: ${esc(m.reply.coverage.detailHosts)} hosts</p>`:''}${briefingSources(m.reply.findingIds,m.reply.evidenceIds)}${(m.reply.candidates||[]).map(c=>briefingCandidateCard(c,i,m.results?.[c.id])).join('')}`)).join('');
  wireRefs(box);
  box.querySelectorAll('[data-briefing-review]').forEach(button=>button.onclick=()=>reviewBriefingCandidate(Number(button.dataset.briefingMessage),button.dataset.briefingReview));
  box.querySelectorAll('[data-briefing-result]').forEach(button=>button.onclick=()=>{const i=Number(button.dataset.briefingMessage),result=(i===-1?briefingSavedResults:briefingMessages[i]?.results)?.[button.dataset.briefingResult];if(result)showDialog('Check output',`<p class="mono">${esc(result.command)}</p><p class="status">${esc(checkOutcome(result))}${result.imported?' · Findings updated':''}</p><pre>${esc(result.output||result.stderr||'No output.')}</pre>`);});
  box.scrollTop=follow?box.scrollHeight:position;
  updateBriefingLatest();
}
$('#briefingTranscript').addEventListener('scroll',updateBriefingLatest);
$('#briefingLatest').onclick=boxScroll;
$('#briefingSettingsOpen').onclick=()=>$('#briefingSettingsDialog').showModal();
$('#briefingSettingsClose').onclick=()=>$('#briefingSettingsDialog').close();
$('#briefingRefresh').onclick=async()=>{const button=$('#briefingRefresh');button.disabled=true;$('#briefingState').textContent='Refreshing saved evidence…';try{briefingMessages=[];briefingSavedResults={};await refreshFindings();await loadAutonomyHistory();renderBriefing();$('#briefingState').textContent='';}catch(e){$('#briefingState').textContent=e.message;}finally{button.disabled=false;}};
$('#briefingAsk').onclick=async()=>{const question=$('#briefingQuestion').value.trim();if(question.length<3||!briefingHostIds().length){$('#briefingState').textContent='Enter a question after approving hosts in Scope.';return;}const button=$('#briefingAsk'),contextKey=briefingContextKey;briefingBusy=true;button.disabled=true;$('#briefingState').textContent='Reading the approved inventory and linked evidence…';try{const reply=await post('/api/briefing/ask',{question,model:$('#briefingModel').value});if(contextKey===briefingContextKey){briefingMessages.push({question,reply,results:{}});$('#briefingQuestion').value='';renderBriefing();$('#briefingState').textContent='';}}catch(e){$('#briefingState').textContent=e.message;}finally{briefingBusy=false;button.disabled=!briefingHostIds().length;}};
function boxScroll(){const box=$('#briefingTranscript');box.scrollTop=box.scrollHeight;updateBriefingLatest();}
async function reviewBriefingCandidate(messageIndex,candidateId){
  const message=briefingMessages[messageIndex],proposed=(messageIndex===-1?briefingSavedCandidates:message?.reply.candidates)?.find(c=>c.id===candidateId),contextKey=briefingContextKey;
  if(!proposed||!checkScope()){$('#briefingState').textContent='This suggestion is no longer available. Ask again with the current scope.';return;}
  $('#briefingState').textContent='Checking the current command and approved target…';
  try{
    const fresh=(await api('/api/workflow')).candidates.find(c=>c.id===candidateId&&c.hostId===proposed.hostId);
    if(!fresh||contextKey!==briefingContextKey||messageIndex!==-1&&briefingMessages[messageIndex]!==message)throw new Error('The suggested check or conversation changed. Ask again before approving.');
    const host=findings.find(f=>f.id===fresh.hostId);
    if(!host)throw new Error('The approved host is no longer available.');
    showDialog('Review suggested check',`<p class="notice">Review this current, validated check before running it. No command runs when you open this review.</p><p><strong>${esc(fresh.title)}</strong> · ${esc(recordLabel(host))}</p><p>${esc(fresh.reason)}</p><pre>${esc(fresh.command)}</pre><p class="status">Saved scope: ${esc(scopeLabel())}</p><p class="status" id="briefingReviewState" role="status"></p><button class="btn primary" id="briefingRunCheck" type="button">Approve and run</button>`);
    $('#briefingRunCheck').onclick=async()=>{
      if(!await confirmScopedAction('Approve suggested check?',`Target: ${esc(recordLabel(host))}<pre>${esc(fresh.command)}</pre>`,'Approve and run'))return;
      const button=$('#briefingRunCheck');button.disabled=true;$('#briefingReviewState').textContent='Running the approved check…';
      try{
        const result=await post('/api/checks/run',{candidateId:fresh.id,expectedCommand:fresh.command,authorized:true,authorizedScope:checkScope()});
        $('#reviewDialog').close();if(messageIndex===-1)briefingSavedResults[fresh.id]={...result,title:fresh.title};else message.results[fresh.id]=result;
        if(result.imported)await refreshFindings();else renderBriefing();
        $('#briefingState').textContent='';
      }catch(e){$('#briefingReviewState').textContent=e.message;button.disabled=false;}
    };
    $('#briefingState').textContent='';
  }catch(e){$('#briefingState').textContent=e.message;}
}
let checkProposals=[];
function renderCheckProposals(){
  const box=$('#proposalList');
  box.innerHTML=checkProposals.length?checkProposals.map(p=>{
    const manual=p.kind==='manual';
    const actions=manual?`<button class="btn" data-review-proposal="${esc(p.id)}">Review ${p.reviewStatus==='approved'?'again':'command'}</button>${p.reviewStatus==='approved'&&!p.stale?`<button class="btn" data-copy-manual="${esc(p.id)}">Copy after review</button>${!p.manualEvidenceId?`<button class="btn" data-record-manual="${esc(p.id)}">Record manual result</button>`:''}`:''}`:`<button class="btn primary" data-run-proposal="${esc(p.id)}" ${p.stale?'disabled':''}>Run saved check</button>`;
    const state=p.stale?'Scope or target changed; request a new proposal.':manual?`Human review: ${esc(p.reviewStatus||'pending')} · ${p.manualEvidenceId?'Manual result recorded; reference added to catalog.':'Yagura cannot execute this command.'}`:p.lastOutcome?'Last result: '+esc(p.lastOutcome):'Not run yet.';
    return `<div class="cmd"><div class="cmdtop"><strong>${esc(p.title)} · ${esc(p.hostName||p.hostIp)}</strong><div class="cmd-actions">${actions}</div></div><p>Requested: ${esc(p.request)}</p><p>AI's reason: ${esc(p.reason)} · ${esc(p.model)} · ${esc(date(p.createdAt))}</p><code>${manual&&p.reviewStatus!=='approved'?'Open Review to inspect the full command.':esc(p.command)}</code><p class="status">${state}</p><p>${evidenceLinks(p.lastEvidenceIds||p.evidenceIds)}</p></div>`;
  }).join(''):'<div class="empty">No AI-created checks yet. Choose a host and describe one check above.</div>';
  wireRefs(box);
  box.querySelectorAll('[data-run-proposal]').forEach(button=>button.onclick=async()=>{
    const proposal=checkProposals.find(p=>p.id===button.dataset.runProposal);if(!proposal||!await confirmScopedAction('Run saved check?',`Target: ${esc(proposal.hostName||proposal.hostIp)}<pre>${esc(proposal.command)}</pre>`,'Run check'))return;
    button.disabled=true;$('#proposalState').textContent='Running the saved, validated check…';
    try{await scopeSave;const result=await post('/api/check-proposals/run',{proposalId:button.dataset.runProposal,authorized:true,authorizedScope:checkScope()});if(result.imported)await refreshFindings();await loadCheckProposals();showDialog('Check output',`<p class="mono">${esc(result.command)}</p><p class="status">${checkOutcome(result)}${result.imported?' · Findings updated':''}</p><pre>${esc(result.output||result.stderr||'No output.')}</pre>`);$('#proposalState').textContent=checkOutcome(result)+' · review linked evidence.';}
    catch(e){$('#proposalState').textContent=e.message;button.disabled=false;}
  });
  box.querySelectorAll('[data-review-proposal]').forEach(button=>button.onclick=()=>reviewManualProposal(checkProposals.find(p=>p.id===button.dataset.reviewProposal)));
  box.querySelectorAll('[data-copy-manual]').forEach(button=>button.onclick=async()=>{button.disabled=true;try{const current=(await api('/api/check-proposals')).proposals.find(row=>row.id===button.dataset.copyManual);if(!current||current.kind!=='manual'||current.reviewStatus!=='approved'||current.stale){$('#proposalState').textContent='Approval or scope changed; review the proposal again.';await loadCheckProposals();return;}await navigator.clipboard.writeText(current.command);toast('Reviewed command copied; run it only in an authorized environment.');}catch{$('#proposalState').textContent='Clipboard unavailable; select the reviewed command manually.';}finally{button.disabled=false;}});
  box.querySelectorAll('[data-record-manual]').forEach(button=>button.onclick=()=>recordManualResult(checkProposals.find(p=>p.id===button.dataset.recordManual)));
}
function recordManualResult(p){if(!p)return;showDialog('Record manual execution',`<p class="notice warning">Yagura will not run this command. Only record a result after you have run this exact command in an authorized environment. Review and redact the output before pasting it; the imported evidence is marked sensitive by default.</p><pre>${esc(p.command)}</pre><div class="field"><label for="manualResultOutput">Command output or redacted excerpt</label><textarea id="manualResultOutput" rows="8" maxlength="12000" placeholder="Paste the observed result"></textarea></div><p class="status" id="manualResultState"></p><button class="btn primary" id="saveManualResult">Save result and add reference</button>`);$('#saveManualResult').onclick=async()=>{const output=$('#manualResultOutput').value;if(!await confirmScopedAction('Record manual result?',`Confirm you ran this exact command in an authorized environment and reviewed the ${output.length} characters of output before saving it as sensitive evidence.<pre>${esc(p.command)}</pre>`,'Save result'))return;const button=$('#saveManualResult');button.disabled=true;try{await post('/api/check-proposals/manual-result',{proposalId:p.id,expectedCommand:p.command,output,acknowledged:true,authorizedScope:checkScope()});$('#reviewDialog').close();await refreshFindings();await loadCheckProposals();{const c=await api('/api/commands');toolCatalog=c.tools||[];renderCatalog();}$('#proposalState').textContent='Manual result recorded as sensitive evidence; reference added to the catalog.';}catch(e){$('#manualResultState').textContent=e.message;button.disabled=false;}};}
function reviewManualProposal(p){if(!p)return;showDialog('Human review required',`<p class="notice warning">This AI-generated command is not validated for execution by Yagura. Check every destination, argument, side effect and credential exposure. Never run it from kaliai05 against the Internet.</p><p>Approved host: ${esc(p.hostName||p.hostIp)} (${esc(p.hostIp)}) · Saved scope: ${esc((p.scope?.cidrs||[]).join(', '))}</p><pre>${esc(p.command)}</pre><p class="status" id="manualReviewState"></p><div class="toolbar"><button class="btn primary" id="approveManualCheck">Approve for manual use</button><button class="btn" id="rejectManualCheck">Reject</button></div>`);const decide=async decision=>{if(decision==='approve'&&!await confirmScopedAction('Approve for manual use?',`Review every destination, argument, side effect and credential exposure. Yagura will not execute this command. Target: ${esc(p.hostName||p.hostIp)}<pre>${esc(p.command)}</pre>`,'Approve for manual use'))return;$('#approveManualCheck').disabled=true;$('#rejectManualCheck').disabled=true;try{await post('/api/check-proposals/review',{proposalId:p.id,expectedCommand:p.command,decision,acknowledged:decision==='approve',authorizedScope:checkScope()});$('#reviewDialog').close();await loadCheckProposals();{const c=await api('/api/commands');toolCatalog=c.tools||[];renderCatalog();}$('#proposalState').textContent=decision==='approve'?'Approved for manual use only. Yagura will not execute it.':'Manual proposal rejected.';}catch(e){$('#manualReviewState').textContent=e.message;$('#approveManualCheck').disabled=false;$('#rejectManualCheck').disabled=false;}};$('#approveManualCheck').onclick=()=>decide('approve');$('#rejectManualCheck').onclick=()=>decide('reject');}
async function loadCheckProposals(){try{checkProposals=(await api('/api/check-proposals')).proposals||[];renderCheckProposals();}catch(e){$('#proposalState').textContent=e.message;}}
$('#proposalNewOpen').onclick=()=>$('#proposalNewDialog').showModal();$('#proposalNewClose').onclick=()=>$('#proposalNewDialog').close();
$('#proposeCheck').onclick=async()=>{const hostId=$('#proposalHost').value,request=$('#proposalRequest').value.trim();if(!hostId||!checkScope()){$('#proposalState').textContent='Choose an approved host in the saved scope.';return;}if(request.length<5){$('#proposalState').textContent='Describe one check in at least five characters.';return;}const button=$('#proposeCheck');button.disabled=true;$('#proposalState').textContent='AI is preparing a check proposal…';try{await scopeSave;const result=await post('/api/check-proposals',{hostId,request,model:$('#proposalModel').value,authorizedScope:checkScope()});if(result.added){$('#proposalState').textContent=result.proposal.kind==='manual'?'Manual proposal saved. A human must review it; Yagura cannot execute it.':'Bounded proposal saved. Review the command and confirm authorization before running.';$('#proposalRequest').value='';await loadCheckProposals();$('#proposalNewDialog').close();toast('Check proposal saved');}else{$('#proposalState').textContent='Not added: '+result.reason;}}catch(e){$('#proposalState').textContent=e.message;}finally{button.disabled=false;}};
function renderAutonomy(){
  const select=$('#autonomyHistory'),selected=autonomyCurrent||select.value;
  select.innerHTML=autonomyRuns.length?autonomyRuns.map(r=>`<option value="${esc(r.id)}">${esc(date(r.startedAt))} · ${esc(r.hostName||r.hostIp)} · ${esc(r.status)}</option>`).join(''):'<option value="">No runs yet</option>';
  autonomyCurrent=autonomyRuns.some(r=>r.id===selected)?selected:autonomyRuns[0]?.id||'';
  select.value=autonomyCurrent;
  const run=autonomyRuns.find(r=>r.id===autonomyCurrent),active=autonomyRuns.find(r=>['running','awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(r.status));
  const now=$('#autonomyNow'),reviewAction=$('#autonomyReviewAction');
  document.querySelectorAll('[data-ai-state]').forEach(modeState=>{modeState.hidden=!active;modeState.textContent=active?.status==='running'?'Investigation running':active?'Your review is needed':'';});
  now.classList.toggle('attention',!!active&&active.status!=='running');
  now.querySelector('strong').textContent=active?active.status==='running'?'Investigation running':active.status==='awaiting-approval'?'Command approval required':'Discovery needs your review':'No active investigation';
  now.querySelector('p').textContent=active?`${active.phase==='deep-dive'?'Deep dive: '+autonomyHostLabel(active.deepDiveHostId||active.hostId):active.hostName||active.hostIp} · ${active.events.filter(e=>e.type==='check').length}/${active.maxChecks==null?'∞':active.maxChecks} checks${active.stopReason?' · '+active.stopReason:''}`:'';
  reviewAction.hidden=!active||active.status==='running';
  if(active)reviewAction.textContent=active.status==='awaiting-approval'?'Review proposed command':active.status==='awaiting-host-review'?'Review host names in Scope':active.mode==='group'?'Continue survey':'Continue discovery';
  $('#autonomyStop').disabled=!active;now.classList.toggle('idle',!active);
  $('#autonomyGroupStart').disabled=!!active||!autonomySelectedHosts.size;
  $('#autonomyDiscoverStart').disabled=!!active;
  $('#autonomyInventoryStart').disabled=!!active||!autonomyInventoryReady;
  $('#autonomyDiscoverResume').disabled=!active||!['awaiting-host-review','awaiting-discovery'].includes(active.status);
  $('#autonomyDiscoverResume').hidden=!active||!['awaiting-host-review','awaiting-discovery'].includes(active.status);
  $('#autonomyNewRunOpen').disabled=!!active;
  const outcome=$('#autonomyOutcome');
  outcome.innerHTML=run?`<strong>${esc(run.status)} · ${esc(run.hostName||run.hostIp)}</strong><p>${esc(date(run.startedAt))} · ${run.events.filter(e=>e.type==='check').length}/${run.maxChecks==null?'∞':run.maxChecks} checks · Model: ${esc(run.model||'server default')}</p>${run.stopReason?`<p>${esc(run.stopReason)}</p>`:''}${run.deepDiveHostId?`<p><strong>Automatic deep dive:</strong> ${esc(autonomyHostLabel(run.deepDiveHostId))}${run.deepDiveReason?' · '+esc(run.deepDiveReason):''}</p>`:''}${(run.flags||[]).length?`<p><strong>${run.flags.length} check result${run.flags.length===1?'':'s'} flagged for review</strong></p>${run.flags.map(f=>`<p>${ref(f.hostId,recordLabel(findings.find(h=>h.id===f.hostId)||{title:f.hostId}))}: ${esc(f.reason)}</p>`).join('')}<p><a href="#briefing">Review flags and sources in Briefing →</a></p>`:''}`:'<strong>No run selected</strong><p>Start an investigation to see its result here.</p>';
  wireRefs(outcome);
  $('#autonomyEventSummary').textContent=run?`Detailed event log · ${run.events.length} ${run.events.length===1?'event':'events'}`:'Detailed event log';
  const box=$('#autonomyTimeline');
  const ruleChangeHtml=e=>(e.ruleChanges||[]).length?`<details><summary>Rule leads changed after this check (${e.ruleChanges.length})</summary>${e.ruleChanges.map(change=>`<p>${esc(change.change)} · ${esc(change.title)} · ${esc(change.reason)}${change.evidenceIds?.length?` · ${evidenceLinks(change.evidenceIds)}`:''}</p>`).join('')}</details>`:'';
  const eventHtml=e=>{
    if(e.type==='decision')return `<div class="cmd"><strong>Step ${esc(e.step)} · AI decision</strong><p>${e.choice?`Chose ${esc(e.title)} · <code>${esc(e.command)}</code>`:'Chose to stop'}</p><p>Why: ${esc(e.reason)}</p>${e.expectedEvidence?`<p>Expected evidence: ${esc(e.expectedEvidence)}</p>`:''}<p>${evidenceLinks(e.evidenceIds)}</p></div>`;
    if(e.type==='check')return `<div class="cmd"><strong>Step ${esc(e.step)} · ${e.reviewed?'Human-approved check':'Check'} result: ${esc(e.outcome)}</strong>${e.hostId?`<p>Host: ${esc(recordLabel(findings.find(f=>f.id===e.hostId)||{title:e.hostId}))}</p>`:''}<p>${e.imported?'Findings imported':'No findings imported'}${e.warning?' · '+esc(e.warning):''}</p><p>Evidence: ${evidenceLinks(e.evidenceIds)||'none'}</p>${e.summary?`<p>Response excerpt: ${esc(e.summary)}</p>`:''}</div>`;
    if(e.type==='flag-review')return `<div class="cmd"><strong>${e.flag?'Check result flagged for review':'Check result reviewed · no flag'}</strong><p>${esc(recordLabel(findings.find(f=>f.id===e.hostId)||{title:e.hostId}))}</p>${ruleChangeHtml(e)}${e.flag?`<p>${esc(e.flag.reason)}</p><p>Uncertainty: ${esc(e.flag.uncertainty)}</p><p>${(e.flag.findingIds||[]).map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:id}))).join(' · ')}</p><p>${evidenceLinks(e.flag.evidenceIds)}</p>`:''}</div>`;
    if(e.type==='flag-review-error')return `<div class="cmd"><strong>Check result flag review unavailable</strong><p>${esc(e.reason)}</p>${ruleChangeHtml(e)}</div>`;
    if(e.type==='proposal')return `<div class="cmd"><strong>Proposed command · revision ${esc(e.revision)}</strong>${e.tool?`<p>Tool: ${esc(e.tool)} · ${e.catalogued===false?'Not in catalog · human review required':'Catalogued'} · Local help: ${esc(e.helpInvocation||'not read')}</p>`:''}<p><code>${esc(e.command)}</code></p><p>Why: ${esc(e.reason)}</p>${e.reviewNotes?`<p>Review notes: ${esc(e.reviewNotes)}</p>`:''}${e.revisionInstruction?`<p>Human correction: ${esc(e.revisionInstruction)}</p>`:''}</div>`;
    if(e.type==='approval')return `<div class="cmd"><strong>Human approved revision ${esc(e.revision)}</strong><p><code>${esc(e.command)}</code></p></div>`;
    if(e.type==='auto-approval')return `<div class="cmd"><strong>Catalog check validated</strong><p><code>${esc(e.command)}</code></p><p>${esc(e.reason)}</p></div>`;
    if(e.type==='duplicate-skipped')return `<div class="cmd"><strong>Repeated check skipped</strong><p><code>${esc(e.command)}</code></p><p>${esc(e.reason)}</p></div>`;
    if(e.type==='deep-dive-selection')return `<div class="cmd"><strong>Automatic deep dive · ${esc(recordLabel(findings.find(f=>f.id===e.hostId)||{title:e.hostId}))}</strong><p>${esc(e.reason)}</p><p>${evidenceLinks(e.evidenceIds)}</p></div>`;
    if(e.type==='survey-batch')return `<div class="cmd"><strong>Survey batch</strong><p>${esc(e.completed)} of ${esc(e.total)} hosts already surveyed · next ${esc(e.size)} hosts</p></div>`;
    if(e.type==='survey')return `<div class="cmd"><strong>Baseline survey · ${esc(recordLabel(findings.find(f=>f.id===e.hostId)||{title:e.hostId}))}</strong><p>${esc(e.reason)}</p>${e.candidateId?`<p>Candidate: ${esc(e.candidateId)}</p>`:''}</div>`;
    if(e.type==='context')return `<div class="cmd"><strong>Comparison context prepared</strong><p>${esc(e.findingIds?.length||0)} findings · ${esc(e.evidenceIds?.length||0)} evidence items · ${esc(e.candidateIds?.length||0)} candidate checks${e.truncated?' · More saved context is available on request.':''}</p><p>Snapshot: <code>${esc((e.snapshotId||'').slice(0,12))}</code></p></div>`;
    if(e.type==='context-read')return `<div class="cmd"><strong>AI requested saved context</strong>${(e.operations||[]).map(o=>`<p>${esc(o.tool)}${o.hostId?' · '+esc(recordLabel(findings.find(f=>f.id===o.hostId)||{title:o.hostId})):''}${o.offset?' · offset '+esc(o.offset):''} · ${esc(o.findingIds?.length||0)} findings, ${esc(o.evidenceIds?.length||0)} evidence items, ${esc(o.candidateIds?.length||0)} candidates</p>`).join('')}</div>`;
    if(e.type==='context-request-repair')return `<div class="cmd"><strong>AI context request correction requested</strong><p>${esc(e.reason)}</p>${(e.submittedRequests||[]).map(r=>`<p>${esc(r.tool||'unknown tool')}${r.hostId?' · hostId '+esc(r.hostId):''}</p>`).join('')}</div>`;
    if(e.type==='context-repair')return `<div class="cmd"><strong>AI citation correction requested</strong><p>${esc(e.reason)}</p>${(e.submittedFlags||[]).map(f=>`<p>hostId ${esc(f.hostId)} · findingIds ${esc((f.findingIds||[]).join(', ')||'none')} · evidenceIds ${esc((f.evidenceIds||[]).join(', ')||'none')}</p>`).join('')}</div>`;
    if(e.type==='model-retry')return `<div class="cmd"><strong>AI response retry</strong><p>${esc(e.reason)} Retrying with up to ${esc(e.maxTokens)} output tokens.</p></div>`;
    if(e.type==='comparison')return `<div class="cmd"><strong>Cross-host comparison · ${esc(e.flags.length)} flagged</strong><p>${esc(e.reason||'Review the cited evidence and uncertainty.')}</p>${e.flags.map(f=>`<div class="finding-record"><strong>${esc(recordLabel(findings.find(x=>x.id===f.hostId)||{title:f.hostId}))}</strong><p>${esc(f.reason)}</p><p>Uncertainty: ${esc(f.uncertainty)}</p><p>${f.findingIds.map(id=>ref(id,recordLabel(findings.find(x=>x.id===id)||{title:id}))).join(' · ')}</p><p>${evidenceLinks(f.evidenceIds)}</p></div>`).join('')}${e.choice?`<p>Next catalog check: ${esc(e.choice)}</p>`:''}</div>`;
    if(e.type==='discovery')return `<div class="cmd"><strong>Discovery segment ${esc(e.cidr)}</strong><p>${esc(e.count)} host(s) found · ${esc(e.completed)}/${esc(e.total)} segments in this range</p></div>`;
    if(e.type==='dns-review')return `<div class="cmd"><strong>DNS review · ${esc(e.hostIp)}</strong><p>Approved-name candidates: ${esc((e.candidates||[]).join(', ')||'none')}${e.conflicting?' · resolver conflict':''}</p></div>`;
    if(e.type==='selection')return `<div class="cmd"><strong>Automatically selected ${esc(e.hostIds.length)} approved hosts</strong><p>${esc(e.reason)}</p><p>${e.hostIds.map(id=>ref(id,recordLabel(findings.find(f=>f.id===id)||{title:id}))).join(' · ')}</p></div>`;
    if(e.type==='pause')return `<div class="cmd"><strong>Waiting for review or continuation</strong><p>${esc(e.reason)}</p><p><a href="#scope">Review discovered hosts in Scope</a></p></div>`;
    return `<div class="cmd"><strong>Run ${run?.status==='completed'?'completed':'stopped'} · ${esc(date(e.at))}</strong><p>${esc(e.reason)}</p></div>`;
  };
  const isKeyEvent=e=>!['context','context-read','context-request-repair','context-repair','model-retry','survey-batch','auto-approval'].includes(e.type)&&(e.type!=='flag-review'||!!e.flag);
  const eventTitle=e=>({decision:e.choice?'AI chose a check':'AI stopped',check:e.reviewed?'Approved check finished':'Check finished','flag-review':e.flag?'Flagged for review':'Review found no flag','flag-review-error':'Flag review unavailable',proposal:'Command proposed',approval:'Command approved','auto-approval':'Catalog check validated','duplicate-skipped':'Repeated check skipped','survey-batch':'Survey batch',survey:'Baseline survey','deep-dive-selection':'Deep-dive host selected',context:'Context prepared','context-read':'Context read','context-request-repair':'Context request corrected','context-repair':'Citation correction requested','model-retry':'Model retried',comparison:'Host comparison',discovery:'Discovery segment','dns-review':'DNS reviewed',selection:'Hosts selected',pause:'Waiting for review'})[e.type]||`Run ${run?.status==='completed'?'completed':'stopped'}`;
  const eventMeta=e=>{const host=e.hostId?recordLabel(findings.find(f=>f.id===e.hostId)||{title:e.hostId}):'';if(e.type==='check')return [host,e.outcome,e.imported?'Findings saved':''].filter(Boolean).join(' · ');if(e.type==='decision')return e.choice?e.title||'Next check':e.reason||'';if(e.type==='flag-review')return [host,e.flag?.reason||'No flag'].filter(Boolean).join(' · ');if(e.type==='deep-dive-selection')return host;
    if(e.type==='survey-batch')return `${e.completed}/${e.total} hosts`;if(e.type==='survey')return host;if(e.type==='comparison')return `${e.flags?.length||0} flagged`;if(e.type==='discovery')return `${e.cidr||''} · ${e.count||0} hosts`;if(e.type==='selection')return `${e.hostIds?.length||0} hosts`;return e.reason||e.hostIp||'';};
  const allEvents=run?.events||[],shown=autonomyEventFilter==='all'?allEvents:allEvents.filter(isKeyEvent);
  document.querySelectorAll('[data-timeline-filter]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.timelineFilter===autonomyEventFilter)));
  $('#autonomyEventCount').textContent=run?`${shown.length} of ${allEvents.length} events shown`:'No events';
  const runMeta=run?`<details class="timeline-run-meta"><summary>Run details</summary><div class="cmd"><p>ID: ${esc(run.id)} · ${['group','discover-group'].includes(run.mode)?'Group':'Host'}: ${esc(run.hostName||run.hostIp)}${run.hostIp?' ('+esc(run.hostIp)+')':''}</p><p>Model: ${esc(run.model||'server default')} · Started: ${esc(date(run.startedAt))}</p><p>Scope: ${esc((run.scope?.cidrs||[]).join(', '))} · ${esc((run.scope?.domains||[]).join(', '))} · ${esc(run.scope?.matchMode||'and').toUpperCase()}</p></div></details>`:'';
  box.innerHTML=run?runMeta+shown.map(e=>`<details class="timeline-event ${e.type==='flag-review'&&e.flag?'flagged':e.type==='approval'?'approved':''}"><summary><strong>${e.step!=null?`Step ${esc(e.step)} · `:''}${esc(eventTitle(e))}</strong><small>${esc(eventMeta(e).slice(0,150))}</small></summary><div class="event-body">${eventHtml(e)}</div></details>`).join(''):'<div class="empty">No autonomous decisions recorded yet.</div>';
  const pendingPanel=$('#autonomyPendingReview');pendingPanel.hidden=run?.id!==active?.id||active?.status!=='awaiting-approval'||!active.pendingProposal;
  if(!pendingPanel.hidden){
    const p=active.pendingProposal;
    pendingPanel.innerHTML=`<div class="cmd"><strong>Human review required before execution</strong>${p.tool?`<p>Tool: ${esc(p.tool)} · ${p.catalogued===false?'Not in catalog · review required':'Catalogued'} · Local help: ${esc(p.helpInvocation||'not read')}</p>`:''}<p>Run: ${esc(active.id)} · Selected host: ${esc(p.hostName||p.hostIp)} (${esc(p.hostIp)})</p><p>Review the exact command, every destination, required privilege, possible side effect, and credential exposure. Approved commands run as the Yagura server user without an implicit shell.</p><pre>${esc(p.command)}</pre><p>Why: ${esc(p.reason)}</p><p>Expected evidence: ${esc(p.expectedEvidence)}</p><p>Review notes: ${esc(p.reviewNotes||'Not supplied by the model.')}</p><div class="field"><label for="autonomyRevisionInstruction">Correction instruction</label><textarea id="autonomyRevisionInstruction" rows="3" maxlength="500" placeholder="For example: use smbclient without credentials to list shares"></textarea></div><div class="toolbar"><button class="btn" id="autonomyRevise">Ask AI to revise</button></div><div class="toolbar"><button class="btn primary" id="autonomyApprove">Approve and run this revision</button></div><p class="status" id="autonomyReviewState"></p></div>`;
    $('#autonomyRevise').onclick=async()=>{const instruction=$('#autonomyRevisionInstruction').value.trim();if(instruction.length<5){$('#autonomyReviewState').textContent='Describe the correction in at least five characters.';return;}$('#autonomyRevise').disabled=true;$('#autonomyApprove').disabled=true;$('#autonomyReviewState').textContent='AI is revising the command…';try{await post('/api/autonomy/revise',{runId:active.id,proposalId:p.id,revision:p.revision,instruction,authorizedScope:checkScope()});await loadAutonomyHistory();}catch(e){$('#autonomyReviewState').textContent=e.message;$('#autonomyRevise').disabled=false;$('#autonomyApprove').disabled=false;}};
    $('#autonomyApprove').onclick=async()=>{if(!await confirmScopedAction('Approve AI-written command?',`Run: ${esc(active.id)} · Target: ${esc(p.hostName||p.hostIp)} (${esc(p.hostIp)}). Review destinations, privileges, side effects and credentials. The command runs as the Yagura server user.<pre>${esc(p.command)}</pre>`,'Approve and run'))return;$('#autonomyRevise').disabled=true;$('#autonomyApprove').disabled=true;$('#autonomyReviewState').textContent='Starting the approved check…';try{await post('/api/autonomy/approve',{runId:active.id,proposalId:p.id,revision:p.revision,expectedCommand:p.command,authorizedScope:checkScope(),authorized:true});await loadAutonomyHistory();}catch(e){$('#autonomyReviewState').textContent=e.message;$('#autonomyRevise').disabled=false;$('#autonomyApprove').disabled=false;}};
  }
  wireRefs(box);
}
async function loadAutonomyHistory(){try{const data=await api('/api/autonomy');const limits=data.limits||{maxChecks:null,maxSeconds:600,groupMaxChecks:null,groupMaxSeconds:900};autonomyLimits=limits;$('#autonomyLimitBadge').textContent=`ONE HOST ${limits.maxChecks==null?'NO COUNT LIMIT':limits.maxChecks+' CHECKS'} / ${limits.maxSeconds}s · GROUP ${limits.groupMaxChecks==null?'NO COUNT LIMIT':limits.groupMaxChecks+' CHECKS'} / ${limits.groupMaxSeconds}s`;const nextRuns=data.runs||[],unchanged=autonomyLoaded&&JSON.stringify(autonomyRuns)===JSON.stringify(nextRuns);if(unchanged){inboxError='';renderActivity();return;}const before=autonomyRuns.flatMap(r=>r.events.filter(e=>e.type==='check').flatMap(e=>e.evidenceIds||[])).join(','),wasRunning=autonomyRuns.some(r=>r.status==='running');autonomyRuns=nextRuns;autonomyLoaded=true;inboxError='';const after=autonomyRuns.flatMap(r=>r.events.filter(e=>e.type==='check').flatMap(e=>e.evidenceIds||[])).join(',');if(scopeLoaded&&checkScope()&&(before!==after||wasRunning&&!autonomyRuns.some(r=>r.status==='running')))await refreshFindings();if(wasRunning&&!autonomyRuns.some(r=>r.status==='running')&&checkScope())await loadPendingDiscovery();if(workspaceReady)InventoryStats.update(findings,evidence,map,attentionFlags,savedScope,autonomyRuns,showRecord);renderAutonomy();renderTriage();renderBriefing();renderActivity();}catch(e){inboxError=e.message;renderActivity();$('#autonomyNow').querySelector('p').textContent='Run status unavailable: '+e.message;$('#autonomyState').textContent=e.message;}}
function metricNumber(value){return Number.isInteger(value)?value.toLocaleString():'—';}
async function loadLlmMetrics(){
  const box=$('#llmMetricsList');
  try{
    const data=await api('/api/llm/metrics');
    box.innerHTML=(data.calls||[]).length?data.calls.map(row=>`<div class="cmd"><strong>${esc(row.model||'Unknown model')}</strong><p>${esc(date(row.at))} · ${esc(row.status)} · finish: ${esc(row.finishReason||'unavailable')} · ${metricNumber(row.durationMs)} ms</p><p>Input: ${metricNumber(row.promptTokens)} tokens / ${metricNumber(row.inputChars)} characters · Output: ${metricNumber(row.completionTokens)} tokens / ${metricNumber(row.outputChars)} characters · requested output cap: ${metricNumber(row.maxOutputTokens)} tokens</p></div>`).join(''):'<div class="empty">No model calls recorded yet.</div>';
  }catch(e){box.textContent='Measurements unavailable: '+e.message;}
}
$('#llmMetricsDetails').ontoggle=()=>{if($('#llmMetricsDetails').open)loadLlmMetrics();};
$('#llmMetricsRefresh').onclick=loadLlmMetrics;
$('#autonomyHistory').onchange=()=>{autonomyCurrent=$('#autonomyHistory').value;renderAutonomy();autonomySummaries();};
$('#autonomyReviewAction').onclick=()=>{const active=autonomyRuns.find(r=>['awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(r.status));if(!active)return;autonomyCurrent=active.id;renderAutonomy();if(active.status==='awaiting-approval'){$('#autonomyPendingReview').scrollIntoView({block:'start'});$('#autonomyPendingReview').focus();}else if(active.status==='awaiting-host-review')location.hash='#scope';else{openAutonomyNewRun(active.mode==='group'?'group':'discover');$('#autonomyDiscoverResume').focus();}};
function autonomyHostLabel(id){const host=map.targets.find(t=>t.host.id===id)?.host;return host?recordLabel(host):id;}
$('#autonomyGroupStart').onclick=async()=>{
  const hostIds=[...autonomySelectedHosts],scope=checkScope(),model=$('#autonomyModel').value;
  if(!hostIds.length||!scope){$('#autonomyState').textContent='Choose at least one approved host under the saved scope.';return;}
  if(!requireAutonomyModel())return;
  const single=hostIds.length===1;
  const description=single
    ?`Target: ${esc(autonomyHostLabel(hostIds[0]))} · Model: ${esc(model||'Server default')}. AI deep dive runs for up to ${autonomyLimits.maxSeconds}s. Validated catalog commands run automatically; unlisted tools need review.`
    :`Targets (${hostIds.length}):<details><summary>Review selected hosts</summary><pre>${esc(hostIds.map(autonomyHostLabel).join('\n'))}</pre></details>Model: ${esc(model||'Server default')}. The survey runs for up to ${autonomyLimits.groupMaxSeconds}s per segment and can be continued if unfinished. Yagura then selects one host for a deep dive of up to ${autonomyLimits.maxSeconds}s. Validated catalog commands run automatically; unlisted tools need review.`;
  if(!await confirmScopedAction(single?'Start deep dive?':'Survey selected hosts?',description,single?'Start deep dive':'Start survey'))return;
  const button=$('#autonomyGroupStart');button.disabled=true;
  $('#autonomyState').textContent=single?'Starting AI deep dive…':'Starting host survey…';
  try{
    const run=single
      ?await post('/api/autonomy/start',{hostId:hostIds[0],model,authorizedScope:scope,authorized:true})
      :await post('/api/autonomy/start-group',{hostIds,model,authorizedScope:scope,authorized:true});
    autonomyCurrent=run.id;$('#autonomyNewRun').close();await loadAutonomyHistory();
  }catch(e){$('#autonomyState').textContent=e.message;button.disabled=false;}
};
$('#autonomyInventoryStart').onclick=async()=>{const scope=checkScope(),model=$('#autonomyModel').value;if(!scope){$('#autonomyState').textContent='Save the target scope first.';return;}if(!requireAutonomyModel())return;if(!await confirmScopedAction('Survey approved inventory?',`Yagura will survey every approved, DNS-verified inventory host in batches of four, then select a deep-dive host. The time limit can pause the survey for continuation. Validated catalog commands run automatically; unlisted tools need review. Model: ${esc(model||'Server default')}.`,'Start survey'))return;const button=$('#autonomyInventoryStart');button.disabled=true;$('#autonomyState').textContent='Starting inventory survey…';try{const run=await post('/api/autonomy/survey-inventory',{model,authorizedScope:scope,authorized:true});autonomyCurrent=run.id;$('#autonomyNewRun').close();await loadAutonomyHistory();}catch(e){$('#autonomyState').textContent=e.message;button.disabled=false;}};
$('#autonomyDiscoverStart').onclick=async()=>{const scope=checkScope(),model=$('#autonomyModel').value;if(!scope){$('#autonomyState').textContent='Save an authorized target scope first.';return;}if(!requireAutonomyModel())return;const resolvers=$('#autonomyResolvers').value.split(/[\s,]+/).filter(Boolean);if(!await confirmScopedAction('Discover scope?',`CIDRs: ${esc(scope.cidrs.join(', '))} · Resolvers: ${esc(resolvers.join(', ')||'None')} · Model: ${esc(model||'Server default')}. New names require approval before checks.`,'Start discovery',false))return;const button=$('#autonomyDiscoverStart');button.disabled=true;$('#autonomyState').textContent='Starting scoped discovery…';try{const run=await post('/api/autonomy/discover-group',{resolvers,model,authorizedScope:scope,authorized:true});autonomyCurrent=run.id;$('#autonomyNewRun').close();await loadAutonomyHistory();}catch(e){$('#autonomyState').textContent=e.message;button.disabled=false;}};
$('#autonomyDiscoverResume').onclick=async()=>{const run=autonomyRuns.find(r=>['awaiting-host-review','awaiting-discovery'].includes(r.status)),scope=checkScope();if(!run||!scope){$('#autonomyState').textContent='A saved run and target scope are required.';return;}const survey=run.mode==='group',label=survey?'Continue survey':'Continue discovery';if(!await confirmScopedAction(label+'?',`Run: ${esc(run.id)} · Status: ${esc(run.status)}. ${survey?'Continue the remaining approved hosts. Completed hosts stay saved.':'Continue discovery or select approved hosts within the saved scope.'}`,label))return;const button=$('#autonomyDiscoverResume');button.disabled=true;try{await post('/api/autonomy/resume-discovery',{runId:run.id,authorizedScope:scope,authorized:true});autonomyCurrent=run.id;$('#autonomyNewRun').close();await loadAutonomyHistory();}catch(e){$('#autonomyState').textContent=e.message;button.disabled=false;}};
$('#autonomyStop').onclick=async()=>{const active=autonomyRuns.find(r=>['running','awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(r.status));if(!active)return;$('#autonomyStop').disabled=true;try{await post('/api/autonomy/stop',{runId:active.id});$('#autonomyState').textContent=active.status==='running'?'Stop requested; waiting for the current check.':'Pending review declined.';await loadAutonomyHistory();}catch(e){$('#autonomyState').textContent=e.message;}};
let activityData={active:[],recent:[]},activityError='',activityLoading=false,activityFocus=null,inboxError='';
let inboxRead=new Set(),inboxReady=false,inboxShowChecks=false;
const inboxReadKey='yagura-inbox-read-v1',inboxChecksKey='yagura-inbox-show-checks-v1';
try{const stored=localStorage.getItem(inboxReadKey);if(stored!==null){const ids=JSON.parse(stored);if(Array.isArray(ids))inboxRead=new Set(ids.filter(id=>typeof id==='string'));inboxReady=true;}inboxShowChecks=localStorage.getItem(inboxChecksKey)==='true';}catch{inboxReady=true;}
$('#inboxShowChecks').checked=inboxShowChecks;
function inboxKey(run){return 'run:'+run.id+':'+run.status;}
function saveInboxRead(){try{localStorage.setItem(inboxReadKey,JSON.stringify([...inboxRead].slice(-100)));}catch{}}
function initializeInbox(){if(inboxReady||!autonomyLoaded)return;for(const run of autonomyRuns)if(['completed','stopped','interrupted'].includes(run.status))inboxRead.add(inboxKey(run));inboxReady=true;saveInboxRead();}
function activityElapsed(started){if(!started)return '';const seconds=Math.max(0,Math.floor((Date.now()-Date.parse(started))/1000));return Number.isFinite(seconds)?seconds<60?seconds+'s':Math.floor(seconds/60)+'m '+String(seconds%60).padStart(2,'0')+'s':'';}
function inboxEmpty(message){return '<div class="inbox-empty">'+esc(message)+'</div>';}
function inboxUpdate(selector,html){const box=$(selector);if(box.innerHTML===html)return;const focused=document.activeElement,action=focused?.dataset.inboxAction,id=focused?.dataset.inboxId;box.innerHTML=html;if(action&&id){const target=[...box.querySelectorAll('[data-inbox-action]')].find(node=>node.dataset.inboxAction===action&&node.dataset.inboxId===id);target?.focus();}}
function inboxActionCard(run){
  const p=run.pendingProposal,command=run.status==='awaiting-approval'&&p;
  const title=command?'Command approval required':run.status==='awaiting-host-review'?'Host approval required':'Discovery needs review';
  const target=command?p.hostName||p.hostIp:run.hostName||run.hostIp;
  const reason=command?p.reason:run.stopReason;
  return '<article class="inbox-card action"><strong>'+esc(title)+'</strong><p class="inbox-meta">'+esc(target)+' · '+esc(date(p?.createdAt||run.startedAt))+'</p>'+
    (reason?'<p>'+esc(reason)+'</p>':'')+(command?'<p>Expected: '+esc(p.expectedEvidence||'Not specified')+'</p><p>Review: '+esc(p.reviewNotes||'Check destinations, privileges, side effects, and credentials.')+'</p>':'')+
    '<div class="toolbar"><button class="btn primary" type="button" data-inbox-action="review" data-inbox-id="'+esc(run.id)+'">Review</button></div></article>';
}
function inboxRunCard(run){
  const checks=run.events.filter(e=>e.type==='check').length,flags=(run.flags||[]).length,selected=run.deepDiveHostId?autonomyHostLabel(run.deepDiveHostId):'';
  const key=inboxKey(run),unread=!inboxRead.has(key),state=run.status==='completed'?'Completed':run.status==='interrupted'?'Interrupted':'Stopped';
  return '<article class="inbox-card'+(unread?' unread':'')+'"><strong>'+esc(state+' · '+(run.hostName||run.hostIp||'Investigation'))+'</strong><p class="inbox-meta">'+esc(date(run.endedAt||run.startedAt))+' · '+checks+' '+(checks===1?'check':'checks')+(flags?' · '+flags+' review flags':'')+'</p>'+
    (selected?'<p>Deep dive: '+esc(selected)+'</p>':'')+(run.stopReason?'<p>'+esc(run.stopReason)+'</p>':'')+
    '<div class="toolbar"><button class="btn" type="button" data-inbox-action="open" data-inbox-id="'+esc(run.id)+'">View run</button>'+(unread?'<button class="btn" type="button" data-inbox-action="read" data-inbox-id="'+esc(run.id)+'">Mark read</button>':'')+'</div></article>';
}
function inboxRunningCard(row){
  const progress=row.progress,hasProgress=progress&&Number.isFinite(progress.completed)&&Number.isFinite(progress.total)&&progress.total>0;
  const pct=hasProgress?Math.min(100,Math.max(0,Math.round(100*progress.completed/progress.total))):0;
  return '<article class="inbox-card inbox-running"><strong>'+esc(row.title||row.kind)+'</strong><p class="inbox-meta">'+esc(row.target||'')+' · '+esc(activityElapsed(row.startedAt))+'</p>'+(row.detail?'<p>'+esc(row.detail)+'</p>':'')+
    (hasProgress?'<p class="inbox-meta">'+esc(progress.completed)+' / '+esc(progress.total)+' '+esc(progress.unit||'steps')+'</p><div class="activity-progress" aria-label="'+esc(progress.completed)+' of '+esc(progress.total)+' '+esc(progress.unit||'steps')+'"><span style="width:'+pct+'%"></span></div>':'')+'</article>';
}
function renderActivity(){
  initializeInbox();
  const pending=autonomyRuns.filter(r=>['awaiting-approval','awaiting-host-review','awaiting-discovery'].includes(r.status));
  const finished=autonomyRuns.filter(r=>['completed','stopped','interrupted'].includes(r.status));
  const local=[];
  if(autoRunning&&autoPlan)local.push({kind:'browser run',title:'Short automatic check run',target:autonomyHostLabel(autoPlan.hostId),detail:$('#autoState').textContent,progress:{completed:$('#autoResults').children.length,total:autoPlan.checks.length,unit:'checks'},startedAt:autoStartedAt});
  if(!$('#stopScanBtn').disabled)local.push({kind:'browser run',title:'Scoped discovery sequence',target:$('#scanTarget').value,detail:$('#scanState').textContent});
  const active=[...local,...activityData.active],unread=finished.filter(r=>!inboxRead.has(inboxKey(r))).length;
  const idle=autonomyLoaded&&scopeLoaded&&!!checkScope()&&!pending.length&&!active.length&&!autonomyRuns.some(r=>r.status==='running')&&!activityError&&!inboxError;
  $('#inboxIdle').hidden=!idle;
  $('#inboxActionsSection').hidden=idle;
  $('#inboxRunningSection').hidden=idle;
  $('#activityToggleText').textContent=pending.length?pending.length+' review'+(unread?' · '+unread+' new':''):inboxError?'Inbox ?':unread?unread+' new':'Inbox';
  $('#activityPulse').classList.toggle('running',!!active.length&&!pending.length&&!activityError);
  $('#activityPulse').classList.toggle('error',!!pending.length||!!activityError||!!inboxError);
  $('#activitySummary').textContent=inboxError?'Investigation status unavailable; retrying.':activityError?'Live progress unavailable. Saved investigations remain available.':!autonomyLoaded?'Loading saved investigations…':pending.length?pending.length+' decision'+(pending.length===1?'':'s')+' awaiting review'+(unread?', '+unread+' new result'+(unread===1?'':'s'):'')+'.':active.length?active.length+' operation'+(active.length===1?'':'s')+' running'+(unread?', '+unread+' new result'+(unread===1?'':'s'):'')+'.':unread?unread+' new result'+(unread===1?'':'s')+'.':'No action required.';
  $('#inboxActionCount').textContent=pending.length?pending.length+' pending':'';
  inboxUpdate('#inboxActions',pending.length?pending.map(inboxActionCard).join(''):inboxEmpty(inboxError?'Saved investigation status unavailable.':!autonomyLoaded?'Loading…':'No decisions waiting for you.'));
  inboxUpdate('#activityActive',active.length?active.map(inboxRunningCard).join(''):inboxEmpty(activityError?'Live progress unavailable; retrying.':'Nothing running.'));
  const routine=inboxShowChecks?activityData.recent.filter(row=>row.kind==='check').map(row=>'<article class="inbox-card"><strong>'+esc(row.title||'Check')+'</strong><p class="inbox-meta">'+esc(row.target||'')+' · '+esc(date(row.endedAt))+'</p><p>'+esc(row.detail||row.outcome||'')+'</p></article>').join(''):'';
  inboxUpdate('#activityRecent',finished.length?finished.map(inboxRunCard).join('')+routine:routine||inboxEmpty('No saved investigation results.'));
  $('#inboxMarkRead').disabled=!unread;
  $('#inboxShowChecks').checked=inboxShowChecks;
}
function openInboxRun(runId,review=false){
  const run=autonomyRuns.find(r=>r.id===runId);if(!run)return;
  if(!review)inboxRead.add(inboxKey(run));saveInboxRead();closeActivity();
  autonomyCurrent=runId;location.hash=review&&run.status==='awaiting-host-review'?'#scope':'#autonomy';showView();renderAutonomy();renderActivity();
  if(review&&run.status==='awaiting-discovery'){openAutonomyNewRun(run.mode==='group'?'group':'discover');$('#autonomyDiscoverResume').focus();}
  else if(review&&run.status==='awaiting-approval')requestAnimationFrame(()=>{$('#autonomyPendingReview').scrollIntoView({block:'start'});$('#autonomyPendingReview').focus();});
  else if(!review){$('#autonomyOutcome').focus();}
}
$('#activityDrawer').addEventListener('click',event=>{const button=event.target.closest('[data-inbox-action]');if(!button)return;const run=autonomyRuns.find(r=>r.id===button.dataset.inboxId);if(!run)return;if(button.dataset.inboxAction==='read'){inboxRead.add(inboxKey(run));saveInboxRead();renderActivity();[...$('#activityRecent').querySelectorAll('[data-inbox-action="open"]')].find(node=>node.dataset.inboxId===run.id)?.focus();}else openInboxRun(run.id,button.dataset.inboxAction==='review');});
$('#inboxMarkRead').onclick=()=>{for(const run of autonomyRuns)if(['completed','stopped','interrupted'].includes(run.status))inboxRead.add(inboxKey(run));saveInboxRead();renderActivity();$('#activityClose').focus();};
$('#inboxShowChecks').onchange=event=>{inboxShowChecks=event.target.checked;try{localStorage.setItem(inboxChecksKey,String(inboxShowChecks));}catch{}renderActivity();};
async function refreshActivity(){if(activityLoading)return;activityLoading=true;try{activityData=await api('/api/activity');activityError='';}catch(e){activityError=e.message;}finally{activityLoading=false;renderActivity();}}
function openActivity(){activityFocus=document.activeElement;$('#activityBackdrop').hidden=false;$('#activityDrawer').hidden=false;document.body.classList.add('activity-open');$('#activityToggle').setAttribute('aria-expanded','true');renderActivity();$('#activityClose').focus();}
function closeActivity(){$('#activityBackdrop').hidden=true;$('#activityDrawer').hidden=true;document.body.classList.remove('activity-open');$('#activityToggle').setAttribute('aria-expanded','false');(activityFocus||$('#activityToggle')).focus();}
$('#activityToggle').onclick=()=>$('#activityDrawer').hidden?openActivity():closeActivity();
$('#inboxNewInvestigation').onclick=()=>{closeActivity();location.hash='#autonomy';showView();openAutonomyNewRun();};
$('#activityClose').onclick=closeActivity;
$('#activityBackdrop').onclick=closeActivity;
document.addEventListener('keydown',event=>{if($('#activityDrawer').hidden||$('#reviewDialog').open)return;if(event.key==='Escape'){event.preventDefault();closeActivity();return;}if(event.key!=='Tab')return;const controls=[...$('#activityDrawer').querySelectorAll('button:not([disabled]),input:not([disabled]),summary')].filter(node=>node.getClientRects().length);if(!controls.length)return;const first=controls[0],last=controls.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}});
let inboxPollTick=0;load();loadAutonomyHistory();loadCheckProposals();refreshActivity();setInterval(()=>{refreshActivity();inboxPollTick++;if(autonomyRuns.some(r=>r.status==='running')||inboxPollTick%2===0)loadAutonomyHistory();if($('#llmMetricsDetails').open)loadLlmMetrics();},2500);
