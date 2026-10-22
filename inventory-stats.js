'use strict';
/* Derived, read-only views of saved findings. No network checks are initiated here. */
const InventoryStats=(()=>{
  const escape=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  let source=null,selected=null,selectionLabel='',portProtocol='tcp',showAllPorts=false;
  const setFor=(rows)=>new Set(rows.map(row=>row.hostId||row.id).filter(Boolean));
  const intersection=(a,b)=>new Set([...a].filter(id=>b.has(id)));
  const family=name=>{const value=String(name||'').toLowerCase();return /windows/.test(value)?'Windows':/linux/.test(value)?'Linux':/freebsd|openbsd|netbsd|bsd/.test(value)?'BSD':/mac os|darwin|apple/.test(value)?'macOS':'Other estimate';};
  function build(findings,evidence,map,flags,scope,runs=[]){
    const hosts=(map.targets||[]).filter(target=>target.eligible).map(target=>target.host),ids=new Set(hosts.map(host=>host.id)),hostById=new Map(hosts.map(host=>[host.id,host]));
    const records=findings.filter(row=>ids.has(row.hostId)),services=records.filter(row=>row.kind==='service'&&row.state==='open');
    const observations=records.filter(row=>row.kind==='observation');
    const evidenceById=new Map(evidence.map(row=>[row.id,row]));
    const osByHost=new Map();
    const osAccuracy=row=>Number(String(row.detail||'').match(/\((\d+)% accuracy\)/)?.[1]||0);
    for(const row of observations.filter(row=>row.title==='Nmap OS guess'&&!String(row.detail||'').includes('No exact OS matches')).sort((a,b)=>String(b.lastSeen||'').localeCompare(String(a.lastSeen||''))||osAccuracy(b)-osAccuracy(a)))if(!osByHost.has(row.hostId))osByHost.set(row.hostId,family(row.detail));
    const hostEvidence=new Map(hosts.map(host=>[host.id,new Set(host.evidenceIds||[])]));
    for(const row of records)for(const id of row.evidenceIds||[])hostEvidence.get(row.hostId)?.add(id);
    const portsScanned=new Set();
    for(const host of hosts)if([...hostEvidence.get(host.id)].some(id=>{const ev=evidenceById.get(id);return ev?.tool==='nmap'&&(/(?:\s-p\s*|--top-ports|--ports|\s-sV\b|\s-sT\b|\s-sU\b)/.test(ev.command||'')||/<port\b|\d+\/(tcp|udp)\s+/.test(ev.output||''));}))portsScanned.add(host.id);
    const osRows=hosts.map(host=>({hostId:host.id,label:osByHost.get(host.id)||'Unknown'}));
    const progress=progressRows(map,services,portsScanned,flags,runs,scope);
    const categories=['Ports','OS','Web','TLS','Version'];
    const coverage=hosts.map(host=>{const rows=records.filter(row=>row.hostId===host.id),obs=rows.filter(row=>row.kind==='observation'),sv=rows.filter(row=>row.kind==='service');return {host,states:[portsScanned.has(host.id)||sv.length>0,obs.some(row=>row.title==='Nmap OS guess'),obs.some(row=>/web|http/i.test(row.title))||sv.some(row=>/http/i.test(row.name||'')),obs.some(row=>/ssl-cert|tls|certificate/i.test(row.title)),sv.some(row=>row.product||row.version)].map(value=>value?'recorded':'unknown')};});
    const latest=new Map();for(const host of hosts){const dates=[host.lastSeen,...[...hostEvidence.get(host.id)].map(id=>evidenceById.get(id)?.observedAt)].filter(Boolean).map(value=>Date.parse(value)).filter(Number.isFinite);latest.set(host.id,dates.length?Math.max(...dates):NaN);}
    const productRows=services.filter(row=>row.product).map(row=>({hostId:row.hostId,label:`${row.product}${row.version?' '+row.version:''}`}));
    const leadRows=flags.filter(flag=>ids.has(flag.hostId)).map(flag=>({hostId:flag.hostId,label:String(flag.kind||'Other').replace(/-/g,' ')}));
    const now=Date.now(),freshness=hosts.map(host=>{const age=(now-latest.get(host.id))/86400000;return {hostId:host.id,label:!Number.isFinite(age)?'Unknown':age<1?'Past 24 hours':age<7?'1–7 days':age<30?'8–30 days':'Over 30 days'};});
    const recent=[...hosts,...records].filter(row=>{const seen=Date.parse(row.firstSeen||'');return Number.isFinite(seen)&&now-seen>=0&&now-seen<7*86400000;});
    return {hosts,hostById,services,osRows,progress,coverage,categories,portsScanned,productRows,leadRows,freshness,recent};
  }
  function groups(rows,key){const out=new Map();for(const row of rows){const label=key(row);if(!out.has(label))out.set(label,new Set());out.get(label).add(row.hostId);}return [...out].map(([label,ids])=>({label,ids,count:ids.size})).sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label));}
  function renderBars(element,rows,maxRows=10){const all=rows.filter(row=>row.count>0),max=Math.max(1,...all.map(row=>row.count));element.innerHTML=all.slice(0,maxRows).map((row,index)=>`<button class="inventory-bar" type="button" data-chart-row="${index}" aria-label="${escape(row.label)}: ${row.count} ${row.count===1?'host':'hosts'}"><span title="${escape(row.label)}">${escape(row.label)}</span><i style="width:${Math.max(2,100*row.count/max)}%"></i><b>${row.count}</b></button>`).join('')||'<div class="empty">No saved matches.</div>';element.querySelectorAll('[data-chart-row]').forEach(button=>button.onclick=()=>choose(all[Number(button.dataset.chartRow)].ids,all[Number(button.dataset.chartRow)].label));}
  function choose(ids,label){selected=selected&&selectionLabel===label?null:new Set(ids);selectionLabel=selected?label:'';render();}
  const sameScope=(a,b)=>a&&b&&['cidrs','domains'].every(key=>JSON.stringify([...(a[key]||[])].sort())===JSON.stringify([...(b[key]||[])].sort()))&&(a.matchMode||'and')===(b.matchMode||'and');
  function progressRows(map,services,portsScanned,flags,runs,scope){
    const targets=(map.targets||[]).filter(target=>target.eligible||['Host identity needs DNS review and approval','Last recorded host state is down'].includes(target.scopeReason));
    const currentRuns=(runs||[]).filter(run=>sameScope(run.scope,scope));
    const checked=new Set(currentRuns.flatMap(run=>(run.events||[]).filter(event=>event.type==='check'&&event.outcome==='completed'&&event.imported).map(event=>event.hostId)));
    const flagged=new Set([...flags,...currentRuns.flatMap(run=>run.flags||[])].map(flag=>flag.hostId));
    const dived=new Set();
    for(const run of currentRuns){const events=run.events||[],selected=events.findIndex(event=>event.type==='deep-dive-selection');if(selected>=0){const hostId=events[selected].hostId;if(events.slice(selected+1).some(event=>event.type==='check'&&event.hostId===hostId&&event.outcome==='completed'&&event.imported))dived.add(hostId);}else if(run.mode!=='group'&&run.mode!=='discover-group')for(const event of events)if(event.type==='check'&&event.outcome==='completed'&&event.imported&&event.hostId)dived.add(event.hostId);}
    const serviceHosts=setFor(services);
    return targets.map(target=>{const host=target.host,approved=target.eligible||target.scopeReason==='Last recorded host state is down';
      const investigated=approved&&(portsScanned.has(host.id)||serviceHosts.has(host.id)||checked.has(host.id));
      const stages=['Recorded in scope',approved?'Approved':'Awaiting approval',!approved?'Awaiting approval':investigated?'Investigated':'Not investigated',!approved?'Awaiting approval':!investigated?'Not investigated':flagged.has(host.id)?'Review lead':'No current lead',!approved?'Awaiting approval':!investigated?'Not investigated':dived.has(host.id)?'Deep dive done':'Deep dive not done'];
      return {hostId:host.id,host,stages};
    });
  }
  const stageTitles=['Scope','Approval','Checks','Review','Deep dive'];
  const stageOrder=[['Recorded in scope'],['Approved','Awaiting approval'],['Investigated','Not investigated','Awaiting approval'],['Review lead','No current lead','Not investigated','Awaiting approval'],['Deep dive done','Deep dive not done','Not investigated','Awaiting approval']];
  function progressDiagram(rows){
    if(!rows.length)return '<div class="empty">No recorded hosts in the saved scope.</div>';
    const xs=[35,255,475,695,915],height=315,gap=17,scale=Math.min(...stageOrder.map((order,i)=>(height-gap*(order.filter(label=>rows.some(row=>row.stages[i]===label)).length-1))/rows.length));
    const nodes=stageOrder.map((order,i)=>{const present=order.map(label=>({label,rows:rows.filter(row=>row.stages[i]===label)})).filter(node=>node.rows.length);let y=52;return present.map(node=>{const item={...node,x:xs[i],y,height:node.rows.length*scale,in:0,out:0};y+=item.height+gap;return item;});});
    const lookups=nodes.map(column=>new Map(column.map(node=>[node.label,node]))),edges=[];
    for(let step=0;step<4;step++){const pairs=new Map();for(const row of rows){const from=row.stages[step],to=row.stages[step+1],key=JSON.stringify([from,to]);if(!pairs.has(key))pairs.set(key,{from,to,rows:[],step});pairs.get(key).rows.push(row);}edges.push(...pairs.values());}
    for(let step=0;step<4;step++){const links=edges.filter(edge=>edge.step===step),sourceOrder=new Map(nodes[step].map((node,i)=>[node.label,i])),targetOrder=new Map(nodes[step+1].map((node,i)=>[node.label,i]));
      for(const edge of [...links].sort((a,b)=>sourceOrder.get(a.from)-sourceOrder.get(b.from)||targetOrder.get(a.to)-targetOrder.get(b.to))){const node=lookups[step].get(edge.from);edge.y1=node.y+node.out+edge.rows.length*scale/2;node.out+=edge.rows.length*scale;}
      for(const edge of [...links].sort((a,b)=>targetOrder.get(a.to)-targetOrder.get(b.to)||sourceOrder.get(a.from)-sourceOrder.get(b.from))){const node=lookups[step+1].get(edge.to);edge.y2=node.y+node.in+edge.rows.length*scale/2;node.in+=edge.rows.length*scale;}
    }
    const links=edges.map((edge,index)=>{const from=lookups[edge.step].get(edge.from),to=lookups[edge.step+1].get(edge.to),width=edge.rows.length*scale;return `<path class="progress-link" d="M ${from.x+10} ${edge.y1} C ${from.x+108} ${edge.y1}, ${to.x-98} ${edge.y2}, ${to.x} ${edge.y2}" stroke-width="${width}" data-progress-edge="${index}" tabindex="0" role="button" aria-label="${escape(edge.from)} to ${escape(edge.to)}: ${edge.rows.length} hosts"><title>${escape(edge.from)} → ${escape(edge.to)} · ${edge.rows.length} hosts</title></path>`;}).join('');
    const nodeList=nodes.flatMap((column,step)=>column.map(node=>({node,step}))),boxes=nodeList.map(({node,step},index)=>{const label=`${node.label} · ${node.rows.length}`;return `<rect class="progress-node" x="${node.x}" y="${node.y}" width="10" height="${node.height}" data-progress-node="${index}" tabindex="0" role="button" aria-label="${escape(label)}"><title>${escape(label)}</title></rect><text x="${step===4?node.x-7:node.x+16}" y="${node.y+Math.min(15,node.height/2+4)}" text-anchor="${step===4?'end':'start'}">${escape(label)}</text>`;}).join('');
    const headings=stageTitles.map((title,i)=>`<text class="progress-heading" x="${xs[i]}" y="24">${escape(title)}</text>`).join('');
    return {markup:`<svg viewBox="0 0 1000 390" role="img" aria-label="Recorded host progress from scope through approval, checks, review, and deep dive">${headings}${links}${boxes}</svg>`,edges:edges.map(edge=>({ids:setFor(edge.rows),label:`${edge.from} → ${edge.to}`})),nodes:nodeList.map(({node})=>({ids:setFor(node.rows),label:node.label}))};
  }
  function render(){if(!source)return;const data=source.data,all=new Set(data.progress.map(row=>row.hostId)),active=selected?intersection(selected,all):all;const visible=rows=>rows.filter(row=>active.has(row.hostId));
    document.querySelector('#inventoryCount').textContent=`${data.hosts.length} approved / ${data.progress.length} in scope · ${data.services.length} open services`;
    document.querySelector('#inventorySelection').textContent=selected?`${selectionLabel} · ${active.size} matching hosts`:`All ${all.size} recorded in-scope hosts`;
    const clear=document.querySelector('#inventoryClear');clear.hidden=!selected;clear.onclick=()=>{selected=null;selectionLabel='';render();};
    const diagram=progressDiagram(data.progress.filter(row=>active.has(row.hostId))),flowBox=document.querySelector('#inventoryFlow');flowBox.innerHTML=typeof diagram==='string'?diagram:diagram.markup;
    if(typeof diagram!=='string')for(const [attribute,items] of [['data-progress-edge',diagram.edges],['data-progress-node',diagram.nodes]])flowBox.querySelectorAll(`[${attribute}]`).forEach(element=>{const activate=()=>{const item=items[Number(element.getAttribute(attribute))];choose(item.ids,item.label);};element.onclick=activate;element.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();activate();}};});
    renderBars(document.querySelector('#inventoryOs'),groups(visible(data.osRows),row=>row.label));
    const portRows=groups(visible(data.services).filter(row=>row.protocol===portProtocol),row=>`${row.port}/${row.protocol}`),portBox=document.querySelector('#inventoryPorts');
    document.querySelector('#inventoryPortCaption').innerHTML=`${data.portsScanned.size} / ${data.hosts.length} approved hosts have saved port-check evidence. Unknown is not closed. <button class="ref" id="inventoryProtocol" type="button">${portProtocol.toUpperCase()} ▾</button>`;
    document.querySelector('#inventoryProtocol').onclick=()=>{portProtocol=portProtocol==='tcp'?'udp':'tcp';render();};
    renderBars(portBox,portRows,showAllPorts?portRows.length:15);
    if(portRows.length>15){const button=document.createElement('button');button.className='btn';button.textContent=showAllPorts?'Show top 15':'Show all ports';button.onclick=()=>{showAllPorts=!showAllPorts;render();};portBox.append(button);}
    renderBars(document.querySelector('#inventoryLeads'),groups(visible(data.leadRows),row=>row.label));
    renderBars(document.querySelector('#inventoryProducts'),groups(visible(data.productRows),row=>row.label));
    renderBars(document.querySelector('#inventoryFreshness'),groups(visible(data.freshness),row=>row.label));
    const recent=data.recent.filter(row=>active.has(row.hostId||row.id));document.querySelector('#inventoryRecent').innerHTML=`<p class="status">${recent.filter(row=>row.kind==='host').length} hosts · ${recent.filter(row=>row.kind==='service').length} services · ${recent.filter(row=>row.kind==='observation').length} observations</p>`+(recent.length?recent.slice(0,8).map(row=>`<div class="item"><span>${escape(row.kind==='host'?row.ip:row.kind==='service'?`${row.port}/${row.protocol} ${row.product||row.name||''} ${row.version||''}`:row.title||'Observation')}</span><span class="hint">${escape(data.hostById.get(row.hostId||row.id)?.name||data.hostById.get(row.hostId||row.id)?.ip||'')}</span></div>`).join(''):'<div class="empty">No recent records.</div>');
    const matrix=data.coverage.filter(row=>active.has(row.host.id));document.querySelector('#inventoryCoverage').innerHTML=matrix.length?`<table><thead><tr><th>Host</th>${data.categories.map(name=>`<th>${escape(name)}</th>`).join('')}</tr></thead><tbody>${matrix.slice(0,30).map(row=>`<tr><th>${escape(row.host.name||row.host.ip)}</th>${row.states.map(state=>`<td data-state="${state}">${state==='recorded'?'●':'—'}</td>`).join('')}</tr>`).join('')}</tbody></table>${matrix.length>30?`<p class="status">Showing 30 of ${matrix.length} hosts. Filter above to narrow the view.</p>`:''}`:'<div class="empty">No matching approved hosts.</div>';
    const hostBox=document.querySelector('#inventoryHosts');hostBox.innerHTML=data.progress.map(row=>row.host).filter(host=>active.has(host.id)).slice(0,40).map(host=>`<button class="btn" type="button" data-inventory-host="${escape(host.id)}">${escape(host.name||host.ip)}</button>`).join('')+(active.size>40?`<span class="status">+${active.size-40} more hosts</span>`:'')||'<div class="empty">No matching hosts.</div>';hostBox.querySelectorAll('[data-inventory-host]').forEach(button=>button.onclick=()=>source.openHost(button.dataset.inventoryHost));
  }
  function update(findings,evidence,map,flags,scope,runs,openHost){source={data:build(findings,evidence,map,flags,scope,runs),openHost};render();}
  return {build,update,progressDiagram};
})();
if(typeof module!=='undefined')module.exports=InventoryStats;
