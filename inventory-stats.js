'use strict';
/* Derived, read-only views of saved findings. No network checks are initiated here. */
const InventoryStats=(()=>{
  const escape=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  let source=null,selected=null,selectionLabel='',portProtocol='tcp',showAllPorts=false;
  const setFor=(rows)=>new Set(rows.map(row=>row.hostId||row.id).filter(Boolean));
  const intersection=(a,b)=>new Set([...a].filter(id=>b.has(id)));
  const family=name=>{const value=String(name||'').toLowerCase();return /windows/.test(value)?'Windows':/linux/.test(value)?'Linux':/freebsd|openbsd|netbsd|bsd/.test(value)?'BSD':/mac os|darwin|apple/.test(value)?'macOS':'Other estimate';};
  const serviceType=service=>{const name=String(service.name||'').toLowerCase(),port=Number(service.port);if(/https?|www/.test(name)||[80,443,8000,8080,8443].includes(port))return 'Web';if(/ssh/.test(name)||port===22)return 'SSH';if(/smb|microsoft-ds|netbios/.test(name)||[139,445].includes(port))return 'SMB';if(/ldap|kerberos|domain/.test(name)||[53,88,389,636].includes(port))return 'Directory / DNS';if(/smtp|imap|pop3/.test(name)||[25,110,143,465,587,993,995].includes(port))return 'Mail';if(/mysql|postgres|mssql|redis|mongodb/.test(name)||[1433,3306,5432,6379,27017].includes(port))return 'Database';return 'Other';};
  const domainGroup=(host,scope)=>{const name=String(host.name||'').toLowerCase().replace(/\.$/,'');if(!name||name===host.ip)return 'IP only';const domain=(scope.domains||[]).filter(item=>name===item||name.endsWith('.'+item)).sort((a,b)=>b.length-a.length)[0];if(domain){const prefix=name.slice(0,-domain.length).replace(/\.$/,'');return prefix?prefix.split('.').slice(-1)[0]+'.'+domain:domain;}const parts=name.split('.');return parts.length>2?parts.slice(-2).join('.'):name;};
  function build(findings,evidence,map,flags,scope){
    const hosts=(map.targets||[]).filter(target=>target.eligible).map(target=>target.host),ids=new Set(hosts.map(host=>host.id)),hostById=new Map(hosts.map(host=>[host.id,host]));
    const records=findings.filter(row=>ids.has(row.hostId)),services=records.filter(row=>row.kind==='service'&&row.state==='open');
    const observations=records.filter(row=>row.kind==='observation');
    const evidenceById=new Map(evidence.map(row=>[row.id,row]));
    const osByHost=new Map();
    for(const row of observations.filter(row=>row.title==='Nmap OS guess').sort((a,b)=>String(b.lastSeen||'').localeCompare(String(a.lastSeen||''))))if(!osByHost.has(row.hostId))osByHost.set(row.hostId,family(row.detail));
    const hostEvidence=new Map(hosts.map(host=>[host.id,new Set(host.evidenceIds||[])]));
    for(const row of records)for(const id of row.evidenceIds||[])hostEvidence.get(row.hostId)?.add(id);
    const portsScanned=new Set();
    for(const host of hosts)if([...hostEvidence.get(host.id)].some(id=>{const ev=evidenceById.get(id);return ev?.tool==='nmap'&&(/(?:\s-p\s*|--top-ports|--ports|\s-sV\b|\s-sT\b|\s-sU\b)/.test(ev.command||'')||/<port\b|\d+\/(tcp|udp)\s+/.test(ev.output||''));}))portsScanned.add(host.id);
    const flow=services.map(service=>({hostId:service.hostId,domain:domainGroup(hostById.get(service.hostId),scope),os:osByHost.get(service.hostId)||'Unknown',type:serviceType(service)}));
    const categories=['Ports','OS','Web','TLS','Version'];
    const coverage=hosts.map(host=>{const rows=records.filter(row=>row.hostId===host.id),obs=rows.filter(row=>row.kind==='observation'),sv=rows.filter(row=>row.kind==='service');return {host,states:[portsScanned.has(host.id)||sv.length>0,obs.some(row=>row.title==='Nmap OS guess'),obs.some(row=>/web|http/i.test(row.title))||sv.some(row=>/http/i.test(row.name||'')),obs.some(row=>/ssl-cert|tls|certificate/i.test(row.title)),sv.some(row=>row.product||row.version)].map(value=>value?'recorded':'unknown')};});
    const latest=new Map();for(const host of hosts){const dates=[host.lastSeen,...[...hostEvidence.get(host.id)].map(id=>evidenceById.get(id)?.observedAt)].filter(Boolean).map(value=>Date.parse(value)).filter(Number.isFinite);latest.set(host.id,dates.length?Math.max(...dates):NaN);}
    const productRows=services.filter(row=>row.product).map(row=>({hostId:row.hostId,label:`${row.product}${row.version?' '+row.version:''}`}));
    const leadRows=flags.filter(flag=>ids.has(flag.hostId)).map(flag=>({hostId:flag.hostId,label:String(flag.kind||'Other').replace(/-/g,' ')}));
    const now=Date.now(),freshness=hosts.map(host=>{const age=(now-latest.get(host.id))/86400000;return {hostId:host.id,label:!Number.isFinite(age)?'Unknown':age<1?'Past 24 hours':age<7?'1–7 days':age<30?'8–30 days':'Over 30 days'};});
    const recent=[...hosts,...records].filter(row=>{const seen=Date.parse(row.firstSeen||'');return Number.isFinite(seen)&&now-seen>=0&&now-seen<7*86400000;});
    return {hosts,hostById,services,flow,coverage,categories,portsScanned,productRows,leadRows,freshness,recent};
  }
  function groups(rows,key){const out=new Map();for(const row of rows){const label=key(row);if(!out.has(label))out.set(label,new Set());out.get(label).add(row.hostId);}return [...out].map(([label,ids])=>({label,ids,count:ids.size})).sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label));}
  function renderBars(element,rows,maxRows=10){const all=rows.filter(row=>row.count>0),max=Math.max(1,...all.map(row=>row.count));element.innerHTML=all.slice(0,maxRows).map((row,index)=>`<button class="inventory-bar" type="button" data-chart-row="${index}" aria-label="${escape(row.label)}: ${row.count} ${row.count===1?'host':'hosts'}"><span title="${escape(row.label)}">${escape(row.label)}</span><i style="width:${Math.max(2,100*row.count/max)}%"></i><b>${row.count}</b></button>`).join('')||'<div class="empty">No saved matches.</div>';element.querySelectorAll('[data-chart-row]').forEach(button=>button.onclick=()=>choose(all[Number(button.dataset.chartRow)].ids,all[Number(button.dataset.chartRow)].label));}
  function choose(ids,label){selected=selected&&selectionLabel===label?null:new Set(ids);selectionLabel=selected?label:'';render();}
  function flowDiagram(rows){
    if(!rows.length)return '<div class="empty">No recorded open services on approved hosts.</div>';
    const topDomains=groups(rows,row=>row.domain).slice(0,8).map(row=>row.label);
    const flow=rows.map(row=>({...row,domain:topDomains.includes(row.domain)?row.domain:'Other domains'}));
    if(flow.every(row=>row.os==='Unknown')){
      const domains=[...new Set(flow.map(row=>row.domain))].sort((a,b)=>flow.filter(row=>row.domain===b).length-flow.filter(row=>row.domain===a).length||a.localeCompare(b));
      const types=['Web','SSH','SMB','Directory / DNS','Mail','Database','Other'];
      const edges=[];
      const markup=`<div class="flow-breakdown" role="list" aria-label="Open services by domain and service type">${domains.map(domain=>{
        const domainRows=flow.filter(row=>row.domain===domain);
        return `<div class="flow-breakdown-group" role="listitem"><div class="flow-breakdown-heading"><strong>${escape(domain)}</strong><span>${domainRows.length} open services</span></div><div class="flow-breakdown-types">${types.map(type=>{
          const matches=domainRows.filter(row=>row.type===type);
          if(!matches.length)return '';
          const key=edges.length;edges.push({ids:setFor(matches),label:`${domain} → ${type}`});
          return `<button class="flow-breakdown-type" type="button" data-flow-edge="${key}" aria-label="${escape(domain)}: ${escape(type)}, ${matches.length} open services"><span>${escape(type)}</span><i style="width:${100*matches.length/domainRows.length}%"></i><b>${matches.length}</b></button>`;
        }).join('')}</div></div>`;
      }).join('')}</div>`;
      return {markup,edges,hasOs:false};
    }
    const byColumn=[...Array(3)].map((_,i)=>[...new Set(flow.map(row=>[row.domain,row.os,row.type][i]))].map(label=>({label,count:flow.filter(row=>[row.domain,row.os,row.type][i]===label).length,ids:setFor(flow.filter(row=>[row.domain,row.os,row.type][i]===label))})).sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label)));
    const total=flow.length,gap=12,height=390,scale=Math.min(...byColumn.map(nodes=>(height-gap*(nodes.length-1))/total));
    const x=[170,465,760],nodes=byColumn.map((column,i)=>{let y=12;return column.map(node=>{const result={...node,x:x[i],y,height:Math.max(1,node.count*scale),out:0,in:0};y+=result.height+gap;return result;});});
    const lookup=nodes.map(column=>new Map(column.map(node=>[node.label,node]))),edges=[],links=[];
    for(let step=0;step<2;step++){const map=new Map();for(const row of flow){const from=[row.domain,row.os,row.type][step],to=[row.domain,row.os,row.type][step+1],key=JSON.stringify([from,to]);if(!map.has(key))map.set(key,{from,to,step,rows:[]});map.get(key).rows.push(row);}links.push(...[...map.values()].sort((a,b)=>a.from.localeCompare(b.from)||a.to.localeCompare(b.to)));}
    for(let step=0;step<2;step++){
      const current=links.filter(link=>link.step===step),sourceOrder=new Map(nodes[step].map((node,i)=>[node.label,i])),targetOrder=new Map(nodes[step+1].map((node,i)=>[node.label,i]));
      for(const link of [...current].sort((a,b)=>sourceOrder.get(a.from)-sourceOrder.get(b.from)||targetOrder.get(a.to)-targetOrder.get(b.to))) {const node=lookup[step].get(link.from);link.y1=node.y+node.out+link.rows.length*scale/2;node.out+=link.rows.length*scale;}
      for(const link of [...current].sort((a,b)=>targetOrder.get(a.to)-targetOrder.get(b.to)||sourceOrder.get(a.from)-sourceOrder.get(b.from))) {const node=lookup[step+1].get(link.to);link.y2=node.y+node.in+link.rows.length*scale/2;node.in+=link.rows.length*scale;}
    }
    for(const link of links){const a=lookup[link.step].get(link.from),b=lookup[link.step+1].get(link.to),width=link.rows.length*scale,ids=setFor(link.rows),key=edges.length;edges.push({ids,label:`${link.from} → ${link.to}`});link.path=`<path class="flow-link" d="M ${a.x+12} ${link.y1} C ${a.x+140} ${link.y1}, ${b.x-128} ${link.y2}, ${b.x} ${link.y2}" stroke-width="${Math.max(1,width)}" data-flow-edge="${key}" tabindex="0" role="button" aria-label="${escape(link.from)} to ${escape(link.to)}: ${link.rows.length} open services"><title>${escape(link.from)} → ${escape(link.to)} · ${link.rows.length} services</title></path>`;}
    const nodeMarkup=nodes.flatMap((column,index)=>column.map(node=>{const label=index===0?`<text x="${node.x-7}" y="${node.y+Math.min(13,node.height/2+4)}" text-anchor="end">${escape(node.label)}</text>`:`<text x="${node.x+18}" y="${node.y+Math.min(13,node.height/2+4)}">${escape(node.label)}</text>`;return `<rect class="flow-node" x="${node.x}" y="${node.y}" width="12" height="${node.height}"><title>${escape(node.label)} · ${node.count} open services</title></rect>${label}`;})).join('');
    const markup=`<svg viewBox="0 0 980 415" role="img" aria-label="Open service flow from domain group through estimated operating system to service type">${links.map(link=>link.path).join('')}${nodeMarkup}</svg>`;
    return {markup,edges,hasOs:true};
  }
  function render(){if(!source)return;const data=source.data,all=new Set(data.hosts.map(host=>host.id)),active=selected?intersection(selected,all):all;const visible=rows=>rows.filter(row=>active.has(row.hostId));
    document.querySelector('#inventoryCount').textContent=`${data.hosts.length} approved hosts · ${data.services.length} open services`;
    document.querySelector('#inventorySelection').textContent=selected?`${selectionLabel} · ${active.size} matching hosts`:`All ${all.size} approved hosts`;
    const clear=document.querySelector('#inventoryClear');clear.hidden=!selected;clear.onclick=()=>{selected=null;selectionLabel='';render();};
    const diagram=flowDiagram(visible(data.flow)),flowBox=document.querySelector('#inventoryFlow');flowBox.innerHTML=typeof diagram==='string'?diagram:diagram.markup;
    document.querySelector('#inventoryFlowTitle').textContent=typeof diagram==='string'||!diagram.hasOs?'Open services by domain':'Domains → estimated OS → services';
    document.querySelector('#inventoryFlowCaption').textContent=typeof diagram==='string'||!diagram.hasOs?'Service mix from recorded open ports. OS estimates are unavailable for these hosts.':'Connections count recorded open services. OS is an Nmap estimate; missing guesses appear as Unknown.';
    if(typeof diagram!=='string')flowBox.querySelectorAll('[data-flow-edge]').forEach(path=>{const activate=()=>{const edge=diagram.edges[Number(path.dataset.flowEdge)];choose(edge.ids,edge.label);};path.onclick=activate;path.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();activate();}};});
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
    const hostBox=document.querySelector('#inventoryHosts');hostBox.innerHTML=data.hosts.filter(host=>active.has(host.id)).slice(0,40).map(host=>`<button class="btn" type="button" data-inventory-host="${escape(host.id)}">${escape(host.name||host.ip)}</button>`).join('')+(active.size>40?`<span class="status">+${active.size-40} more hosts</span>`:'')||'<div class="empty">No matching hosts.</div>';hostBox.querySelectorAll('[data-inventory-host]').forEach(button=>button.onclick=()=>source.openHost(button.dataset.inventoryHost));
  }
  function update(findings,evidence,map,flags,scope,openHost){source={data:build(findings,evidence,map,flags,scope),openHost};render();}
  return {build,update,flowDiagram};
})();
if(typeof module!=='undefined')module.exports=InventoryStats;
