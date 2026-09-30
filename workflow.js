'use strict';
const { isIP } = require('node:net');
function isLocalIp(ip) {
  if(isIP(ip)!==4)return false;
  const p=ip.split('.').map(Number);
  return p[0]===10 || p[0]===172 && p[1]>=16 && p[1]<=31 || p[0]===192 && p[1]===168 || p[0]===127 || p[0]===169 && p[1]===254;
}
const commandCatalog=[
  {id:'neighbors',title:'Refresh local neighbors',command:'ip -4 neigh',when:'Refresh neighbor entries seen on the local link.'},
  {id:'ping',title:'Check host reachability',command:'ping -c 3 {host}',when:'Check ICMP reachability of a recorded host.'},
  {id:'nmap-ports',title:'Check common TCP ports',command:'nmap -n -Pn --top-ports 100 {host}',when:'Discover common services when a target has no recorded open TCP ports.'},
  {id:'nmap-service',title:'Identify service versions',command:'nmap -n -Pn -sV --version-light -p {ports} {host}',when:'Identify versions on recorded open TCP ports.'},
  {id:'http-headers',title:'Inspect HTTP headers',command:'curl -I --max-time 5 {scheme}://{host}:{port}/',when:'Review headers for a recorded open web service.'},
  {id:'smb-shares',title:'List SMB shares',command:'smbclient -L //{host} -N',when:'Check advertised shares for a recorded open SMB service.'}
];
function workflow(doc) {
  const candidates=[];
  const add=(catalogId,host,services,reason,values={})=>{
    const catalog=commandCatalog.find(c=>c.id===catalogId);
    const findingIds=[host.id,...services.map(s=>s.id)];
    const evidenceIds=[...new Set(findingIds.flatMap(id=>doc.findings.find(f=>f.id===id)?.evidenceIds || []))];
    if(!evidenceIds.length)return;
    const replacements={host:host.ip,...values};
    const command=catalog.command.replace(/\{(\w+)\}/g,(all,key)=>replacements[key] ?? all);
    candidates.push({id:`${catalogId}:${host.id}:${services.map(s=>s.id).join(',')}`,catalogId,title:catalog.title,command,hostId:host.id,serviceIds:services.map(s=>s.id),findingIds,evidenceIds,reason});
  };
  const targets=doc.findings.filter(f=>f.kind==='host').map(host=>{
    const services=doc.findings.filter(s=>s.kind==='service'&&s.hostId===host.id);
    const observations=doc.findings.filter(o=>o.kind==='observation'&&o.hostId===host.id);
    const open=services.filter(s=>s.state==='open');
    const eligible=isLocalIp(host.ip)&&!host.local&&host.state!=='down';
    if(eligible) {
      if(host.state!=='up')add('ping',host,[],`Host ${host.ip} is recorded with reachability ${host.state}; verify ICMP response.`);
      const tcp=open.filter(s=>s.protocol==='tcp');
      if(!tcp.length)add('nmap-ports',host,[],`Host ${host.ip} has no recorded open TCP services; discover common ports.`);
      const unknown=tcp.filter(s=>!s.product && !s.version);
      if(unknown.length)add('nmap-service',host,unknown,`Open TCP ports ${unknown.map(s=>s.port).join(', ')} lack recorded product/version information.`,{ports:unknown.map(s=>s.port).sort((a,b)=>a-b).join(',')});
      for(const s of tcp) {
        if(/http|www/i.test(s.name) || [80,443,8000,8080,8443].includes(s.port))add('http-headers',host,[s],`Recorded open ${s.port}/tcp (${s.name || 'web-associated port'}) supports a web header check.`,{port:s.port,scheme:s.tunnel==='ssl'||/https/i.test(s.name)||[443,8443].includes(s.port)?'https':'http'});
        if(s.port===445 || /^(microsoft-ds|netbios-ssn|smb)$/.test(s.name))add('smb-shares',host,[s],`Recorded open ${s.port}/tcp (${s.name || 'SMB-associated port'}) supports share enumeration.`);
      }
    }
    const stage=host.local?'local context':!open.length?'recon':open.some(s=>!s.product&&!s.version)?'service identification':'access triage';
    return {host,services,observations,stage,eligible,scopeReason:eligible?'':host.local?'Local interface address':!isLocalIp(host.ip)?'Imported target outside local IPv4 suggestion scope':host.state==='down'?'Last recorded host state is down':''};
  });
  return {targets,candidates};
}
module.exports={isLocalIp,commandCatalog,workflow};
