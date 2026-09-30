'use strict';
const { randomUUID } = require('node:crypto');
const { isIP } = require('node:net');
const SCHEMA_VERSION = 1;
const id = prefix => `${prefix}-${randomUUID()}`;
const now = () => new Date().toISOString();
const empty = () => ({schemaVersion:SCHEMA_VERSION, findings:[], evidence:[]});
const validDate = value => typeof value === 'string' && value.trim() && Number.isFinite(Date.parse(value));
function timestamp(value) {
  if (value === undefined || value === '') return now();
  if (!validDate(value)) throw new Error('Use an ISO timestamp for observedAt.');
  return new Date(value).toISOString();
}
function record(kind, fields, evidenceId, time) {
  return {id:id(kind), kind, ...fields, evidenceIds:evidenceId?[evidenceId]:[], firstSeen:time, lastSeen:time, createdAt:now(), updatedAt:now(), reviewStatus:'unreviewed'};
}
function migrate(data) {
  if (!Array.isArray(data)) {
    if (data?.schemaVersion === SCHEMA_VERSION && Array.isArray(data.findings) && Array.isArray(data.evidence)) return data;
    throw new Error('Unsupported findings file format.');
  }
  const doc = empty();
  for (const old of data) {
    const time = validDate(old.createdAt) ? timestamp(old.createdAt) : now();
    const ev = {id:id('evidence'), tool:old.source || 'manual', command:'', output:old.detail || '', observedAt:time, importedAt:now(), format:'legacy'};
    doc.evidence.push(ev);
    let host = doc.findings.find(f => f.kind === 'host' && f.ip === old.ip);
    if (isIP(old.ip || '') && !host) {
      host = record('host', {ip:old.ip, aliases:[], name:old.kind === 'host' && old.title !== old.ip ? old.title : '', state:'unknown', local:false, title:old.ip, detail:''}, ev.id, time);
      doc.findings.push(host);
    }
    if (old.kind !== 'host') doc.findings.push(record('observation', {title:old.title || 'Imported note', detail:old.detail || '', hostId:host?.id || null, serviceId:null}, ev.id, time));
    else if (host) {host.evidenceIds = [...new Set([...host.evidenceIds, ev.id])]; host.detail = old.detail || '';}
  }
  return doc;
}
function attributes(tag) {
  const attrs = {};
  for (const m of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[m[1]] = decode(m[2] ?? m[3]);
  return attrs;
}
function decode(s) {
  return String(s).replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (all, entity) => {
    const named = {amp:'&',lt:'<',gt:'>',quot:'"',apos:"'"};
    if (named[entity]) return named[entity];
    const n = entity[1]?.toLowerCase() === 'x' ? parseInt(entity.slice(2),16) : Number(entity.slice(1));
    return Number.isInteger(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : all;
  });
}
function validateXml(xml) {
  if (/<!ENTITY/i.test(xml)) throw new Error('XML entity declarations are not supported.');
  const stack=[];
  const clean=xml.replace(/<!--[\s\S]*?-->/g,'').replace(/<\?[\s\S]*?\?>/g,'').replace(/<!DOCTYPE[^>]*>/gi,'');
  for(const match of clean.matchAll(/<(?:"[^"]*"|'[^']*'|[^'">])*>/g)) {
    const tag=match[0],name=tag.match(/^<\/?([\w:-]+)/)?.[1];
    if(!name)throw new Error('Unsupported XML markup.');
    if(tag.startsWith('</')) {if(stack.pop()!==name)throw new Error('Malformed Nmap XML: tags do not match.');}
    else if(!/\/\s*>$/.test(tag))stack.push(name);
  }
  if(stack.length)throw new Error('Incomplete Nmap XML. Import the completed output.');
}
function parseImport(input) {
  const tool = input.tool;
  if (!['nmap','ip addr','ip neigh','ping'].includes(tool)) throw new Error('Choose nmap, ip addr, ip neigh, or ping.');
  if (typeof input.output !== 'string' || !input.output.trim()) throw new Error('Command output is required.');
  if (Buffer.byteLength(input.output) > 800000) throw new Error('Output exceeds the 800 KB import limit.');
  const output = input.output;
  const time = timestamp(input.observedAt);
  const evidence = {id:id('evidence'), tool, command:String(input.command || (tool==='nmap' ? attributes(output.match(/<nmaprun\b[^>]*>/)?.[0] || '').args : '') || tool).trim().slice(0,2000), output, observedAt:time, importedAt:now(), format:output.trim().startsWith('[')?'json':output.includes('<nmaprun')?'xml':'text'};
  const findings = [], warnings = [];
  const host = (ip, fields = {}) => {
    if (!isIP(ip || '')) return null;
    let h = findings.find(f => f.kind === 'host' && f.ip === ip);
    if (!h) { h = record('host', {ip, aliases:[], name:'', state:'unknown', local:false, title:ip, detail:'', ...fields}, evidence.id, time); findings.push(h); }
    else Object.assign(h, fields);
    return h;
  };
  const observe = (h, title, detail, service = null) => findings.push(record('observation', {hostId:h?.id || null, serviceId:service?.id || null, title, detail}, evidence.id, time));
  const service = (h, fields) => {
    if (!h || !Number.isInteger(fields.port) || fields.port < 1 || fields.port > 65535 || !['tcp','udp','sctp'].includes(fields.protocol)) return null;
    const s = record('service', {hostId:h.id, name:'', product:'', version:'', tunnel:'', state:'unknown', title:`${fields.port}/${fields.protocol}`, detail:'', ...fields}, evidence.id, time);
    findings.push(s); return s;
  };
  if (tool === 'nmap') {
    if (output.includes('<nmaprun')) {
      validateXml(output);
      if (!/<\/nmaprun\s*>/.test(output)) throw new Error('Incomplete Nmap XML. Import the completed output.');
      for (const block of output.matchAll(/<host\b[^>]*>[\s\S]*?<\/host\s*>/g)) {
        const part = block[0];
        const addresses = [...part.matchAll(/<address\b[^>]*>/g)].map(m => attributes(m[0]));
        const address = addresses.find(a => a.addrtype === 'ipv4') || addresses.find(a => a.addrtype === 'ipv6');
        if (!address) continue;
        const status = attributes(part.match(/<status\b[^>]*>/)?.[0] || '');
        const name = attributes(part.match(/<hostname\b[^>]*>/)?.[0] || '').name || '';
        const h = host(address.addr, {state:status.state || 'unknown', name, mac:addresses.find(a=>a.addrtype==='mac')?.addr || ''});
        if (!h) continue;
        const otherAddresses = addresses.filter(a=>isIP(a.addr) && a.addr !== address.addr).map(a=>a.addr);
        h.aliases = otherAddresses;
        observe(h, 'Nmap host status', `${status.state || 'unknown'}${status.reason ? ` (${status.reason})` : ''}`);
        for (const p of part.matchAll(/<port\b[^>]*>[\s\S]*?<\/port\s*>/g)) {
          const pa = attributes(p[0].match(/<port\b[^>]*>/)[0]);
          const st = attributes(p[0].match(/<state\b[^>]*>/)?.[0] || '');
          const sv = attributes(p[0].match(/<service\b[^>]*>/)?.[0] || '');
          const s = service(h, {port:Number(pa.portid), protocol:pa.protocol, state:st.state || 'unknown', name:sv.name || '', product:sv.product || '', version:sv.version || '', tunnel:sv.tunnel || '', detail:sv.extrainfo || ''});
          if (s) for (const script of p[0].matchAll(/<script\b[^>]*>/g)) {const a=attributes(script[0]); observe(h, a.id || 'Nmap script', a.output || '', s);}
        }
        const hostScripts = part.match(/<hostscript\b[^>]*>[\s\S]*?<\/hostscript>/)?.[0] || '';
        for (const script of hostScripts.matchAll(/<script\b[^>]*>/g)) {const a=attributes(script[0]);observe(h, a.id || 'Nmap host script', a.output || '');}
      }
    } else {
      let h = null, currentService = null;
      for (const line of output.split(/\r?\n/)) {
        const report = line.match(/^Nmap scan report for (.+)$/);
        if (report) {
          const named = report[1].match(/^(.*?)\s+\(([^)]+)\)$/);
          h = host(named ? named[2] : report[1].trim(), {name:named?.[1] || ''}); currentService = null; continue;
        }
        if (!h) continue;
        if (/^Host is up/.test(line)) {h.state='up';observe(h, 'Nmap host status', line.trim());}
        if (/^Host seems down/.test(line)) {h.state='down';observe(h, 'Nmap host status', line.trim());}
        const port = line.match(/^\s*(\d+)\/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/);
        if (port) {currentService = service(h, {port:Number(port[1]),protocol:port[2],state:port[3],name:port[4] === 'unknown' ? '' : port[4],product:port[5] || ''});continue;}
        const mac = line.match(/^MAC Address:\s+(\S+)/); if (mac) h.mac=mac[1];
        if (/^\|/.test(line)) observe(h, 'Nmap script output', line.replace(/^\|[_ ]?/, '').trim(), currentService);
      }
      if (!/Nmap scan report for|Nmap done:/.test(output)) throw new Error('Output is not recognized as Nmap text or XML.');
    }
  } else if (tool === 'ip addr') {
    if (output.trim().startsWith('[')) {
      let rows; try {rows=JSON.parse(output);} catch {throw new Error('Invalid ip addr JSON.');}
      for (const row of rows) for (const a of row.addr_info || []) {
        const h = host(a.local, {local:true, interface:row.ifname || '', prefix:a.prefixlen, state:row.operstate?.toLowerCase() || 'unknown'});
        if (h) observe(h, 'Local interface address', `${row.ifname || ''}: ${a.local}/${a.prefixlen} (${a.scope || 'unknown scope'})`);
      }
    } else {
      let iface = '', state = 'unknown', recognized = false;
      for (const line of output.split(/\r?\n/)) {
        const header = line.match(/^\d+:\s+(\S+?):\s+.*?(?:state\s+(\S+))?/);
        if (header) {iface=header[1].split('@')[0];state=line.match(/\bstate\s+(\S+)/)?.[1]?.toLowerCase() || 'unknown';recognized=true;}
        const a = line.match(/\binet6?\s+([\da-fA-F:.]+)\/(\d+)/);
        if (a) {const h=host(a[1], {local:true,interface:iface,prefix:Number(a[2]),state});if(h)observe(h,'Local interface address',line.trim());}
      }
      if (!recognized) throw new Error('Output is not recognized as ip addr text or JSON.');
    }
  } else if (tool === 'ip neigh') {
    if (output.trim().startsWith('[')) {
      let rows; try {rows=JSON.parse(output);} catch {throw new Error('Invalid ip neigh JSON.');}
      for (const row of rows) {
        const neighborState = Array.isArray(row.state) ? row.state.join(', ') : String(row.state || 'unknown');
        const h=host(row.dst, {interface:row.dev || '',mac:row.lladdr || '',neighborState});
        if(h)observe(h,'Neighbor table entry',`${row.dst} dev ${row.dev || ''} ${row.lladdr || ''} ${neighborState}`.trim());
      }
    } else {
      for (const line of output.split(/\r?\n/)) {
        const n=line.trim().match(/^(\S+)\s+dev\s+(\S+)(.*)$/); if(!n)continue;
        const h=host(n[1],{interface:n[2],mac:n[3].match(/\blladdr\s+(\S+)/)?.[1] || '',neighborState:n[3].trim().split(/\s+/).at(-1) || 'unknown'});
        if(h)observe(h,'Neighbor table entry',line.trim());
      }
      if (!findings.length) throw new Error('Output is not recognized as ip neigh text or JSON; use [] for an empty table.');
    }
  } else {
    const match=output.match(/(?:PING\s+[^\n]*?\(([\da-fA-F:.]+)\)|PING\s+([\da-fA-F:.]+)(?:\s|\()|Pinging\s+[^\n]*?\[([\da-fA-F:.]+)\]|Pinging\s+([\d.]+)\s)/i);
    const ip=match?.slice(1).find(Boolean);
    const reply=output.match(/(?:bytes from|Reply from)\s+([\da-fA-F:.]+)(?::|\s)/i);
    const h=host(ip || reply?.[1]);
    if(!h)throw new Error('Ping output must identify a numeric target address.');
    const received=output.match(/(\d+)\s+(?:packets?\s+)?received/i) || output.match(/Received\s*=\s*(\d+)/i);
    const goodReply=/(?:bytes from .*(?:time[=<]|icmp_seq)|Reply from .*bytes=)/i.test(output);
    const state=received ? Number(received[1]) > 0 ? 'up' : 'no-response' : goodReply ? 'up' : 'unknown';
    h.state=state;
    observe(h,'ICMP reachability',`${state}; ${output.split(/\r?\n/).filter(l=>/transmitted|received|loss|rtt|round-trip|Packets:/i.test(l)).join(' · ') || 'No complete statistics reported.'}`);
    if(state === 'no-response') warnings.push('No ICMP reply does not prove the host is down.');
  }
  if(!findings.length)warnings.push('No hosts or services were found. The source output can still be saved as evidence.');
  return {schemaVersion:SCHEMA_VERSION,findings,evidence:[evidence],warnings};
}
function mergeParsed(doc, parsed) {
  const remap = new Map(); let added=0, linked=0;
  const apply = f => {
    const key = x => f.kind === 'host' ? x.kind==='host' && ([x.ip,...(x.aliases || [])].includes(f.ip) || (f.aliases || []).includes(x.ip)) :
      f.kind === 'service' ? x.kind==='service' && x.hostId===f.hostId && x.port===f.port && x.protocol===f.protocol :
      x.kind==='observation' && x.hostId===f.hostId && x.serviceId===f.serviceId && x.title===f.title && x.detail===f.detail;
    const existing=doc.findings.find(key);
    if(existing) {
      remap.set(f.id,existing.id);
      const earliest=f.firstSeen < existing.firstSeen;
      const latest=f.lastSeen >= existing.lastSeen;
      existing.evidenceIds=[...new Set([...existing.evidenceIds,...f.evidenceIds])];
      if(f.kind==='host')f.local=existing.local || f.local;
      if(existing.reviewStatus !== 'reviewed' && latest) for(const [k,v] of Object.entries(f)) if(!['id','evidenceIds','firstSeen','lastSeen','createdAt','updatedAt','reviewStatus','aliases'].includes(k) && v !== '' && v !== 'unknown') existing[k]=v;
      if(f.kind==='host')existing.aliases=[...new Set([...(existing.aliases || []),...(f.aliases || [])])].filter(ip=>ip!==existing.ip);
      if(earliest)existing.firstSeen=f.firstSeen;if(latest)existing.lastSeen=f.lastSeen;
      existing.updatedAt=now();linked++;
    } else {doc.findings.push(f);remap.set(f.id,f.id);added++;}
  };
  for(const kind of ['host','service','observation'])for(const row of parsed.findings.filter(f=>f.kind===kind)) {
    const f={...row,evidenceIds:[...row.evidenceIds]};
    if(f.hostId)f.hostId=remap.get(f.hostId) || f.hostId;
    if(f.serviceId)f.serviceId=remap.get(f.serviceId) || f.serviceId;
    apply(f);
  }
  doc.evidence.push(...parsed.evidence);
  return {added,linked};
}
function text(value, max=2000) {return typeof value==='string'?value.trim().slice(0,max):'';}
function editFinding(doc, finding, patch) {
  const f={...finding};
  for(const k of ['title','detail'])if(k in patch)f[k]=text(patch[k],k==='title'?160:4000);
  if(!f.title)throw new Error('Title is required.');
  if(f.kind==='host') {
    for(const k of ['ip','name','mac','interface','state','neighborState'])if(k in patch)f[k]=text(patch[k],160);
    if(!isIP(f.ip))throw new Error('A valid host IP is required.');
    if('prefix' in patch){if(patch.prefix==='')delete f.prefix;else {f.prefix=Number(patch.prefix);if(!Number.isInteger(f.prefix)||f.prefix<0||f.prefix>(isIP(f.ip)===4?32:128))throw new Error('Invalid address prefix length.');}}
    if('aliases' in patch){if(!Array.isArray(patch.aliases)||patch.aliases.some(ip=>!isIP(ip)))throw new Error('Aliases must be valid IP addresses.');f.aliases=[...new Set(patch.aliases)].filter(ip=>ip!==f.ip);}
    if(doc.findings.some(x=>x.kind==='host' && x.id!==f.id && (f.aliases||[]).some(ip=>[x.ip,...(x.aliases||[])].includes(ip))))throw new Error('An alias belongs to another host. Merge the duplicates instead.');
    if(doc.findings.some(x=>x.kind==='host' && x.id!==f.id && [x.ip,...(x.aliases || [])].includes(f.ip)))throw new Error('This host already exists. Merge the duplicates instead.');
    if('local' in patch)f.local=patch.local===true;
  }
  if(f.kind==='service') {
    for(const k of ['name','product','version','state','tunnel'])if(k in patch)f[k]=text(patch[k],160);
    if('port' in patch)f.port=Number(patch.port);
    if('protocol' in patch)f.protocol=text(patch.protocol,10);
    if(!Number.isInteger(f.port)||f.port<1||f.port>65535||!['tcp','udp','sctp'].includes(f.protocol))throw new Error('Use a port from 1–65535 and tcp, udp, or sctp.');
    if(doc.findings.some(x=>x.kind==='service' && x.id!==f.id && x.hostId===f.hostId && x.port===f.port && x.protocol===f.protocol))throw new Error('This service already exists. Merge the duplicates instead.');
  }
  if(f.kind==='observation') {
    if('hostId' in patch)f.hostId=patch.hostId || null;
    if('serviceId' in patch)f.serviceId=patch.serviceId || null;
    if(f.serviceId){const s=doc.findings.find(x=>x.kind==='service'&&x.id===f.serviceId);if(!s)throw new Error('Service not found.');f.hostId=s.hostId;}
    if(f.hostId && !doc.findings.some(x=>x.kind==='host'&&x.id===f.hostId))throw new Error('Host not found.');
  }
  f.reviewStatus='reviewed';f.updatedAt=now();Object.assign(finding,f);return finding;
}
function mergeFindings(doc, targetId, sourceId) {
  const target=doc.findings.find(f=>f.id===targetId), source=doc.findings.find(f=>f.id===sourceId);
  if(!target || !source || target===source || target.kind!==source.kind)throw new Error('Choose two different findings of the same kind.');
  if(target.kind==='service' && (target.hostId!==source.hostId || target.port!==source.port || target.protocol!==source.protocol))throw new Error('Only services on the same host, port, and protocol can be merged.');
  target.evidenceIds=[...new Set([...target.evidenceIds,...source.evidenceIds])];
  target.firstSeen=[target.firstSeen,source.firstSeen].sort()[0];target.lastSeen=[target.lastSeen,source.lastSeen].sort().at(-1);
  if(source.detail && source.detail!==target.detail)target.detail=[target.detail,source.detail].filter(Boolean).join('\n');
  if(target.kind==='host')target.aliases=[...new Set([...(target.aliases || []),source.ip,...(source.aliases || [])])].filter(ip=>ip!==target.ip);
  for(const f of doc.findings){if(f.hostId===sourceId){f.hostId=targetId;f.updatedAt=now();}if(f.serviceId===sourceId){f.serviceId=targetId;f.updatedAt=now();}}
  doc.findings=doc.findings.filter(f=>f.id!==sourceId);target.reviewStatus='reviewed';target.updatedAt=now();
  if(target.kind==='host') {
    const seen=new Map();
    for(const s of [...doc.findings.filter(f=>f.kind==='service'&&f.hostId===target.id)]){
      const key=`${s.protocol}/${s.port}`;if(seen.has(key))mergeFindings(doc,seen.get(key),s.id);else seen.set(key,s.id);
    }
  }
  return target;
}
function removeFinding(doc, findingId) {
  const ids=new Set([findingId]);
  for(const f of doc.findings)if(f.hostId===findingId)ids.add(f.id);
  for(const f of doc.findings)if(ids.has(f.serviceId))ids.add(f.id);
  doc.findings=doc.findings.filter(f=>!ids.has(f.id));
}
module.exports={SCHEMA_VERSION,empty,migrate,parseImport,mergeParsed,record,id,now,timestamp,editFinding,mergeFindings,removeFinding};
