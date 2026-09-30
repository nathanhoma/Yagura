'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const F=require('../findings');
const {workflow}=require('../workflow');
const {createServer,validCidr,isPrivateLlmUrl}=require('../server');
const fixture=name=>fs.readFileSync(path.join(__dirname,'fixtures',name),'utf8');
const input=(tool,file,time='2026-09-29T12:00:00Z')=>({tool,command:`${tool} example`,output:fixture(file),observedAt:time});
function imported(){const doc=F.empty();F.mergeParsed(doc,F.parseImport(input('nmap','nmap.xml')));return doc;}
function validLinks(doc) {
  const ids=new Map(doc.findings.map(f=>[f.id,f]));const evidence=new Set(doc.evidence.map(e=>e.id));
  for(const f of doc.findings){if(f.hostId)assert.equal(ids.get(f.hostId)?.kind,'host');if(f.serviceId){assert.equal(ids.get(f.serviceId)?.kind,'service');assert.equal(ids.get(f.serviceId).hostId,f.hostId);}assert.ok(f.evidenceIds.length);for(const id of f.evidenceIds)assert.ok(evidence.has(id));assert.ok(f.firstSeen<=f.lastSeen);}
}
test('Nmap XML parses attributes, entities, states, versions and script links',()=>{
  const doc=imported();validLinks(doc);assert.equal(doc.findings.find(f=>f.kind==='host').name,'lab&web');assert.equal(doc.findings.filter(f=>f.kind==='service').length,5);
  const obs=doc.findings.find(f=>f.title==='http-title');assert.equal(obs.detail,'Hello "lab"');assert.ok(obs.serviceId);
  const s=doc.findings.find(f=>f.port===80);assert.equal(s.product,'nginx');assert.equal(s.version,'1.24');assert.equal(doc.evidence[0].output,fixture('nmap.xml'));
});
test('Nmap text links services and scripts to their host',()=>{const d=F.parseImport(input('nmap','nmap.txt'));validLinks(d);assert.equal(d.findings.filter(f=>f.kind==='service').length,3);assert.equal(d.findings.find(f=>f.kind==='host').state,'up');assert.ok(d.findings.find(f=>f.title==='Nmap script output').serviceId);});
for(const [tool,file,count] of [['ip addr','addr.txt',4],['ip addr','addr.json',2],['ip neigh','neigh.txt',3],['ip neigh','neigh.json',2],['ping','ping.txt',1]])test(`${tool} parses ${file}`,()=>{const d=F.parseImport(input(tool,file));validLinks(d);assert.equal(d.findings.filter(f=>f.kind==='host').length,count);});
test('No ICMP replies are not treated as a down host; Windows statistics supported',()=>{
  const d=F.parseImport({tool:'ping',output:'PING 192.168.56.10 (192.168.56.10) 56(84) bytes of data.\n3 packets transmitted, 0 received, 100% packet loss'});assert.equal(d.findings[0].state,'no-response');assert.ok(d.warnings.length);
  const w=F.parseImport({tool:'ping',output:'Pinging lab [192.168.56.10] with 32 bytes of data:\nReply from 192.168.56.10: bytes=32 time<1ms TTL=64\nPackets: Sent = 3, Received = 3, Lost = 0 (0% loss)'});assert.equal(w.findings[0].state,'up');
});
test('Empty scans and empty JSON tables retain evidence; malformed input rejected',()=>{
  assert.equal(F.parseImport({tool:'nmap',output:'<nmaprun><runstats/></nmaprun>'}).findings.length,0);
  assert.equal(F.parseImport({tool:'ip neigh',output:'[]'}).evidence.length,1);
  for(const [tool,output] of [['nmap','<nmaprun>'],['nmap','random'],['ip addr','random'],['ip neigh','random'],['ping','hostname only']])assert.throws(()=>F.parseImport({tool,output}));
  assert.throws(()=>F.parseImport({tool:'ping',output:fixture('ping.txt'),observedAt:'invalid'}));
});
test('Repeated imports deduplicate and attach evidence; reviewed edits survive; chronology retained',()=>{
  const d=imported(),h=d.findings.find(f=>f.kind==='host'),s=d.findings.find(f=>f.port===80),count=d.findings.length;
  F.editFinding(d,h,{name:'Corrected host'});F.editFinding(d,s,{product:'Corrected server'});
  const summary=F.mergeParsed(d,F.parseImport(input('nmap','nmap.xml','2026-09-30T12:00:00Z')));
  assert.equal(d.findings.length,count);assert.equal(summary.added,0);assert.equal(h.name,'Corrected host');assert.equal(s.product,'Corrected server');assert.equal(h.evidenceIds.length,2);assert.equal(h.firstSeen,'2026-09-29T12:00:00.000Z');assert.equal(h.lastSeen,'2026-09-30T12:00:00.000Z');validLinks(d);
});
test('Host merge combines evidence, aliases, matching services and observation references',()=>{
  const d=imported();F.mergeParsed(d,F.parseImport({...input('nmap','nmap.xml'),output:fixture('nmap.xml').replaceAll('192.168.56.10','192.168.56.20')}));
  const hosts=d.findings.filter(f=>f.kind==='host');F.mergeFindings(d,hosts[0].id,hosts[1].id);assert.equal(d.findings.filter(f=>f.kind==='host').length,1);assert.equal(d.findings.filter(f=>f.kind==='service').length,5);assert.deepEqual(hosts[0].aliases,['192.168.56.20']);validLinks(d);
  F.mergeParsed(d,F.parseImport({...input('nmap','nmap.xml'),output:fixture('nmap.xml').replaceAll('192.168.56.10','192.168.56.20')}));assert.equal(d.findings.filter(f=>f.kind==='host').length,1);assert.equal(d.findings.filter(f=>f.kind==='service').length,5);validLinks(d);
});
test('Service deletion cascades observations; host deletion cascades services; evidence survives',()=>{
  const d=imported(),s=d.findings.find(f=>f.port===80);F.removeFinding(d,s.id);assert.ok(!d.findings.some(f=>f.serviceId===s.id));validLinks(d);F.removeFinding(d,d.findings.find(f=>f.kind==='host').id);assert.equal(d.findings.length,0);assert.equal(d.evidence.length,1);
});
test('Legacy notes migrate to linked findings with evidence',()=>{const d=F.migrate([{id:'old',kind:'host',ip:'192.168.56.10',title:'lab',detail:'Discovered',source:'nmap',createdAt:'2026-09-29T12:00:00Z'},{kind:'note',ip:'192.168.56.10',title:'Web note',detail:'observed'}]);validLinks(d);assert.equal(d.findings.filter(f=>f.kind==='host').length,1);assert.equal(d.findings[1].kind,'observation');});
test('Workflow uses only observed open services, resolves HTTPS, links evidence',()=>{
  const d=imported(),w=workflow(d);assert.equal(w.targets[0].stage,'service identification');assert.ok(!w.candidates.some(c=>c.catalogId==='nmap-ports'));assert.ok(w.candidates.some(c=>c.command==='curl -I --max-time 5 https://192.168.56.10:443/'));assert.ok(w.candidates.some(c=>c.catalogId==='smb-shares'));
  const version=w.candidates.find(c=>c.catalogId==='nmap-service');assert.ok(version.command.includes('-p 443,445'));for(const c of w.candidates){assert.ok(!c.command.includes('{'));assert.ok(c.evidenceIds.length);}
  d.findings.find(f=>f.kind==='host').ip='8.8.8.8';assert.equal(workflow(d).candidates.length,0);d.findings.find(f=>f.kind==='host').ip='192.168.56.10';d.findings.find(f=>f.kind==='host').local=true;assert.equal(workflow(d).candidates.length,0);
});
test('Scope validation rejects public, malformed and oversized ranges',()=>{
  for(const cidr of ['8.8.8.0/24','1.2.3.4/32','192.168.0.0/21','192.168.300.1/24','192.168.1.1/','192.168.1.1/32/extra'])assert.equal(validCidr(cidr),false,cidr);
  for(const cidr of ['192.168.56.0/24','10.0.0.0/22','127.0.0.1/32','169.254.0.0/24'])assert.equal(validCidr(cidr),true,cidr);
  assert.equal(isPrivateLlmUrl('https://example.com'),false);assert.equal(isPrivateLlmUrl('http://127.0.0.1:11434/v1'),true);assert.equal(isPrivateLlmUrl('http://user:pass@localhost'),false);
});
async function serve(t,options={}) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'yagura-test-'));const file=path.join(dir,'findings.json');
  const server=createServer({findingsFile:file,llmBase:'',llmModel:'',run:async()=>({ok:false,stdout:'',stderr:'test tool unavailable'}),...options});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));fs.rmSync(dir,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${server.address().port}`;
  const call=async(url,method='GET',body)=>{const r=await fetch(base+url,{method,headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,data:await r.json()};};
  return {call,base,file};
}
test('API preview does not persist; import, edit, export, merge and delete round trip',async t=>{
  const {call,base,file}=await serve(t);
  assert.equal((await call('/api/import/preview','POST',input('nmap','nmap.xml'))).status,200);assert.ok(!fs.existsSync(file));
  const saved=await call('/api/import','POST',input('nmap','nmap.xml'));assert.equal(saved.status,201);validLinks(saved.data);
  const h=saved.data.findings.find(f=>f.kind==='host');assert.equal((await call('/api/findings/'+h.id,'PATCH',{name:'Reviewed'})).status,200);
  const doc=(await call('/api/findings')).data;assert.equal(doc.findings.find(f=>f.id===h.id).name,'Reviewed');
  const exported=await fetch(base+'/api/export');assert.deepEqual(await exported.json(),doc);assert.ok(exported.headers.get('content-disposition').includes('.json'));
  const csv=await (await fetch(base+'/api/export?format=csv')).text();assert.ok(csv.includes('sourceCommands'));assert.ok(csv.includes('nmap example'));
  for(const url of ['/.env','/server.js','/data/findings.json'])assert.equal((await fetch(base+url)).status,404);
  const check=await call('/api/suggest','POST',{findings:[{ip:'8.8.8.8'}]});assert.equal(check.data.source,'built-in');assert.ok(check.data.suggestions.every(s=>s.command.includes('192.168.56.10')));
  const note=await call('/api/findings','POST',{ip:h.ip,title:'note',detail:'observed'});const note2=await call('/api/findings','POST',{ip:h.ip,title:'duplicate',detail:'duplicate observation'});
  const merged=await call('/api/findings/merge','POST',{targetId:note.data.finding.id,sourceId:note2.data.finding.id});assert.equal(merged.status,200);validLinks(merged.data);
  assert.equal((await call('/api/findings/'+h.id,'DELETE')).data.findings.length,0);
});
test('Local discovery stores source commands and normalized evidence',async t=>{
  const {call}=await serve(t,{run:async(command,args)=>({ok:true,stdout:fixture(args.at(-1)==='addr'?'addr.json':'neigh.json'),stderr:''})});
  const r=await call('/api/discovery/local','POST',{});assert.equal(r.status,200);assert.equal(r.data.interfaces.length,2);const d=(await call('/api/findings')).data;validLinks(d);assert.deepEqual(d.evidence.map(e=>e.command),['ip -j -4 addr','ip -j -4 neigh']);
});
test('LLM can only choose eligible candidates; invented commands and reasons never pass through',async t=>{
  let sent,malicious=false;
  const {call}=await serve(t,{llmBase:'http://127.0.0.1:11434/v1',llmModel:'test',fetch:async(url,options)=>{sent=JSON.parse(options.body);const context=JSON.parse(sent.messages[1].content);return {ok:true,json:async()=>({choices:[{message:{content:JSON.stringify({suggestions:malicious?[{candidateId:'invented',command:'bad'}]:[{candidateId:context.candidates[0].id,command:'bad',reason:'Invented vulnerability'},{candidateId:'invented'}]})}}]})};}});
  await call('/api/import','POST',input('nmap','nmap.xml'));const r=await call('/api/suggest','POST',{});assert.equal(r.data.source,'local model');assert.equal(r.data.suggestions.length,1);assert.ok(!JSON.stringify(r.data.suggestions).includes('Invented vulnerability'));assert.ok(r.data.suggestions.every(s=>s.command!=='bad'));assert.ok(JSON.parse(sent.messages[1].content).findings.length);
  malicious=true;const fallback=await call('/api/suggest','POST',{});assert.equal(fallback.data.source,'built-in');assert.ok(fallback.data.suggestions.length);
});
test('Unreadable storage fails explicitly instead of losing records',async t=>{const {call,file}=await serve(t);fs.writeFileSync(file,'broken');assert.equal((await call('/api/findings')).status,500);assert.equal((await call('/api/import','POST',input('nmap','nmap.xml'))).status,500);assert.equal(fs.readFileSync(file,'utf8'),'broken');});
test('Legacy migration is persisted once so graph IDs remain stable across API reads',async t=>{
  const {call,file}=await serve(t);fs.writeFileSync(file,JSON.stringify([{kind:'host',ip:'192.168.56.10',title:'lab',detail:'found',source:'nmap'}]));
  const a=(await call('/api/findings')).data,b=(await call('/api/findings')).data;assert.deepEqual(a,b);assert.ok(fs.existsSync(file+'.legacy.bak'));assert.equal((await call('/api/workflow')).data.targets[0].host.id,a.findings[0].id);
});
test('Local interface identity remains local when a neighbor import mentions it',()=>{
  const d=F.empty();F.mergeParsed(d,F.parseImport(input('ip addr','addr.json')));F.mergeParsed(d,F.parseImport({tool:'ip neigh',output:'192.168.56.2 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE'}));assert.equal(d.findings.find(f=>f.ip==='192.168.56.2').local,true);assert.equal(workflow(d).candidates.length,0);
});
test('Malformed XML nesting fails before saving any findings',()=>assert.throws(()=>F.parseImport({tool:'nmap',output:'<nmaprun><host><address addr="192.168.56.10" addrtype="ipv4"/></nmaprun>'}),/tags do not match/));
test('Model selection is revalidated if a target is deleted during the request',async t=>{
  let started,release;const waiting=new Promise(resolve=>started=resolve),released=new Promise(resolve=>release=resolve);let chosen;
  const {call}=await serve(t,{llmBase:'http://127.0.0.1:11434/v1',llmModel:'test',fetch:async(url,options)=>{chosen=JSON.parse(JSON.parse(options.body).messages[1].content).candidates[0].id;started();await released;return {ok:true,json:async()=>({choices:[{message:{content:JSON.stringify({suggestions:[{candidateId:chosen}]})}}]})};}});
  const imported=await call('/api/import','POST',input('nmap','nmap.xml'));const h=imported.data.findings.find(f=>f.kind==='host');const pending=call('/api/suggest','POST',{});await waiting;await call('/api/findings/'+h.id,'DELETE');release();const result=await pending;assert.equal(result.data.suggestions.length,0);
});
