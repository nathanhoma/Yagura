'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const F=require('../findings');
const {createServer}=require('../server');
const {createLlmService}=require('../llm');
const {analyze,buildContext,validateResult}=require('../analysis');
const target='10.0.4.80';
const output=`<nmaprun><host><status state="up"/><address addr="${target}" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.24"/></port></ports></host></nmaprun>`;
function doc(){const d=F.empty();F.mergeParsed(d,F.parseImport({tool:'nmap',command:`nmap -sV -oX - ${target}`,output}));return d;}
function response(data,status=200){return {ok:status<400,status,json:async()=>data};}
function validModelResult(context){const f=context.findings.find(f=>f.kind==='service')||context.findings[0];return {assessments:[{findingIds:[f.id],evidenceIds:[f.evidenceIds[0]],interpretation:'An observed service requires further review; its banner alone does not confirm a vulnerability.',uncertainties:['No authentication or access evidence is recorded.']}],suggestions:context.candidates.slice(0,1).map(c=>({candidateId:c.id}))};}
test('Health selects one advertised model automatically and never exposes credentials',async()=>{
  let auth;
  const llm=createLlmService({baseUrl:'http://localhost:8100/v1',apiKey:'test-secret',request:async(url,options)=>{auth=options.headers.Authorization;assert.equal(options.redirect,'error');return response({data:[{id:'local-lab-model'}]});}});
  const health=await llm.health();assert.equal(health.status,'ready');assert.equal(health.model,'local-lab-model');assert.equal(auth,'Bearer test-secret');assert.ok(!JSON.stringify(health).includes('test-secret'));
});
test('Multiple models require explicit selection; unsafe URLs never receive requests',async()=>{
  const many=createLlmService({baseUrl:'http://localhost:8100/v1',request:async()=>response({data:[{id:'a'},{id:'b'}]})});assert.equal((await many.health()).status,'model-required');
  let calls=0;for(const baseUrl of ['https://example.com/v1','http://user:secret@localhost/v1','http://localhost/v1?api_key=secret']){const llm=createLlmService({baseUrl,request:async()=>{calls++;}});assert.equal((await llm.health()).status,'blocked');}
  assert.equal(calls,0);
});
test('Selected advertised model overrides the server default; unknown models are rejected',async()=>{
  let used;
  const llm=createLlmService({baseUrl:'http://localhost:8100/v1',model:'default',request:async(url,options)=>{
    if(url.endsWith('/models'))return response({data:[{id:'default'},{id:'chosen'}]});
    used=JSON.parse(options.body).model;return response({choices:[{message:{content:'{}'}}]});
  }});
  await llm.complete([],{model:'chosen'});assert.equal(used,'chosen');
  await assert.rejects(llm.complete([],{model:'missing'}),e=>e.code==='model-unavailable');
});
test('Analyses cite supplied evidence and use server-generated candidate commands',async()=>{
  const d=doc();let sent;
  const llm=createLlmService({baseUrl:'http://localhost:8100/v1',model:'local-model',request:async(url,options)=>{sent=JSON.parse(options.body);const context=JSON.parse(sent.messages[1].content),result=validModelResult(context);result.suggestions[0].command='invented-command';return response({choices:[{message:{content:JSON.stringify(result)}}]});}});
  const result=await analyze(d,{authorizedCidr:`${target}/32`},llm);assert.equal(result.source,'local model');assert.equal(result.status,'complete');assert.equal(result.model,'local-model');assert.equal(result.assessments.length,1);assert.ok(result.suggestions.every(s=>s.command.includes(target)&&s.command!=='invented-command'));assert.ok(JSON.parse(sent.messages[1].content).evidence[0].output.includes(target));
});
test('Unknown, unrelated, or missing citations are rejected',()=>{
  const d=doc(),context=buildContext(d),valid=validModelResult(context);
  assert.throws(()=>validateResult({...valid,assessments:[{...valid.assessments[0],findingIds:['invented']}],suggestions:[]},context),/no valid/);
  assert.throws(()=>validateResult({...valid,assessments:[{...valid.assessments[0],evidenceIds:['invented']}],suggestions:[]},context),/no valid/);
  const observation=F.record('observation',{title:'unrelated',detail:'different source',hostId:null,serviceId:null},'unrelated-evidence',F.now());d.findings.push(observation);d.evidence.push({id:'unrelated-evidence',tool:'manual',command:'manual',output:'unrelated',observedAt:F.now()});
  assert.throws(()=>validateResult({assessments:[{...valid.assessments[0],evidenceIds:['unrelated-evidence']}],suggestions:[]},buildContext(d)),/no valid/);
});
test('Provider failures and invalid output produce explicit fallback, never pretend model success',async()=>{
  for(const [code,request] of [['authentication',async()=>response({},401)],['invalid-response',async()=>response({choices:[{message:{content:'not JSON'}}]})],['invalid-response',async()=>response({choices:[{message:{content:'{}'},finish_reason:'length'}]})],['unreachable',async()=>{throw new Error('network');}]]) {
    const llm=createLlmService({baseUrl:'http://localhost:8100/v1',model:'test',request});const r=await analyze(doc(),{},llm);assert.equal(r.status,'fallback');assert.equal(r.source,'built-in');assert.equal(r.error.code,code);assert.ok(r.assessments.length);assert.ok(r.suggestions.every(s=>s.command.includes(target)));
  }
});
test('Empty scope avoids a model request; invalid scope is rejected',async()=>{
  let requests=0;const llm=createLlmService({request:async()=>{requests++;}});assert.equal((await analyze(F.empty(),{},llm)).status,'no-findings');assert.equal(requests,0);await assert.rejects(analyze(doc(),{hostId:'invented'},llm),/existing hostId/);
});
test('Context and excerpts are bounded without changing raw evidence',()=>{
  const d=doc(),raw='x'.repeat(80000);d.evidence[0].output=raw;for(let i=0;i<200;i++)d.findings.push(F.record('observation',{title:`obs ${i}`,detail:'a'.repeat(4000),hostId:d.findings[0].id,serviceId:null},d.evidence[0].id,F.now()));
  const context=buildContext(d);assert.ok(context.truncated);assert.ok(context.evidence.length>0);assert.ok(context.findings.length<=100);assert.ok(context.evidence.length<=40);assert.ok(JSON.stringify(context).length<24500);assert.equal(d.evidence[0].output,raw);
});
async function listen(t,server) {await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));return `http://127.0.0.1:${server.address().port}`;}
test('Suggested checks execute fixed arguments only after authorization',async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'yagura-check-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const calls=[];
  const app=await listen(t,createServer({findingsFile:path.join(dir,'findings.json'),run:async(program,args)=>{calls.push([program,args]);return {ok:true,stdout:output,stderr:''};}}));
  const post=async(route,body)=>{const r=await fetch(app+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return {status:r.status,data:await r.json()};};
  await post('/api/import',{tool:'nmap',output,command:`nmap -sV ${target}`});
  const checks=await (await fetch(app+`/api/workflow?cidr=${target}/32`)).json(),candidate=checks.candidates.find(c=>c.catalogId==='http-headers');
  assert.ok(candidate);
  assert.equal((await post('/api/checks/run',{candidateId:candidate.id})).status,400);
  assert.equal((await post('/api/checks/run',{candidateId:'invented',authorized:true})).status,400);
  assert.equal(calls.length,0);
  const done=await post('/api/checks/run',{candidateId:candidate.id,authorized:true,authorizedCidr:`${target}/32`});
  assert.equal(done.status,200);assert.deepEqual(calls[0],['curl',['-I','--max-time','5',`https://${target}:443/`]]);
  assert.equal(done.data.command,candidate.command);assert.equal(done.data.imported,false);
  const osCandidate=checks.candidates.find(c=>c.catalogId==='nmap-os');assert.ok(osCandidate);
  assert.equal((await post('/api/checks/run',{candidateId:osCandidate.id,authorized:true,authorizedCidr:`10.0.4.81/32`})).status,400);
  const osRun=await post('/api/checks/run',{candidateId:osCandidate.id,authorized:true,authorizedCidr:`${target}/32`});
  assert.equal(osRun.status,200);assert.deepEqual(calls[1],['nmap',['-n','-Pn','-O',target]]);
});
test('Nmap check output becomes linked findings',async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'yagura-check-import-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const app=await listen(t,createServer({findingsFile:path.join(dir,'findings.json'),run:async()=>({ok:true,stdout:output,stderr:''})}));
  const post=async(route,body)=>{const r=await fetch(app+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return {status:r.status,data:await r.json()};};
  await post('/api/findings',{ip:target,title:'Target',detail:'Authorized local target'});
  const workflow=await (await fetch(app+`/api/workflow?cidr=${target}/32`)).json(),candidate=workflow.candidates.find(c=>c.catalogId==='nmap-ports');
  assert.ok(candidate);
  const done=await post('/api/checks/run',{candidateId:candidate.id,authorized:true,authorizedCidr:`${target}/32`});assert.equal(done.status,200);assert.equal(done.data.imported,true);
  const doc=await (await fetch(app+'/api/findings')).json();assert.ok(doc.findings.some(f=>f.kind==='service'&&f.port===443));
});
test('Real HTTP model adapter: health, scoped analysis, saved results, stale detection and input validation',async t=>{
  let completions=0,lastContext;
  const model=http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req)raw+=chunk;
    res.setHeader('Content-Type','application/json');
    if(req.url==='/v1/models')return res.end(JSON.stringify({data:[{id:'integration-model'}]}));
    assert.equal(req.url,'/v1/chat/completions');assert.equal(req.headers.authorization,'Bearer dummy-key');completions++;
    const body=JSON.parse(raw);lastContext=JSON.parse(body.messages[1].content);assert.equal(body.model,'integration-model');
    res.end(JSON.stringify({choices:[{message:{content:JSON.stringify(validModelResult(lastContext))}}]}));
  });
  const modelUrl=await listen(t,model),dir=fs.mkdtempSync(path.join(os.tmpdir(),'yagura-analysis-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const app=await listen(t,createServer({findingsFile:path.join(dir,'findings.json'),llmBase:modelUrl+'/v1',llmModel:'',llmKey:'dummy-key'}));
  const call=async(route,body,method='POST')=>{const r=await fetch(app+route,{method,headers:{'Content-Type':'application/json'},...(method==='POST'?{body:JSON.stringify(body)}:{})});return {status:r.status,data:await r.json()};};
  assert.equal((await call('/api/llm/health',null,'GET')).data.status,'ready');
  const imported=await call('/api/import',{tool:'nmap',output,command:`nmap -sV ${target}`});const h=imported.data.findings.find(f=>f.kind==='host');
  const result=await call('/api/analysis',{hostId:h.id});assert.equal(result.status,200);assert.equal(result.data.source,'local model');assert.equal(result.data.stale,false);assert.deepEqual(result.data.scope.ips,[target]);assert.equal(completions,1);assert.ok(lastContext.findings.every(f=>f.kind!=='host'||f.ip===target));
  const latest=await call('/api/analysis/latest',null,'GET');assert.deepEqual(latest.data.analysis,result.data);assert.ok(fs.existsSync(path.join(dir,'analysis.json')));
  for(const body of [{hostId:'unknown'},{findings:[]},{hostId:0},[]])assert.equal((await call('/api/analysis',body)).status,400);
  await call('/api/findings',{ip:target,title:'Additional observation',detail:'Updated evidence'});assert.equal((await call('/api/analysis/latest',null,'GET')).data.analysis.stale,true);
});
test('Requests for an identical analysis snapshot share a single in-flight completion',async t=>{
  let resolveModel,notify;const started=new Promise(r=>notify=r);let calls=0;
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'yagura-analysis-concurrent-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const app=await listen(t,createServer({findingsFile:path.join(dir,'findings.json'),llmBase:'http://localhost:8100/v1',llmModel:'test',fetch:async(url,options)=>{calls++;const context=JSON.parse(JSON.parse(options.body).messages[1].content);notify();await new Promise(r=>resolveModel=r);return response({choices:[{message:{content:JSON.stringify(validModelResult(context))}}]});}}));
  const post=(route,body)=>fetch(app+route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  await post('/api/import',{tool:'nmap',output});const a=post('/api/analysis',{});await started;const b=post('/api/analysis',{});
  // An API read lets both incoming POST bodies be processed before the model completes.
  await fetch(app+'/api/analysis/latest');resolveModel();const [ra,rb]=await Promise.all([a,b]);assert.deepEqual(await ra.json(),await rb.json());assert.equal(calls,1);
});

test('A stalled HTTP model request times out and returns fallback',async t=>{
  const modelUrl=await listen(t,http.createServer(()=>{}));
  const llm=createLlmService({baseUrl:modelUrl+'/v1',model:'test',timeoutMs:100});
  const result=await analyze(doc(),{},llm);assert.equal(result.status,'fallback');assert.equal(result.error.code,'timeout');
});
