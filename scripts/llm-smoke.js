'use strict';
// Fixed-target live smoke test. It never scans ports or runs suggested checks.
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFile}=require('node:child_process');
const {createServer}=require('../server');
const target='10.0.4.80';
if(!process.argv.includes('--live'))throw new Error('Use npm run test:llm to run the live test explicitly.');
(async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'iafinder-live-'));
  const server=createServer({findingsFile:path.join(dir,'findings.json')});
  try {
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    const base=`http://127.0.0.1:${server.address().port}`;
    const call=async(route,body)=>{const r=await fetch(base+route,{...(body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(65000)});const data=await r.json();if(!r.ok)throw Error(data.error||`HTTP ${r.status}`);return data;};
    const health=await call('/api/llm/health');
    if(health.status!=='ready'){console.log(JSON.stringify({target,modelHealth:health.status,message:health.message,model:health.model},null,2));process.exitCode=1;return;}
    const observedAt=new Date().toISOString();
    const ping=await new Promise(resolve=>execFile('ping',['-n','-c','3','-W','2',target],{timeout:12000,encoding:'utf8'},(error,stdout,stderr)=>resolve({ok:!error,output:stdout||'',error:stderr||error?.message||''})));
    if(!ping.output.includes(target))throw Error('Ping did not produce importable target output.');
    const imported=await call('/api/import',{tool:'ping',command:`ping -n -c 3 -W 2 ${target}`,output:ping.output,observedAt});
    const host=imported.findings.find(f=>f.kind==='host'&&f.ip===target);
    if(!host||imported.findings.some(f=>f.kind==='host'&&f.ip!==target))throw Error('Unexpected target in test findings.');
    const analysis=await call('/api/analysis',{hostId:host.id}),latest=await call('/api/analysis/latest');
    const checks={onlyAllowedTarget:analysis.scope.ips.length===1&&analysis.scope.ips[0]===target,evidenceLinked:analysis.assessments.every(a=>a.findingIds.length&&a.evidenceIds.length),savedResult:latest.analysis?.snapshotId===analysis.snapshotId,modelAnalyzed:analysis.source==='local model'&&analysis.status==='complete'};
    const report={testedAt:new Date().toISOString(),target,pingResponded:ping.ok,health,checks,analysis};
    const reportPath=path.join(os.tmpdir(),'iafinder-llm-live-test.json');fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify({target,pingResponded:ping.ok,modelHealth:health.status,model:health.model,analysisStatus:analysis.status,analysisSource:analysis.source,checks,reportPath},null,2));
    if(!Object.values(checks).every(Boolean))process.exitCode=1;
  }catch(e){console.error(e.message);process.exitCode=1;}
  finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));fs.rmSync(dir,{recursive:true,force:true});}
})();
