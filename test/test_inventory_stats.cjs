'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {build,progressDiagram}=require('../inventory-stats.js');

test('inventory statistics count only eligible hosts and confirmed open services',()=>{
  const hosts=[
    {id:'h1',kind:'host',ip:'10.0.0.1',name:'www.dev.example.test',evidenceIds:['e1'],lastSeen:'2026-10-20T00:00:00Z'},
    {id:'h2',kind:'host',ip:'10.0.0.2',name:'db.dev.example.test',evidenceIds:[]},
    {id:'h3',kind:'host',ip:'10.0.1.1',name:'other.example.test',evidenceIds:[]},
  ];
  const findings=[...hosts,
    {id:'s1',kind:'service',hostId:'h1',port:443,protocol:'tcp',state:'open',name:'https',product:'nginx',version:'1.27',evidenceIds:['e1']},
    {id:'s2',kind:'service',hostId:'h2',port:443,protocol:'tcp',state:'closed',name:'https',evidenceIds:[]},
    {id:'s3',kind:'service',hostId:'h3',port:22,protocol:'tcp',state:'open',name:'ssh',evidenceIds:[]},
    {id:'o2',kind:'observation',hostId:'h1',title:'Nmap OS guess',detail:'FreeBSD (89% accuracy)',lastSeen:'2026-10-20T00:00:00Z',evidenceIds:['e1']},
    {id:'o1',kind:'observation',hostId:'h1',title:'Nmap OS guess',detail:'Linux (95% accuracy)',lastSeen:'2026-10-20T00:00:00Z',evidenceIds:['e1']},
  ];
  const evidence=[{id:'e1',tool:'nmap',command:'nmap -n -Pn -sT -p 443 10.0.0.1',observedAt:'2026-10-20T00:00:00Z',output:'443/tcp open https'}];
  const map={targets:hosts.map((host,i)=>({host,eligible:i<2}))};
  const stats=build(findings,evidence,map,[{hostId:'h1',kind:'software'},{hostId:'h3',kind:'exposure'}],{domains:['example.test']});
  assert.equal(stats.hosts.length,2);
  assert.equal(stats.services.length,1);
  assert.deepEqual(stats.osRows.map(row=>row.label),['Linux','Unknown']);
  assert.equal(stats.progress.length,2);
  assert.equal(stats.progress[0].stages[2],'Investigated');
  assert.equal(stats.progress[1].stages[2],'Not investigated');
  assert.equal(stats.portsScanned.size,1);
  assert.equal(stats.coverage[0].states[0],'recorded');
  assert.equal(stats.coverage[1].states[0],'recorded'); // closed is recorded, not open
  assert.equal(stats.leadRows.length,1);
  assert.equal(stats.productRows[0].label,'nginx 1.27');
});

test('progress counts each host once even with multiple services and saved runs',()=>{
  const host={id:'h1',kind:'host',ip:'10.0.0.1',name:'web.example.test',evidenceIds:[]};
  const scope={cidrs:['10.0.0.0/24'],domains:[],matchMode:'and'};
  const services=[80,443].map((port,i)=>({id:`s${i}`,kind:'service',hostId:'h1',port,protocol:'tcp',state:'open',name:'http',evidenceIds:[]}));
  const run={scope,mode:'group',events:[{type:'deep-dive-selection',hostId:'h1'},
    {type:'check',hostId:'h1',outcome:'completed',imported:true}]};
  const stats=build([host,...services],[],{targets:[{host,eligible:true}]},[{hostId:'h1',kind:'web'}],scope,[run]);
  assert.equal(stats.services.length,2);
  assert.equal(stats.progress.length,1);
  assert.deepEqual(stats.progress[0].stages,['Recorded in scope','Approved','Investigated','Review lead','Deep dive done']);
  const diagram=progressDiagram(stats.progress);
  assert.match(diagram.markup,/Recorded host progress/);
  assert.equal(diagram.edges.length,4);
  assert.ok(diagram.edges.every(edge=>edge.ids.size===1));
});

test('unapproved and unchecked hosts retain distinct paths',()=>{
  const scope={cidrs:['10.0.0.0/24'],domains:[],matchMode:'and'};
  const host=id=>({id,kind:'host',ip:`10.0.0.${id.slice(1)}`,evidenceIds:[]});
  const stats=build([host('h1'),host('h2')],[],{targets:[
    {host:host('h1'),eligible:true},
    {host:host('h2'),eligible:false,scopeReason:'Host identity needs DNS review and approval'}
  ]},[],scope,[]);
  assert.equal(stats.progress.length,2);
  assert.equal(stats.progress[0].stages[4],'Not investigated');
  assert.equal(stats.progress[1].stages[1],'Awaiting approval');
  assert.equal(stats.progress[1].stages[4],'Awaiting approval');
  const diagram=progressDiagram(stats.progress);
  assert.equal(diagram.edges.filter(edge=>edge.label.startsWith('Recorded in scope')).reduce((sum,edge)=>sum+edge.ids.size,0),2);
});
