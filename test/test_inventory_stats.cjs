'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {build,flowDiagram}=require('../inventory-stats.js');

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
    {id:'o1',kind:'observation',hostId:'h1',title:'Nmap OS guess',detail:'Linux (95% accuracy)',evidenceIds:['e1']},
  ];
  const evidence=[{id:'e1',tool:'nmap',command:'nmap -n -Pn -sT -p 443 10.0.0.1',observedAt:'2026-10-20T00:00:00Z',output:'443/tcp open https'}];
  const map={targets:hosts.map((host,i)=>({host,eligible:i<2}))};
  const stats=build(findings,evidence,map,[{hostId:'h1',kind:'software'},{hostId:'h3',kind:'exposure'}],{domains:['example.test']});
  assert.equal(stats.hosts.length,2);
  assert.equal(stats.services.length,1);
  assert.equal(stats.flow[0].os,'Linux');
  assert.equal(stats.flow[0].type,'Web');
  assert.equal(stats.flow[0].domain,'dev.example.test');
  assert.equal(stats.portsScanned.size,1);
  assert.equal(stats.coverage[0].states[0],'recorded');
  assert.equal(stats.coverage[1].states[0],'recorded'); // closed is recorded, not open
  assert.equal(stats.leadRows.length,1);
  assert.equal(stats.productRows[0].label,'nginx 1.27');
});

test('unknown OS uses a readable service breakdown with clickable host filters',()=>{
  const rows=[{hostId:'h1',domain:'dev.example.test',os:'Unknown',type:'Web'},{hostId:'h2',domain:'dev.example.test',os:'Unknown',type:'SSH'},{hostId:'h1',domain:'dev.example.test',os:'Unknown',type:'Web'}];
  const diagram=flowDiagram(rows);
  assert.equal(diagram.hasOs,false);
  assert.match(diagram.markup,/Open services by domain and service type/);
  assert.doesNotMatch(diagram.markup,/<svg|flow-link/);
  assert.match(diagram.markup,/2 open services/);
  assert.deepEqual([...diagram.edges[0].ids],['h1']);
});

test('known OS preserves the flow diagram and its edge filters',()=>{
  const diagram=flowDiagram([{hostId:'h1',domain:'dev.example.test',os:'Linux',type:'Web'},{hostId:'h2',domain:'dev.example.test',os:'Unknown',type:'SSH'}]);
  assert.equal(diagram.hasOs,true);
  assert.match(diagram.markup,/<svg/);
  assert.equal(diagram.edges.length,4);
});
