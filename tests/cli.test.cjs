const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHmac}=require('node:crypto');
const {mkdtempSync,writeFileSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {join}=require('node:path');
const {spawnSync}=require('node:child_process');
const {parseArgs}=require('../dist/bin/index.js');
const cli=join(__dirname,'..','dist','bin','index.js');
const secret='another_strong_32_byte_hmac_key_here';
const claims={iss:'issuer',aud:'audience',sub:'topsecret-user',exp:Math.floor(Date.now()/1000)+200};
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
const token=(()=>{const data=b64({alg:'HS256',typ:'JWT'})+'.'+b64(claims);return data+'.'+createHmac('sha256',secret).update(data).digest('base64url')})();
const run=(args,vars={})=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',env:{...process.env,JWT_INSPECTOR_TOKEN:token,JWT_TEST_SECRET:secret,...vars},timeout:5000});
const verified=['--token-env','JWT_INSPECTOR_TOKEN','--algorithm','HS256','--secret-env','JWT_TEST_SECRET','--issuer','issuer','--audience','audience'];
test('parse options validates algorithm and claims expectations',()=>{
  const a=parseArgs(verified);assert.equal(a.algorithm,'HS256');assert.equal(a.issuer,'issuer');
  assert.throws(()=>parseArgs(['--token-env','A','--algorithm','none','--issuer','issuer','--audience','audience']));
  assert.throws(()=>parseArgs(['--token-env','A','--algorithm','HS256','--secret-env','KEY']));
});
test('CLI verifies from environment without revealing token or claims',()=>{
  const r=run([...verified,'--format','json']);assert.equal(r.status,0,r.stderr);
  const doc=JSON.parse(r.stdout);assert.equal(doc.status,'VALID');assert.equal(doc.algorithm,'HS256');
  assert.ok(!r.stdout.includes(token));assert.ok(!r.stdout.includes('topsecret-user'));assert.equal(doc.claimsPresent.exp,true);
});
test('invalid expected audience causes exit 1',()=>{
  const args=verified.map((a,i)=>i===verified.indexOf('audience')?'wrong':a);
  const r=run(args);assert.equal(r.status,1);assert.match(r.stdout,/INVALID/);
});
test('unverified decode is clear, exits 3 and redacts by default',()=>{
  const r=run(['--token-env','JWT_INSPECTOR_TOKEN','--format','json']);assert.equal(r.status,3);
  assert.equal(JSON.parse(r.stdout).status,'UNVERIFIED');assert.ok(!r.stdout.includes('topsecret-user'));
});
test('explicit --show-claims reveals payload only on request',()=>{
  const r=run(['--token-env','JWT_INSPECTOR_TOKEN','--show-claims','--format','json']);assert.equal(r.status,3);
  assert.equal(JSON.parse(r.stdout).payload.sub,'topsecret-user');
});
test('legacy positional token warns without echoing token',()=>{
  const r=run([token]);assert.equal(r.status,3);assert.match(r.stderr,/AVISO/);assert.ok(!r.stdout.includes(token));
});
test('missing token, file or secret returns operational exit 2',()=>{
  let r=run(['--token-env','MISSING_TOKEN'],{MISSING_TOKEN:''});assert.equal(r.status,2);
  r=run(['--token-file','/nonexistent/secure/token']);assert.equal(r.status,2);
  r=run(verified,{JWT_TEST_SECRET:''});assert.equal(r.status,2);
});
test('safe --token-file and --stdin input',()=>{
  const dir=mkdtempSync(join(tmpdir(),'jwt-inspector-'));
  try{
    const f=join(dir,'token.txt');writeFileSync(f,token+'\n');
    assert.equal(run(['--token-file',f]).status,3);
    const r=spawnSync(process.execPath,[cli,'--stdin'],{encoding:'utf8',input:token+'\n',timeout:5000});
    assert.equal(r.status,3);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
test('--help and --version are safe without token',()=>{
  assert.equal(run(['--help']).status,0);
  assert.match(run(['--version']).stdout,/1.1.0/);
});
