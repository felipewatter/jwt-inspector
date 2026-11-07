const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHmac}=require('node:crypto');
const {verifyJWT}=require('../dist/src/validator.js');
const {decodeJWT}=require('../dist/src/decoder.js');
const secret='synthetic-unit-test-hmac-key-with-32-bytes-minimum';
const now=1800000000;
const b64=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
function token(header,payload) {
  const signingInput=b64(header)+'.'+b64(payload);
  return signingInput+'.'+createHmac('sha256',secret).update(signingInput).digest('base64url');
}
const opts={algorithm:'HS256',secret,nowSeconds:now,issuer:'https://trusted.test',audience:'api'};
const base={iss:'https://trusted.test',aud:'api',sub:'unit-test',exp:now+30};

test('expiry boundary is exclusive and tolerance only applies within configured window',()=>{
  assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT'},{...base,exp:now}),opts).code,'expired');
  assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT'},{...base,exp:now}),{...opts,clockToleranceSeconds:1}).valid,true);
  assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT'},{...base,exp:now-2}),
    {...opts,clockToleranceSeconds:1}).code,'expired');
});

test('signed remote key discovery and critical JWT headers are always denied',()=>{
  for(const field of [
    {jku:'https://untrusted.example/keys'}, {x5u:'https://untrusted.example/cert'},
    {crit:['custom']}, {b64:false}, {typ:'JOSE'}
  ]){
    assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT',...field},base),opts).code,'unsupported_header');
  }
});

test('validly signed wrong issuer and audience fail their respective policies',()=>{
  assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT'},{...base,iss:'https://wrong.test'}),opts).code,'issuer_mismatch');
  assert.equal(verifyJWT(token({alg:'HS256',typ:'JWT'},{...base,aud:['other']}),opts).code,'audience_mismatch');
});

test('truncated, extra-segment and random malformed token fragments never verify',()=>{
  const valid=token({alg:'HS256',typ:'JWT'},base);
  const candidates=['','..','%%%.'+'%%%.'+'%%%',' a.b.c',valid+'.extra',valid.slice(0,-7),
    'not-base64url.'+b64(base)+'.AA'];
  for(const candidate of candidates){
    assert.equal(verifyJWT(candidate,opts).valid,false,candidate);
  }
  assert.equal(decodeJWT(''),null);
});

test('algorithm claim cannot downgrade to none even if attacker signs the bytes',()=>{
  const malformed=token({alg:'none',typ:'JWT'},base);
  assert.equal(verifyJWT(malformed,opts).valid,false);
});
