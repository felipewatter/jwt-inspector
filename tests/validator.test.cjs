const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHmac,generateKeyPairSync,sign}=require('node:crypto');
const {decodeJWT}=require('../dist/src/decoder.js');
const {verifyJWT,validateJWT}=require('../dist/src/validator.js');
const secret='A_32_byte_secret_for_hmac_2026__SURE';
const keys=generateKeyPairSync('rsa',{modulusLength:2048});
const shortKeys=generateKeyPairSync('rsa',{modulusLength:1024});
const now=Math.floor(Date.now()/1000);
const base={iss:'https://issuer.example.test',aud:'expected-api',sub:'test-user',exp:now+600,nbf:now-10,iat:now-20};
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
const jwt=(alg='HS256',claims=base,header={alg,typ:'JWT'},key=alg==='HS256'?secret:keys.privateKey)=>{
  const data=b64(header)+'.'+b64(claims);
  const signature=alg==='HS256'?createHmac('sha256',key).update(data).digest():sign('RSA-SHA256',Buffer.from(data),key);
  return data+'.'+signature.toString('base64url');
};
const hs={algorithm:'HS256',secret,issuer:base.iss,audience:base.aud};
const rs={algorithm:'RS256',publicKey:keys.publicKey,issuer:base.iss,audience:base.aud};
test('HS256 correct signature + issuer/audience/exp verified',()=>{
  const r=verifyJWT(jwt(),hs);assert.equal(r.valid,true);assert.equal(r.code,'valid');
  assert.deepEqual(r.checks,['signature','exp','nbf','iat','iss','aud']);
});
test('RS256 correct RSA 2048 public key verified',()=>{
  const r=verifyJWT(jwt('RS256'),rs);assert.equal(r.valid,true);assert.equal(r.code,'valid');
});
test('decode returns untrusted claims but does not verify signature',()=>{
  const tampered=jwt().split('.');tampered[1]=b64({...base,sub:'forged'});
  const token=tampered.join('.');
  assert.equal(decodeJWT(token).payload.sub,'forged');
  assert.equal(verifyJWT(token,hs).code,'invalid_signature');
});
test('algorithm pinning defeats RS256-HS256 confusion',()=>{
  const rsaToken=jwt('RS256');const hmacToken=jwt();
  assert.equal(verifyJWT(rsaToken,hs).code,'algorithm_mismatch');
  assert.equal(verifyJWT(hmacToken,rs).code,'algorithm_mismatch');
  assert.equal(validateJWT(hmacToken,secret,['HS256','RS256']),false);
  assert.equal(validateJWT(rsaToken,keys.publicKey.export({type:'spki',format:'pem'}).toString()),false);
});
test('alg none and critical/remote headers rejected',()=>{
  const none=b64({alg:'none'})+'.'+b64(base)+'.';
  assert.equal(decodeJWT(none),null);
  for(const header of [{alg:'HS256',crit:['b64']},{alg:'HS256',jku:'https://attacker.example/jwks'},{alg:'HS256',b64:false},{alg:'HS256',typ:'unknown'}]){
    assert.equal(verifyJWT(jwt('HS256',base,header),hs).code,'unsupported_header');
  }
});
test('expired token and missing expiry fail closed',()=>{
  assert.equal(verifyJWT(jwt('HS256',{...base,exp:now-10}),hs).code,'expired');
  const x={...base};delete x.exp;
  assert.equal(verifyJWT(jwt('HS256',x),hs).code,'invalid_claims');
  assert.equal(verifyJWT(jwt('HS256',{...base,exp:'future'}),hs).code,'invalid_claims');
});
test('not-before and issued-at future rejected',()=>{
  assert.equal(verifyJWT(jwt('HS256',{...base,nbf:now+60}),hs).code,'not_yet_valid');
  assert.equal(verifyJWT(jwt('HS256',{...base,iat:now+60}),hs).code,'not_yet_valid');
  assert.equal(verifyJWT(jwt('HS256',{...base,iat:'tomorrow'}),hs).code,'invalid_claims');
});
test('issuer/audience and subject policy mismatches',()=>{
  for(const [options,code] of [[{...hs,issuer:'wrong'},'issuer_mismatch'],[{...hs,audience:'other'},'audience_mismatch'],[{...hs,subject:'somebody'},'subject_mismatch']]){
    assert.equal(verifyJWT(jwt(),options).code,code);
  }
});
test('audience arrays supported and checked',()=>{
  const token=jwt('HS256',{...base,aud:['service-a','expected-api']});
  assert.equal(verifyJWT(token,hs).valid,true);
  assert.equal(verifyJWT(token,{...hs,audience:'third-service'}).code,'audience_mismatch');
});
test('weak HMAC secret fails before acceptance',()=>{
  assert.equal(verifyJWT(jwt(),{...hs,secret:'tiny'}).code,'invalid_key');
  assert.equal(verifyJWT(jwt(),{...hs,publicKey:keys.publicKey}).code,'invalid_key');
});
test('RSA weak key and wrong key fail closed',()=>{
  assert.equal(verifyJWT(jwt('RS256',base,undefined,shortKeys.privateKey),{...rs,publicKey:shortKeys.publicKey}).code,'invalid_key');
  const another=generateKeyPairSync('rsa',{modulusLength:2048});
  assert.equal(verifyJWT(jwt('RS256'),{...rs,publicKey:another.publicKey}).code,'invalid_signature');
  assert.equal(verifyJWT(jwt('RS256'),{...rs,secret}).code,'invalid_key');
});
test('malformed, oversized, non-canonical and non-UTF8 segments rejected',()=>{
  for(const tok of ['abc.def','abc.def.ghi.more','a'.repeat(17000),b64({alg:'HS256'})+'.'+b64(base)+'.',' AAA.aaa.bbb',
     Buffer.from([0xff]).toString('base64url')+'.'+b64(base)+'.AQ']){
    assert.equal(decodeJWT(tok),null);
  }
});
test('legacy boolean API works only with one pinned algorithm',()=>{
  assert.equal(validateJWT(jwt(),secret,['HS256']),true);
  assert.equal(validateJWT(jwt(),secret),false);
  assert.equal(validateJWT(jwt(),secret,['HS256','RS256']),false);
  assert.equal(validateJWT(jwt('RS256'),keys.publicKey.export({type:'spki',format:'pem'}).toString(),['RS256']),true);
});
test('leeway tolerance capped at five minutes',()=>{
  const token=jwt('HS256',{...base,exp:now-5});
  assert.equal(verifyJWT(token,hs).code,'expired');
  assert.equal(verifyJWT(token,{...hs,clockToleranceSeconds:10}).valid,true);
  assert.equal(verifyJWT(token,{...hs,clockToleranceSeconds:301}).code,'invalid_claims');
});
