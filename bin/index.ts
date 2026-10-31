#!/usr/bin/env node
/** JWT Inspector: parsing never implies signature or authorization validation. */
import {readFileSync,lstatSync} from 'node:fs';
import {decodeJWT, MAX_TOKEN_LENGTH, type DecodedJWT} from '../src/decoder';
import {verifyJWT, type Algorithm, type VerificationOptions, type VerificationResult} from '../src/validator';

export type CLIOptions = {
  tokenArg?: string; tokenFile?: string; stdin: boolean; tokenEnv?: string;
  algorithm?: Algorithm; publicKeyFile?: string; secretEnv?: string;
  issuer?: string; audience?: string; subject?: string;
  showClaims: boolean; format: 'text'|'json'; clockToleranceSeconds: number;
};
const HELP = `JWT Inspector v1.1.0 — never confuse decoding with verification.
Usage: jwt-inspector [token] [options]   (positional tokens are unsafe)
  --token-env NAME       Environment variable containing the token (recommended)
  --token-file FILE      Read compact JWT from a local regular file
  --stdin                Read compact JWT from standard input
  --algorithm HS256|RS256    Pin the expected algorithm (never trust JWT header)
  --public-key FILE      RS256: RSA public PEM key (at least 2048 bits)
  --secret-env NAME      HS256: environment variable containing >=32-byte secret
  --issuer VALUE         Required to claim policy-verified result
  --audience VALUE       Required to claim policy-verified result
  --subject VALUE        Optional expected subject
  --leeway SECONDS       Clock tolerance: 0..300 (default 0)
  --format text|json     Output format (default text)
  --show-claims          Explicitly show sensitive header/payload values
  --help                 Show help
  --version              Show CLI version

No key/algorithm: inspection-only result (UNVERIFIED, exit 3).
Verified exit codes: 0=signature+configured claims valid, 1=invalid,
2=usage/key/operational error, 3=decoded but UNVERIFIED.
Tokens/keys are never output by default or logged.
`;

function safeArg(s:string): string {return s.replace(/[\x00-\x1f\x7f-\x9f]/g,'?').slice(0,100);}
const validEnvName = (s: string): boolean => /^[A-Za-z_][A-Za-z0-9_]{0,100}$/.test(s);
export function parseArgs(args: readonly string[]): CLIOptions | 'help'|'version' {
  const value:CLIOptions={stdin:false,showClaims:false,format:'text',clockToleranceSeconds:0};
  for(let i=0;i<args.length;i++){
    const raw=args[i]!;
    const equal=raw.indexOf('=');
    const key=equal>=0?raw.slice(0,equal):raw;
    if(key==='--help'||key==='-h') return 'help';
    if(key==='--version'||key==='-v') return 'version';
    if(key==='--stdin'||key==='--show-claims'){
      if(equal!==-1)throw Error('Flag não recebe valor');
      if(key==='--stdin')value.stdin=true;else value.showClaims=true;
      continue;
    }
    if(!key.startsWith('--')){
      if(!value.tokenArg) {value.tokenArg=raw;continue;}
      throw Error('Apenas uma fonte de token é permitida');
    }
    if(!['--token-env','--token-file','--algorithm','--public-key','--secret-env','--issuer','--audience','--subject','--leeway','--format'].includes(key))
      throw Error('Opção não reconhecida: '+safeArg(key));
    const v=equal!==-1?raw.slice(equal+1):args[++i];
    if(!v || (equal===-1 && v.startsWith('--')))throw Error('Valor ausente para '+safeArg(key));
    switch(key){
      case '--token-env':value.tokenEnv=v;break;
      case '--token-file':value.tokenFile=v;break;
      case '--algorithm':if(v!=='HS256'&&v!=='RS256')throw Error('Algoritmo não permitido');value.algorithm=v;break;
      case '--public-key':value.publicKeyFile=v;break;
      case '--secret-env':value.secretEnv=v;break;
      case '--issuer':value.issuer=v;break;
      case '--audience':value.audience=v;break;
      case '--subject':value.subject=v;break;
      case '--format':if(v!=='json'&&v!=='text')throw Error('Formato inválido');value.format=v;break;
      case '--leeway':{
        if(!/^(0|[1-9][0-9]*)$/.test(v))throw Error('Leeway inválido');
        const n=Number(v);if(!Number.isSafeInteger(n)||n>300)throw Error('Leeway fora do intervalo');
        value.clockToleranceSeconds=n;break;
      }
    }
  }
  const sources=[value.tokenArg!==undefined,value.tokenEnv!==undefined,value.tokenFile!==undefined,value.stdin].filter(Boolean).length;
  if(sources!==1)throw Error('Informe exatamente uma fonte: token, --token-env, --token-file ou --stdin');
  if(value.tokenEnv!==undefined&&!validEnvName(value.tokenEnv))throw Error('Nome de variável de token inválido');
  if(value.secretEnv!==undefined&&!validEnvName(value.secretEnv))throw Error('Nome de variável de segredo inválido');
  if(value.publicKeyFile&&value.secretEnv)throw Error('Chave pública e segredo HMAC não podem coexistir');
  const verifying=!!(value.algorithm||value.publicKeyFile||value.secretEnv||value.issuer||value.audience||value.subject);
  if(verifying){
    if(!value.algorithm)throw Error('Defina --algorithm explicitamente');
    if(value.algorithm==='RS256' && (!value.publicKeyFile||value.secretEnv))throw Error('RS256 requer --public-key');
    if(value.algorithm==='HS256' && (!value.secretEnv||value.publicKeyFile))throw Error('HS256 requer --secret-env');
    if(!value.issuer||!value.audience)throw Error('Verificação completa exige --issuer e --audience');
  }
  return value;
}
function regularFile(path:string,maxBytes:number):string {
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.size>maxBytes)throw Error('Arquivo ausente, não regular ou excessivo');
  return readFileSync(path,'utf8');
}
function describe(decoded:DecodedJWT,result:VerificationResult|null,showClaims:boolean) {
  const p=decoded.payload;
  const safe={
    status:!result?'UNVERIFIED':result.valid?'VALID':'INVALID',
    reason:result?.code??'no_signature_verification',
    algorithm:typeof decoded.header.alg==='string'?decoded.header.alg:'missing',
    claimsPresent:{
      iss:Object.prototype.hasOwnProperty.call(p,'iss'),aud:Object.prototype.hasOwnProperty.call(p,'aud'),
      sub:Object.prototype.hasOwnProperty.call(p,'sub'),exp:Object.prototype.hasOwnProperty.call(p,'exp'),
      nbf:Object.prototype.hasOwnProperty.call(p,'nbf'),iat:Object.prototype.hasOwnProperty.call(p,'iat')
    },
    checks:result?.checks??[],message:result?.valid?'Signature and expected claims verified':result?'Verification failed':'Decoded only: signature NOT verified'
  };
  return showClaims?{...safe,header:decoded.header,payload:decoded.payload}:safe;
}
export async function main(args: readonly string[]=process.argv.slice(2),env:NodeJS.ProcessEnv=process.env):Promise<number>{
  let opt:ReturnType<typeof parseArgs>;
  try{opt=parseArgs(args);}catch{console.error('JWT Inspector: argumentos inválidos. Use --help.');return 2;}
  if(opt==='help'){console.log(HELP);return 0;}
  if(opt==='version'){console.log('1.1.0');return 0;}
  try{
    if(opt.tokenArg)console.error('AVISO: tokens na linha de comando são visíveis no histórico/processos; prefira --token-env.');
    let token=opt.tokenArg;
    if(opt.tokenEnv)token=env[opt.tokenEnv];
    if(opt.tokenFile)token=regularFile(opt.tokenFile,MAX_TOKEN_LENGTH);
    if(opt.stdin) {
      const input=readFileSync(0,'utf8');
      if(input.length>MAX_TOKEN_LENGTH+2)throw Error('Entrada muito longa');
      token=input;
    }
    token=token?.trim();
    if(!token||token.length>MAX_TOKEN_LENGTH)throw Error('Token ausente ou excessivo');
    const decoded=decodeJWT(token);
    if(!decoded){console.error('JWT Inspector: token malformado (não verificado).');return 1;}
    let result:VerificationResult|null=null;
    if(opt.algorithm){
      const options:VerificationOptions={algorithm:opt.algorithm,issuer:opt.issuer,audience:opt.audience,subject:opt.subject,clockToleranceSeconds:opt.clockToleranceSeconds};
      if(opt.algorithm==='RS256')options.publicKey=regularFile(opt.publicKeyFile!,65536);
      else options.secret=env[opt.secretEnv!];
      if(!options.publicKey&&!options.secret)throw Error('Credencial de verificação ausente');
      result=verifyJWT(token,options);
    }
    const output=describe(decoded,result,opt.showClaims);
    if(opt.format==='json')console.log(JSON.stringify(output,null,2));
    else{
      console.log('JWT Inspector v1.1.0');
      for(const [name,val] of Object.entries(output))console.log(name+': '+JSON.stringify(val));
    }
    return !result?3:result.valid?0:1;
  }catch{console.error('JWT Inspector: falha de configuração, arquivo ou leitura.');return 2;}
}
if(require.main===module)void main().then(code=>{process.exitCode=code;});
