/** JWT signature verification with pinned algorithm; HS/RS key confusion is prohibited. */
import {createHmac, createPublicKey, timingSafeEqual, verify as verifySignature, type KeyObject} from 'node:crypto';
import {decodeJWT, type DecodedJWT, type Claims} from './decoder';

export type Algorithm = 'HS256' | 'RS256';
export type VerificationOptions = {
  algorithm: Algorithm;
  secret?: string | Buffer;
  publicKey?: string | Buffer | KeyObject;
  issuer?: string;
  audience?: string;
  subject?: string;
  nowSeconds?: number;
  clockToleranceSeconds?: number;
};
export type VerificationResult = {
  valid: boolean;
  code: 'valid' | 'malformed' | 'algorithm_mismatch' | 'unsupported_header' |
    'invalid_key' | 'invalid_signature' | 'invalid_claims' | 'expired' | 'not_yet_valid' |
    'issuer_mismatch' | 'audience_mismatch' | 'subject_mismatch';
  decoded: DecodedJWT | null;
  checks: string[];
};
const invalid = (code: Exclude<VerificationResult['code'],'valid'>, decoded: DecodedJWT | null, checks: string[] = []): VerificationResult =>
  ({valid:false,code,decoded,checks});
const own = (obj: Claims, key: string): boolean => Object.prototype.hasOwnProperty.call(obj,key);

export function verifyJWT(token: string, options: VerificationOptions): VerificationResult {
  const decoded = decodeJWT(token);
  if (!decoded) return invalid('malformed',null);
  const {header,payload} = decoded;
  if (options.algorithm !== 'HS256' && options.algorithm !== 'RS256')
    return invalid('algorithm_mismatch',decoded);
  if (header.alg !== options.algorithm) return invalid('algorithm_mismatch',decoded);
  if ((own(header,'typ') && header.typ !== 'JWT') || own(header,'crit') ||
      own(header,'b64') || own(header,'jku') || own(header,'x5u'))
    return invalid('unsupported_header',decoded);
  const parts = token.split('.');
  const data = Buffer.from(parts[0]+'.'+parts[1], 'ascii');
  const signature = Buffer.from(decoded.signature,'base64url');
  const checks: string[] = [];
  let signatureValid: boolean;
  try {
    if (options.algorithm === 'HS256') {
      if (options.publicKey !== undefined || options.secret === undefined) return invalid('invalid_key',decoded);
      const key = Buffer.isBuffer(options.secret) ? options.secret : Buffer.from(options.secret,'utf8');
      if (key.length < 32) return invalid('invalid_key',decoded);
      const expected = createHmac('sha256', key).update(data).digest();
      signatureValid = expected.length === signature.length && timingSafeEqual(expected,signature);
    } else {
      if (options.secret !== undefined || options.publicKey === undefined) return invalid('invalid_key',decoded);
      const key = options.publicKey instanceof KeyObject ? options.publicKey : createPublicKey(options.publicKey);
      if (key.type !== 'public' || key.asymmetricKeyType !== 'rsa' ||
          (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return invalid('invalid_key',decoded);
      signatureValid = verifySignature('RSA-SHA256',data,key,signature);
    }
  } catch {return invalid('invalid_key',decoded);}
  if (!signatureValid) return invalid('invalid_signature',decoded);
  checks.push('signature');
  const now = options.nowSeconds ?? Math.floor(Date.now()/1000);
  const tolerance = options.clockToleranceSeconds ?? 0;
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(tolerance) || tolerance < 0 || tolerance > 300)
    return invalid('invalid_claims',decoded,checks);
  if (!own(payload,'exp') || typeof payload.exp !== 'number' || !Number.isSafeInteger(payload.exp))
    return invalid('invalid_claims',decoded,checks);
  if (payload.exp <= now - tolerance) return invalid('expired',decoded,checks);
  checks.push('exp');
  if (own(payload,'nbf')) {
    if (typeof payload.nbf !== 'number' || !Number.isSafeInteger(payload.nbf))
      return invalid('invalid_claims',decoded,checks);
    if (payload.nbf > now + tolerance) return invalid('not_yet_valid',decoded,checks);
    checks.push('nbf');
  }
  if (own(payload,'iat')) {
    if (typeof payload.iat !== 'number' || !Number.isSafeInteger(payload.iat))
      return invalid('invalid_claims',decoded,checks);
    if (payload.iat > now + tolerance) return invalid('not_yet_valid',decoded,checks);
    checks.push('iat');
  }
  if (options.issuer !== undefined) {
    if (payload.iss !== options.issuer) return invalid('issuer_mismatch',decoded,checks);
    checks.push('iss');
  }
  if (options.audience !== undefined) {
    const aud = payload.aud;
    if (!(aud===options.audience ||
         (Array.isArray(aud) && aud.every(x=>typeof x==='string') && aud.includes(options.audience))))
      return invalid('audience_mismatch',decoded,checks);
    checks.push('aud');
  }
  if (options.subject !== undefined) {
    if (payload.sub !== options.subject) return invalid('subject_mismatch',decoded,checks);
    checks.push('sub');
  }
  return {valid:true,code:'valid',decoded,checks};
}
/**
 * Backward compatible boolean API. Exactly ONE algorithm must be provided.
 * For HS256, use a >=32 byte secret; for RS256, a >=2048-bit RSA public key.
 * Signature and expiry are checked, but issuer/audience must be handled by callers.
 */
export function validateJWT(token: string, key: string, algorithms: readonly string[] = []): boolean {
  if (algorithms.length !== 1 || !['HS256','RS256'].includes(algorithms[0]!)) return false;
  const algorithm = algorithms[0] as Algorithm;
  return verifyJWT(token,algorithm==='HS256'?{algorithm,secret:key}:{algorithm,publicKey:key}).valid;
}
