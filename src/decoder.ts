/**
 * Parse untrusted JWT data. Successful parsing MUST NOT be interpreted as verification.
 * No network, key discovery, token execution, or signature checking occurs here.
 */
export type Claims = Record<string, unknown>;
export type JWTHeader = Record<string, unknown>;
export type DecodedJWT = {header: JWTHeader; payload: Claims; signature: string};
export const MAX_TOKEN_LENGTH = 16384;
const maxSegment = 12288;
const utf8 = new TextDecoder('utf-8', {fatal: true});

export function decodeSegment(input: string): unknown {
  if (!input || input.length > maxSegment || !/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new Error('Invalid JWT segment');
  }
  const b = Buffer.from(input, 'base64url');
  if (b.toString('base64url') !== input) throw new Error('Non-canonical base64url');
  return JSON.parse(utf8.decode(b)) as unknown;
}
export function decodeJWT(token: string): DecodedJWT | null {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH || token.trim() !== token) return null;
  const segments = token.split('.');
  if (segments.length !== 3) return null;
  try {
    const header = decodeSegment(segments[0]!);
    const payload = decodeSegment(segments[1]!);
    const signature = segments[2]!;
    if (!header || Array.isArray(header) || typeof header !== 'object' ||
        !payload || Array.isArray(payload) || typeof payload !== 'object' ||
        !signature || signature.length > maxSegment || !/^[A-Za-z0-9_-]+$/.test(signature)) return null;
    const bytes = Buffer.from(signature, 'base64url');
    if (bytes.length === 0 || bytes.toString('base64url') !== signature) return null;
    return {header: header as JWTHeader, payload: payload as Claims, signature};
  } catch {return null;}
}
