import jwt from 'jsonwebtoken';

export function decodeJWT(token: string) {
  const decoded = jwt.decode(token, { complete: true });
  return decoded;
}