import jwt from 'jsonwebtoken';

export function validateJWT(token: string, key: string, algorithms: string[] = ['HS256', 'RS256']): boolean {
  try {
    jwt.verify(token, key, { algorithms });
    return true;
  } catch (err) {
    return false;
  }
}