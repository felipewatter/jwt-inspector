#!/usr/bin/env node
import fs from 'fs';
import { decodeJWT } from '../src/decoder';
import { validateJWT } from '../src/validator';

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('❌ Please provide a JWT token');
  process.exit(1);
}

const token = args[0];
const publicKeyArg = args.find(arg => arg.startsWith('--public-key='));
const publicKeyPath = publicKeyArg ? publicKeyArg.split('=')[1] : null;

const decoded = decodeJWT(token);
console.log('🔎 JWT Inspector\n---------------------------------------');

if (!decoded) {
  console.log('❌ Invalid token format');
  process.exit(1);
}

console.log(`✔️ Algorithm: ${decoded.header.alg}`);
console.log(`✔️ Issuer: ${decoded.payload.iss || 'Not set'}`);
console.log(`✔️ Subject: ${decoded.payload.sub || 'Not set'}`);
console.log(`✔️ Expiration: ${decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toISOString() : 'Not set'}`);

if (publicKeyPath && fs.existsSync(publicKeyPath)) {
  const key = fs.readFileSync(publicKeyPath, 'utf8');
  const valid = validateJWT(token, key, [decoded.header.alg]);
  console.log(`---------------------------------------\nSignature valid: ${valid ? '✅' : '❌'}`);
} else {
  console.log(`---------------------------------------\n⚠️ Skipping signature validation (no key provided)`);
}