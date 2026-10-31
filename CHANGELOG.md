# Changelog

## 1.1.0 — 2026-10-31

- Implementada verificação offline real de assinaturas HS256 e RS256 usando node:crypto.
- Algoritmo explicitamente fixado pelo operador, bloqueando confusão entre HMAC e RSA.
- Validação de exp, nbf, iat, issuer, audience e subject; chaves/segredos fracos rejeitados.
- Parser JWT limitado e estrito (base64url canônico, JSON bem formado e UTF-8 válido).
- CLI segura com --token-env, --token-file, --stdin, --algorithm, --issuer e --audience.
- Saídas textuais/JSON, redigidas por padrão; --show-claims exige opt-in.
- Códigos de saída distintos para verificado, inválido, erro e apenas decodificado.
- Testes unitários/regressão, documentação e CI Node.js 22/24 em Linux, Windows e macOS.
- Retirada dependência runtime jsonwebtoken; preservada API booleana validateJWT com algoritmo único obrigatório.

## 1.0.0 — 2025-07-07

- Primeira versão, com decodificação e verificação baseada em alg recebido do token.
