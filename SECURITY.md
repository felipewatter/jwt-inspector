# Política de segurança

Para comunicação privada de vulnerabilidades, use as opções de GitHub Security Advisories do repositório, quando disponíveis. Nunca publique JWTs, chaves privadas ou segredos em issues.

## Semântica de confiança

**Decodificar um JWT não comprova autoria, integridade, validade, autorização ou identidade.** A função decodeJWT() e o modo CLI sem credenciais retornam apenas dados não confiáveis.

A verificação exige algoritmo fornecido pelo operador, que deve corresponder ao cabeçalho do token; não há escolha automática pelo token. Aceita HS256 com segredo de pelo menos 32 bytes e RS256 com chave RSA pública de pelo menos 2048 bits. Misturas de chave RSA/HMAC são rejeitadas. O cabeçalho não ativa downloads de JWK, x5u, jku ou processamento de extensões crit.

A verificação exige assinatura válida, exp numérico não expirado, nbf/iat coerentes e opcionalmente iss, aud e sub. **A CLI exige issuer e audience esperados** quando uma verificação é solicitada. A API programática deve sempre fornecer esses parâmetros em cenários de autenticação reais.

**Verificação não é autorização.** O consumidor é responsável por isolar o escopo do token, restringir recursos, verificar revogação/rotatividade de chaves e adequar claims ao contexto. Não implementa JWKS remoto, revogação, JWE, refresh tokens, algoritmos EdDSA/ES256, TLS ou identidade de usuário.

## Privacidade

Use --token-env, --token-file ou --stdin para evitar tokens na linha de comando. Evite --show-claims em logs de CI: pode revelar dados pessoais e segredos do payload. O token não é impresso por padrão. Não registre o conteúdo de variáveis de ambiente.

Saídas: 0 = validade criptográfica/política confirmada, 1 = token inválido, 2 = erro operacional, 3 = apenas decodificado (**UNVERIFIED**).

A biblioteca é voltada a inspeção e verificação offline. Ela não realiza conexões de rede.
