# JWT Inspector

[![CI](https://github.com/felipewatter/jwt-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/jwt-inspector/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/felipewatter/jwt-inspector)](https://github.com/felipewatter/jwt-inspector/releases)
[![MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Ferramenta CLI e biblioteca TypeScript para **inspecionar e verificar JWTs offline** com algoritmos fixos, validação criptográfica real e checagem de claims.

> **ATENÇÃO:** decodificar um JWT **não valida sua assinatura**. Cabeçalho e payload podem ser forjados. O status UNVERIFIED não deve ser usado como autorização.

## Requisitos

Node.js 22 ou 24. Nenhuma dependência runtime de JWT é necessária; usa a criptografia nativa do Node.js. Suporte a HS256 e RS256. Uso offline, sem chamadas de rede, downloads de chaves ou acesso automático a JWKS.

## Instalação a partir do GitHub

    git clone https://github.com/felipewatter/jwt-inspector.git
    cd jwt-inspector
    npm install
    npm run build
    node dist/bin/index.js --help

Opcional, após compilar: npm install -g .

**O pacote não foi publicado no npm**; não presuma que npx jwt-inspector esteja disponível no registro.

## Inspecionar sem verificar

Informe um JWT por variável de ambiente, sem expor seu conteúdo ao histórico do shell:

    export JWT_INSPECTOR_TOKEN='seu-token'
    node dist/bin/index.js --token-env JWT_INSPECTOR_TOKEN --format json

Também pode usar --token-file ./token.txt ou --stdin. O token posicional legado é suportado, mas não recomendado.

**Importante:** o comando de inspeção retorna **exit 3** e status **UNVERIFIED**; nunca retorna exit 0 em modo sem verificação.

Por padrão o programa mostra somente algoritmo declarado, presença de claims e estado de verificação; para examinar valores (dados potencialmente sensíveis), adicione **--show-claims**. Não use esta opção em logs públicos.

## Verificar assinatura e claims (RS256)

    node dist/bin/index.js \
      --token-env JWT_INSPECTOR_TOKEN \
      --algorithm RS256 \
      --public-key ./public.pem \
      --issuer https://issuer.example.test \
      --audience my-api \
      --format json

A chave RSA pública precisa ter pelo menos 2048 bits.

## Verificar HMAC (HS256)

    export JWT_HMAC_SECRET='seu-segredo-com-pelo-menos-32-bytes-seguros'
    node dist/bin/index.js \
      --token-env JWT_INSPECTOR_TOKEN \
      --algorithm HS256 \
      --secret-env JWT_HMAC_SECRET \
      --issuer https://issuer.example.test \
      --audience my-api

O segredo HMAC deve ter pelo menos 32 bytes e ser protegido fora do repositório. Um segredo longo, mas previsível, continua inseguro.

No PowerShell use: $env:JWT_INSPECTOR_TOKEN='...' (o mesmo para JWT_HMAC_SECRET).

## Códigos de saída

| Exit | Interpretação |
|---|---|
| 0 | Assinatura e políticas de claims configuradas válidas |
| 1 | Token malformado/inválido, expiração ou falha de assinatura/claims |
| 2 | Erro de configuração, leitura ou parâmetros |
| 3 | Apenas decodificado: **UNVERIFIED**, não confiável |

## Opções

| Opção | Função |
|---|---|
| --token-env NAME | Token de variável de ambiente |
| --token-file FILE | Token armazenado em arquivo |
| --stdin | Ler token da entrada padrão |
| --algorithm HS256/RS256 | Algoritmo esperado; obrigatório para verificar |
| --public-key FILE | Chave pública RS256 |
| --secret-env NAME | Nome da variável do segredo HS256 |
| --issuer VALUE | Emissor esperado |
| --audience VALUE | Audiência esperada |
| --subject VALUE | Subject esperado opcional |
| --leeway 0..300 | Tolerância em segundos (padrão zero) |
| --format text/json | Formato da resposta |
| --show-claims | Exibe valores completos do cabeçalho e payload |
| --version / --help | Versão e ajuda |

## API TypeScript

    import {decodeJWT} from 'jwt-inspector/dist/src/decoder';
    import {verifyJWT} from 'jwt-inspector';

    const untrusted = decodeJWT(token); // Dados NÃO verificados
    const verified = verifyJWT(token, {
      algorithm: 'RS256',
      publicKey: publicPem,
      issuer: 'https://issuer.example.test',
      audience: 'my-api'
    });
    if (!verified.valid) throw new Error('JWT não validado');

O wrapper legado validateJWT(token,key,['RS256']) permanece disponível, mas exige uma lista com **um único algoritmo** e não é recomendado como mecanismo completo de autenticação por não exigir issuer e audience.

## Testes e segurança

    npm run typecheck
    npm test
    npm pack --dry-run

A pipeline GitHub Actions valida Node.js 22/24 em Ubuntu, Windows e macOS, incluindo ataques de confusão algorítmica, alteração de assinatura, claims expirados e saída que não revela tokens.

Leia [SECURITY.md](SECURITY.md). A ferramenta é para inspeção/validação, não é um servidor de autenticação nem um sistema de autorização.
