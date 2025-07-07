# 🛡️ JWT Inspector

![GitHub release](https://img.shields.io/github/v/release/felipewatter/jwt-inspector)?include_prereleases
![GitHub](https://img.shields.io/github/license/felipewatter/jwt-inspector)
![GitHub language count](https://img.shields.io/github/languages/count/felipewatter/jwt-inspector)

A CLI tool to inspect, decode, and validate JSON Web Tokens (JWT).

---

## ✅ Features

- Decode JWT header and payload
- Validate signature with secret or public key
- Check important claims (`exp`, `iss`, `aud`, `sub`)
- Warn about insecure configurations
- Clear and detailed CLI output

---

## 💻 Usage

```bash
npx jwt-inspector "<your-token>" --public-key=./keys/public.pem
```

---

## ⚙️ Supported algorithms

- HS256 (HMAC)
- RS256 (RSA)

---

## 💡 Best Practices

- Always check the expiration (`exp`) and issuer (`iss`)
- Avoid using `alg: none`
- Integrate checks in CI pipelines

---

## 🧑‍💻 Contributing

Pull requests and suggestions are welcome!

---

## 📄 License

MIT License