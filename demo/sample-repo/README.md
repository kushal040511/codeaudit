# codeaudit-demo

A small Flask shop API used to demo [CodeAudit](https://github.com/kushal040511/codeaudit).

**Intentionally insecure. Do not deploy or install its requirements.** Every
issue is deliberate: SQL and command injection, unsafe YAML, a hardcoded secret,
outdated dependencies with known CVEs, an import cycle between two services and a
model that imports the web layer.
