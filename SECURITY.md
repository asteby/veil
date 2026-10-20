# Security policy / Política de seguridad

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's *Security → Report a vulnerability* (private vulnerability reporting) on this repository. Include: affected version/commit, a description, reproduction steps or a proof of concept, and the impact you expect (e.g. "a value reaches a tool result", "the local page accepts a cross-origin POST").

- We acknowledge reports within **3 business days** and aim to ship a fix or mitigation within **30 days** for high-severity issues.
- We will credit you in the release notes unless you prefer otherwise.
- Please give us a reasonable window before public disclosure (coordinated disclosure, 90 days maximum).
- Good-faith research that respects users' data and avoids service disruption will not be pursued legally.

## Scope

In scope: anything that lets the model, the transcript, logs, argv or another local web origin obtain a value handled by this server; bypasses of the single-use token, CSRF, Origin/Host checks or CSP; approval bypasses; allowlist escapes (paths, hosts, tables, origins); weaknesses in the encrypted-file, sync bundle, share token and encrypted `.env` formats, and in the master-password store.

Out of scope (see [THREAT-MODEL.md](THREAT-MODEL.md) §6): actions the owner explicitly approved, same-OS-user malware, compromised browsers/extensions, and values the owner chose to deploy into plaintext files.

## Supported versions

Only the latest minor release receives security fixes while the project is 0.x.

---

## Reportar una vulnerabilidad

**No abras un issue público.** Usa *Security → Report a vulnerability* (reporte privado) de GitHub en este repositorio, con versión, descripción, pasos para reproducir e impacto. Respondemos en 3 días hábiles, buscamos corregir en 30 días los casos graves y te damos crédito si lo deseas. Pedimos divulgación coordinada (máximo 90 días).
