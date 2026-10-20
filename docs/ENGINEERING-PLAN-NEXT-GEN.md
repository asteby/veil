# Plan de ingeniería de siguiente generación — Veil

> **Estado (2026-10-20, rama `integracion/veil`):** el renombrado de §2.2 ya se aplicó con compatibilidad (paquete `@asteby/veil`, comando `veil`, `VEIL_*`, `~/.config/veil`; se conservan las constantes de formato y se leen los nombres anteriores; ver CHANGELOG 0.2.0) y los prefijos de `.env` de la spec §10.2 están implementados. El resto del plan sigue siendo diseño, sin implementar.

> **Estado:** borrador de diseño para revisión del dueño. Solo diseño: salvo lo indicado arriba, nada de esto está implementado.
> **Base:** `main` @ `6aa8c88` (veilform 0.1.0, sin publicar en npm). Rama: `docs/engineering-plan`.
> **Fecha:** 2026-10-19.
> **Nombre:** "Veil" es una **propuesta**; el dueño no lo ha confirmado. Donde el renombrado tiene impacto se marca con **[RENOMBRE]**. Donde un dato de un proyecto externo no está verificado se marca con **(verificar)**.
> **Documento hermano:** [`FORMAT-VEIL-SPEC.md`](FORMAT-VEIL-SPEC.md) (borrador de la especificación del formato `.veil`).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Estado actual y hallazgos del código](#1-estado-actual-y-hallazgos-del-código)
2. [Nombre y renombrado: impacto](#2-nombre-y-renombrado-impacto)
3. [Investigación previa: qué copiar y qué hacer distinto](#3-investigación-previa)
4. [Arquitectura objetivo](#4-arquitectura-objetivo)
5. [Pilar 1 — Cifrado automático al subir](#5-pilar-1--cifrado-automático-al-subir)
6. [Pilar 2 — Detección de lectura, canarios y respuesta](#6-pilar-2--detección-de-lectura-canarios-y-respuesta)
7. [Pilar 3 — Formato `.veil`](#7-pilar-3--formato-veil)
8. [Pilar 4 — Custodia de llaves](#8-pilar-4--custodia-de-llaves)
9. [Pilar 5 — Plataforma, equipo, OPS y CI](#9-pilar-5--plataforma-equipo-ops-y-ci)
10. [Pilar 6 — Cadena de suministro y calidad](#10-pilar-6--cadena-de-suministro-y-calidad)
11. [Modelo de amenazas ampliado (honesto)](#11-modelo-de-amenazas-ampliado)
12. [Métricas y cómo medirlas](#12-métricas-y-cómo-medirlas)
13. [Roadmap por fases, ramas y dueños de archivos](#13-roadmap-por-fases)
14. [Riesgos](#14-riesgos)
15. [Decisiones SOLO del dueño](#15-decisiones-solo-del-dueño)
16. [Datos por verificar](#16-datos-por-verificar)
17. [Apéndices](#17-apéndices)

---

## 0. Resumen ejecutivo

**Qué es Veil hoy.** Un servidor MCP (TypeScript, stdio) que permite a un agente de IA pedir, guardar y usar credenciales sin ver sus valores: formularios ciegos en `127.0.0.1`, captura web ciega, llaves SSH ciegas, escritura a `.env`/JSON/YAML/systemd/GitHub/SQL/API, aprobaciones por huella exacta, redactor de variantes y auditoría encadenada. En paralelo, otra rama (`feat/vault-sync-share`) diseña bóveda, sincronía, compartir por token y `.env` cifrado por valor.

**Qué propone este plan.** Pasar de "un MCP que no le muestra secretos al modelo" a **una capa de seguridad de secretos para humanos y agentes** con cuatro capacidades nuevas:

1. **Que nada sensible salga en claro**: un escáner de alta precisión (patrones de proveedores con checksum + entropía + contexto + **huellas de valores que la bóveda ya conoce**) conectado a todos los puntos de salida —hooks de git, filtro clean, GitHub Action, contexto de Docker, `s3/rsync/scp`, portapapeles, transcripts del agente— que **bloquea por defecto** y **cifra automáticamente** solo donde una política del proyecto (`.veil/policy.toml`) lo declara.
2. **Saber quién intenta leer**: un **broker local** (`veild`) que es la única puerta a los valores y que atribuye cada petición a un proceso (pid, binario, árbol, si desciende de Claude Code) **sin root**, gracias a credenciales del par en el socket; **canarios** locales y remotos de alta señal; hooks de Claude Code que niegan lecturas; barrido de transcripts; alertas; playbooks de rotación; log Merkle con anclaje opcional.
3. **Un formato propio `.veil`** versionado, con cabecera TLV canónica, AEAD en streaming, múltiples destinatarios (X25519, passphrase, P-256 de hardware, FIDO2-PRF, KMS, grupos umbral), metadatos cifrados, firma opcional verificable **sin descifrar**, vectores de prueba y fuzzing; con importación/exportación a age/sops/dotenvx.
4. **Custodia de llaves moderna**: llaves atadas al dispositivo (Secure Enclave, TPM, YubiKey/FIDO2), llaves de servidor en KMS para CI sin humanos, recuperación por Shamir M-de-N, aprobaciones de compartición M-de-N **forzadas criptográficamente**, y un camino post-cuántico híbrido (X25519 + ML-KEM-768) **solo como experimento** con criterio de adopción.

### Hallazgos clave

1. **El momento de renombrar es ahora**: `veilform` no está en npm; `@asteby/veil` está libre y `asteby/veil` no existe en GitHub (comprobado 2026-10-19). El nombre sin scope `veil` en npm **ya está tomado** por un paquete ajeno; hay además un proyecto de seguridad ofensiva conocido como "Veil Framework" (evasión de antivirus) **(verificar marca y SEO)**. Dos constantes de formato llevan el nombre y **no deben cambiar**: `CHECK = 'veilform:v1'` del archivo cifrado y el servicio de llavero por defecto `veilform` (§2).
2. **El log de auditoría actual detecta ediciones parciales, no reescrituras**: la cadena SHA-256 no tiene llave; un proceso del mismo usuario puede reescribir todo el archivo y recalcular la cadena. Hace falta firma de checkpoints + anclaje externo (§6.9).
3. **`encrypted-file` v1 no detecta rollback ni borrado de entradas** y deja los **nombres** de los secretos en claro; no tiene id de llave, ni múltiples destinatarios. Es el punto de partida del formato `.veil` y necesita migración (§7, spec §12).
4. **OPS sigue guardando credenciales de addons en claro**: `AddonService.GetSettings` devuelve `installation.Settings` tal cual (`backend/services/addon_service.go`, OPS @ `e1d69037`); `AddonSettingDef.Type` solo admite `text/number/boolean/select` (no hay tipo `secret`). Además `backend/utils/crypto.go` usa una **llave por defecto fija** si falta `ENCRYPTION_KEY` y rellena/trunca la llave en vez de derivarla (§9.5).
5. **Sin privilegios no se puede saber con fiabilidad quién lee un archivo en claro** (inotify no da pid; FSEvents no reporta lecturas). La respuesta de diseño es **no dejar archivos en claro** y canalizar todo por un broker que sí ve al proceso que pide (SO_PEERCRED / getpeereid / GetNamedPipeClientProcessId). La telemetría de archivos con privilegios (fanotify, eBPF, Endpoint Security, ETW) queda como módulo opcional (§6.2).
6. **Un agente con shell libre bajo el mismo usuario sigue pudiendo ganar** (reemplazar el binario, leer memoria si no hay endurecimiento, registrar teclas del navegador). Veil sube el costo y detecta; la frontera real es otro usuario del SO, contenedor o sandbox del kernel (Landlock/bubblewrap/Seatbelt). El plan entrega un perfil `veil agent run` para eso (§11).
7. **El valor inmediato está en el escáner + hooks de agente**, no en el formato: el `redact.ts` actual ya genera variantes (base64 a cualquier desplazamiento, hex, URL, JSON…) y es la base de las **huellas de valores conocidos**, el detector de mayor precisión posible porque compara contra secretos reales del usuario.
8. **La rama hermana ya fija formatos concretos** (trabajo sin commitear en `/home/user/projects/veilform-vault` al 2026-10-19): `.env` cifrado por valor `#/veilform-env v1` con prefijo `enc:v1:`, bundle de sincronía con índice cifrado y contador anti-rollback, compartir por token `vfs1://…#<llave en el fragmento>`, destinos `dir/ssh/git/s3/webdav/http`, un **agente de sesión** tras un socket unix `0600` y un hook pre-commit para `.env`. Este plan **adopta** esos formatos (la forma por valor de Veil *es* `veilform-env v1`) y propone solo extensiones: destinatarios asimétricos, prefijos con el nombre nuevo, y convertir el agente de sesión en el broker `veild` (§1.3).
9. **Recomiendo mover el núcleo a Go** (formato, escáner, daemon, hooks, CLI) en un binario estático, y dejar el MCP en TypeScript como cliente del daemon. Motivos: latencia de hooks, binario único para Windows/macOS/Linux/CI, y el ecosistema de referencia (age, sops, gitleaks, trufflehog, sigstore) está en Go. Es una decisión del dueño (§15).

### Las 10 decisiones más importantes (con recomendación)

| # | Decisión | Recomendación |
|---|---|---|
| D1 | Nombre y momento del renombrado | Adoptar **Veil / `@asteby/veil` / CLI `veil` / `asteby/veil`** antes de la primera publicación en npm; conservar alias y constantes de compatibilidad `veilform` (§2). |
| D2 | Lenguaje del núcleo | **Go** para núcleo + CLI + daemon + hooks + Action; **TS** para MCP, librería cliente y extensión de VS Code. Una sola implementación criptográfica (Go); TS solo **parsea y verifica** cabeceras (§4). |
| D3 | ¿Formato propio o age tal cual? | **Contenedor propio `.veil`** con primitivas y construcción derivadas de age (X25519/HKDF/ChaCha20-Poly1305/STREAM) y **compatibilidad con el protocolo de plugins de age** para hardware; exportación sin pérdidas a age cuando los destinatarios lo permiten. Alternativa de menor riesgo documentada (§7.1). |
| D4 | ¿Texto plano en el árbol de trabajo? | **No por defecto**: en el árbol vive el cifrado; los valores se consumen con `veil run`/broker. El smudge que descifra a disco es opt-in por ruta (§5.3). |
| D5 | Acción por defecto al detectar | **Bloquear y explicar** en todo lo no declarado; **auto-cifrar** solo rutas y formatos declarados en `.veil/policy.toml` (§5.6). |
| D6 | Huellas de valores conocidos | **HMAC con llave local** (nunca hashes sin llave), truncadas y en filtro Bloom; CI recibe un conjunto separado con su propia llave (§5.2). |
| D7 | Arquitectura de detección de acceso | **Broker con atribución sin root** como primaria; canarios como señal de alta confianza; telemetría de kernel privilegiada como opcional (§6). |
| D8 | Contención del agente | Hooks y `permissions.deny` son **topes de velocidad**; la frontera es un **sandbox o usuario aparte**, que Veil configura (`veil agent run`) (§6.5, §11). |
| D9 | Custodia por defecto | Llave de dispositivo (SE/TPM/llavero) + recuperación **Shamir 2-de-3**; passphrase con **Argon2id** solo como respaldo; PQ híbrido experimental tras bandera (§8). |
| D10 | Auditoría | **Log Merkle con checkpoints firmados** por la llave del dispositivo; anclaje opcional (servidor de equipo, Rekor u OpenTimestamps); el servidor de equipo solo ve cifrado y hashes (§6.9). |

### Orden recomendado de construcción

1. **F0** — Decisiones del dueño, renombrado, monorepo, CI de cadena de suministro básica, spec del formato congelada como borrador `v1-draft`.
2. **F1** — Escáner + huellas + política + hooks de git + **guardia de Claude Code** + barrido de transcripts (valor inmediato, no depende del formato nuevo).
3. **F2** — Formato `.veil` v1 en Go + vectores + `veil verify` + migración de `encrypted-file` v1 + import/export age.
4. **F3** — Auto-cifrado: filtro git, `.env` por valor (alineado con `feat/vault-sync-share`), `veil run`, GitHub Action.
5. **F4** — Daemon broker con atribución, canarios locales y remotos, alertas, log Merkle firmado.
6. **F5** — Custodia: hardware (plugins age), KMS, Shamir, rotación/revocación.
7. **F6** — Equipo multiusuario, aprobaciones M-de-N, auditoría centralizada ciega, integración OPS, CI sin humanos.
8. **F7** — Telemetría privilegiada, playbooks de rotación automática, proxy de salida del agente, PQ experimental.
9. **1.0** — Auditoría externa, formato congelado, política de soporte.

---

## 1. Estado actual y hallazgos del código

### 1.1 Lo que existe (main @ 6aa8c88)

| Área | Archivo(s) | Notas relevantes para el plan |
|---|---|---|
| Servidor MCP, 13 herramientas | `src/server.ts`, `src/app.ts` | `SECURITY_NOTE` instruye al modelo; nombre MCP `veilform` **[RENOMBRE]**. |
| Páginas locales | `src/ui/*` | Token de un uso, CSRF (`X-SI-CSRF`), CSP con nonce. Reutilizables para aprobaciones de Veil (compartir, M-de-N, alertas). |
| Bóveda (índice + caché) | `src/vault.ts` | Índice de metadatos en claro (nombres, tags, proyecto). Caché en memoria con TTL. |
| Almacenes | `src/stores/*` | Llavero vía `secret-tool`/`security`; `encrypted-file` AES-256-GCM + scrypt; `env-file`; `ssh-file`; `http-api` (Vault, Infisical, 1Password Connect, OPS). Sin backend de llavero en Windows. |
| Redactor | `src/redact.ts` | `variantsOf()` genera variantes; base del motor de huellas (§5.2). |
| Auditoría | `src/audit.ts` | JSONL con `prev = sha256(línea anterior)`; `verify-audit`. |
| Aprobaciones | `approvals.json` | Editables por el mismo usuario (ya documentado). |
| CI | `.github/workflows/ci.yml` | Acciones por tag (`@v4`), no por SHA. Sin firma de releases, sin SBOM. |
| Dependencias de ejecución | `package.json` | Solo `@modelcontextprotocol/sdk` y `zod`; `playwright-core` opcional. Buen punto de partida. |

### 1.2 Hallazgos (para corregir o tener en cuenta)

| ID | Hallazgo | Severidad | Acción propuesta |
|---|---|---|---|
| H-01 | `audit.ts`: cadena sin llave → reescritura completa indetectable por un proceso del mismo usuario. | Media | Checkpoints firmados + anclaje (§6.9). Documentar en THREAT-MODEL. |
| H-02 | `encrypted-file` v1: sin protección de rollback ni de borrado de entradas (cada entrada tiene su AEAD, pero no hay MAC global ni contador). | Media | `.veil` v1 con MAC de cabecera y metadatos cifrados; contador monotónico opcional anclado en el llavero (spec §9). |
| H-03 | `encrypted-file` v1: nombres de secretos en claro (`entries` es un objeto con nombres como claves). | Baja/Media (fuga de metadatos) | Metadatos cifrados en `.veil`. |
| H-04 | `encrypted-file` v1: sin id de llave ni múltiples destinatarios; parámetros de scrypt no autenticados (un cambio solo produce "llave incorrecta", no "archivo manipulado"). | Baja | Cabecera autenticada en `.veil`. |
| H-05 | `approvals.json` editable → un proceso del mismo usuario puede pre-aprobar acciones. | Media | MAC con llave del llavero sobre el archivo de aprobaciones; mover al daemon. |
| H-06 | Node ≥ 20.11: no hay Argon2 nativo (la rama hermana lo detecta en tiempo de ejecución y documenta `node:crypto` ≥ 24.7, con scrypt como alternativa) ni ML-KEM (dependería de OpenSSL 3.5 **(verificar)**). | Info | Motivo adicional para el núcleo en Go (`x/crypto/argon2`, `crypto/mlkem` en Go ≥ 1.24). |
| H-07 | El redactor no cubre base32, gzip, ROT13, salida carácter a carácter (ya documentado). | Info | El escáner reutiliza variantes; el detector de exfiltración por transformación es heurístico y se declara así. |
| H-08 | CI usa acciones por tag móvil. | Baja | Fijar por SHA + Dependabot/Renovate (§10). |
| H-09 | OPS: credenciales de addons en claro, `GET` sin enmascarar, llave por defecto fija en `utils/crypto.go`. | **Alta** (fuera de este repo) | Propuesta concreta en §9.5; PR en OPS por separado. |
| H-10 | Prefijos heredados `si_`/`X-SI-CSRF` de "secret-intake". | Cosmético | Renombrar en el mismo PR de renombrado, sin impacto de formato. |

### 1.3 Relación con las ramas hermanas

- **`docs/readme-visuals`** (en `/home/user/projects/secret-intake-mcp`): toca `README*.md`, `docs/assets/shots/**`, `scripts/readme-assets/**`. Este plan **no toca** esos archivos.
- **`feat/vault-sync-share`** (worktree `/home/user/projects/veilform-vault`): sin commits propios todavía, pero con trabajo en curso sin commitear (leído el 2026-10-19; puede cambiar): `src/crypto/{primitives,keysource,attempts}.ts`, `src/envenc/{format,service}.ts`, `src/sync/{bundle,service,targets}.ts`, `src/share/share.ts` y cambios en `src/config.ts`/`src/vault.ts`. Es dueña de: bóveda, sincronía a destinos opacos, compartir por token, `.env` cifrado por valor y desbloqueo por passphrase/llave/token/llave de servidor.
  - **Lo que ya decidió** (y este plan respeta): AES-256-GCM con nonce aleatorio, Argon2id (Node ≥ 24.7) o scrypt con **límites mínimos y máximos** de parámetros, HKDF para sub-llaves, HMAC para integridad de estructuras; `.env` por valor con AAD = contexto (nombre del archivo) + nombre de variable, MAC de documento y re-cifrado estable; bundle con DEK por secreto, índice cifrado, ids de objeto aleatorios y `seq` anti-rollback; compartir con la llave en el **fragmento** de la URL, caducidad y máximo de vistas autenticados; llaves desde archivo, llavero, credenciales de systemd o un **agente de sesión** (socket unix `0600`); contador persistente de intentos fallidos; `veilform env hook install` para pre-commit.
  - **Cómo encaja aquí:** (1) la forma por valor de Veil **es** `veilform-env v1`; la spec solo propone v1.1 con destinatarios asimétricos (X25519/P-256/KMS/plugins/umbral) y prefijos renombrados (spec §10). (2) El contenedor binario `.veil` es para **archivos completos** (llaves SSH, volcados, bóveda local, checkpoints) y no reemplaza al bundle ni al formato de compartir en 1.0. (3) El **agente de sesión** es la semilla del broker `veild` (§4): se le añade atribución por credenciales del par, política y log, sin duplicarlo. (4) El hook de `.env` es la semilla de los hooks de git de F1: se generaliza al escáner, no se escribe otro.
  - Diferencia de fondo a resolver con esa rama: sus destinatarios son **simétricos** (quien puede cifrar puede descifrar). Para equipos y CI hacen falta destinatarios de llave pública; la extensión es compatible (spec §10.2).
  - Recomendación al dueño: que la rama hermana lea `docs/FORMAT-VEIL-SPEC.md` §10 y §12 antes de commitear, y que el renombrado de prefijos (`enc:v1:` → `veil:1:`) se haga **antes** de publicar cualquier archivo.

---

## 2. Nombre y renombrado: impacto

Propuesta: producto **Veil**, paquete **`@asteby/veil`**, repo **`asteby/veil`**, CLI **`veil`**, extensión **`.veil`**, directorio de proyecto **`.veil/`**.

### 2.1 Disponibilidad (comprobada el 2026-10-19)

| Recurso | Estado |
|---|---|
| npm `veil` (sin scope) | **Tomado** (paquete ajeno, "Convert RFC822 and HTTP messages…", v0.1.0). No usable. |
| npm `@asteby/veil` | Libre (404). |
| npm `veilform` | Libre: **nunca se publicó**, así que renombrar no rompe a usuarios de npm. |
| GitHub `asteby/veil` | No existe (o no es visible). |
| GitHub `asteby/veilform` | Existe, público. GitHub redirige tras renombrar el repo (comportamiento conocido de GitHub; las redirecciones se pierden si luego se crea otro repo con el nombre viejo). |
| Comando `veil` en PATH | Riesgo de choque con otros binarios llamados `veil` en Homebrew/distros **(verificar)**. |
| Marca / búsqueda | Existe "Veil Framework" (herramienta ofensiva de evasión de antivirus) **(verificar estado actual)**: riesgo de confusión en búsquedas y en listas de bloqueo de antivirus/EDR que buscan la cadena "veil". |
| Extensión `.veil` | No conozco un uso registrado previo **(verificar en registros de extensiones, Linguist, shared-mime-info)**. |

### 2.2 Impacto del renombrado en el código **[RENOMBRE]**

| Elemento | Dónde | Tratamiento |
|---|---|---|
| `name`, `bin` | `package.json` | `@asteby/veil`, bin `veil`; mantener bin `veilform` como alias deprecado una versión menor. |
| Constante de formato `CHECK = 'veilform:v1'` | `src/stores/encrypted-file.ts:34` | **No cambiar.** Es parte del formato v1 en disco; cambiarla rompe archivos existentes. `.veil` usa sus propias etiquetas. |
| Servicio del llavero por defecto `veilform` | `src/config.ts:17,25,28,132`, `src/stores/keychain.ts` | **No cambiar el valor por defecto en silencio**: los secretos existentes viven bajo ese servicio. Nuevo valor por defecto `veil` solo para instalaciones nuevas; si existe el servicio `veilform`, seguir leyéndolo y ofrecer `veil migrate keychain`. |
| Variables `VEILFORM_HOME/CONFIG/AGENT/QUIET` | `src/config.ts`, `src/util.ts` | Leer `VEIL_*`; si faltan, leer `VEILFORM_*` con aviso. |
| Directorio `~/.config/veilform` | `src/config.ts:187` | Si existe y no existe `~/.config/veil`, usarlo y ofrecer migración (mover + enlace). |
| Rutas en servidores remotos `/etc/veilform/<unit>.env`, `50-veilform.conf` | `src/targets.ts` | Archivos ya desplegados: el escritor debe reconocer ambos nombres y no duplicar drop-ins. |
| Comentario de llaves SSH `veilform:<alias>` | `src/sshkeys.ts` | Solo afecta llaves nuevas; reconocer ambos prefijos al listar. |
| `user-agent`, `PGAPPNAME`, `appName` i18n, nombre del servidor MCP | `src/net.ts`, `src/sinks.ts`, `src/ui/i18n.ts`, `src/server.ts` | Cambio directo. Usuarios deben re-registrar `claude mcp add veil …`. |
| `X-SI-CSRF`, `si_*` | `src/ui/*`, `src/sinks.ts` | Cosmético; mismo PR. |
| Documentación | `README*.md`, `THREAT-MODEL.md`, `SECURITY.md`, `CHANGELOG.md` | Coordinar con `docs/readme-visuals` (dueña de README). |
| Carpeta local del clon `secret-intake-mcp` | Máquina del dueño | Cosmético. |

Costo estimado: un PR mediano (≈ 60 referencias en 21 archivos) + migradores pequeños. Costo si se pospone a después de publicar: además, deprecación en npm, redirecciones y documentación duplicada.

---

## 3. Investigación previa

Comparación honesta. Lo que no está verificado se marca. No he ejecutado benchmarks de ninguno de estos proyectos; las tasas de detección de terceros **no** se citan.

| Proyecto | Qué hace (resumen) | Qué copiar | Qué hacer distinto |
|---|---|---|---|
| **git-crypt** | Filtro clean/smudge de git; cifra archivos completos con AES-256 en modo CTR e IV sintético derivado por HMAC del contenido (determinista, para que git no vea cambios espurios); acceso multiusuario por GPG. | La integración por `.gitattributes` (`filter=`, `diff=`), transparente para el flujo de git. | Determinismo **revela igualdad** de contenidos entre versiones/archivos; revocar a un usuario exige recifrar y el historial conserva lo viejo; smudge deja **texto plano en el árbol** (malo con agentes). Veil: cifrado aleatorio con "re-cifrado estable" (no recifrar si no cambió), cifrado por valor, sin texto plano por defecto. |
| **sops** (CNCF, getsops) | Cifra **valores** (no llaves) de YAML/JSON/ENV/INI; llave de datos envuelta con KMS, PGP, age, Vault Transit; MAC sobre el documento; **grupos de llaves con umbral Shamir**. | Cifrado por valor con diffs legibles; envoltura multi-proveedor; grupos umbral; MAC de documento. | El MAC global provoca conflictos en merges **(verificar si hoy ofrece driver de merge)**; los nombres de llaves quedan en claro (aceptable y útil, pero hay que decirlo); no tiene escáner ni detección. Veil: mismo modelo de valores + driver de merge + escáner + broker. |
| **age** | Formato simple: cabecera con "stanzas" por destinatario (X25519, scrypt, SSH), HMAC de cabecera, payload STREAM ChaCha20-Poly1305 en bloques de 64 KiB; **plugins** (YubiKey, TPM, Secure Enclave, FIDO2 de terceros). Versiones recientes añadieron destinatarios híbridos post-cuánticos ML-KEM-768 + X25519 **(verificar versión y estado)**. | Construcción criptográfica completa (es la base del formato `.veil`), regla "scrypt va solo", protocolo de plugins para reutilizar el hardware soportado. | age deliberadamente no tiene metadatos, firmas ni agilidad negociada. Veil añade metadatos cifrados, firma opcional, tipos de contenido, grupos umbral, destinatarios KMS. |
| **dotenvx** | `.env` con valores `encrypted:…` (ECIES sobre secp256k1), llave pública en el propio `.env`, privada en `.env.keys`; `dotenvx run`. | Ergonomía: un solo archivo commiteable, llave pública en el archivo para que cualquiera cifre, `run` que inyecta. | Una sola llave privada compartida por entorno (sin múltiples destinatarios reales ni revocación fina) **(verificar soporte multi-llave actual)**; `.env.keys` en claro junto al repo. Veil: destinatarios por persona/dispositivo/CI, llaves en hardware/KMS. |
| **1Password CLI / Connect** | Referencias `op://vault/item/field`, `op run`, `op inject`; Connect como servidor en tu infraestructura; cuentas de servicio. | Referencias por nombre resueltas en tiempo de uso (Veil ya lo hace con `${secret:x}`); `inject` de plantillas. | Producto comercial cerrado y centrado en humanos; Veil se integra como destino (`http-api` ya soporta Connect) en vez de competir en bóveda empresarial. |
| **HashiCorp Vault / OpenBao** | Servidor de secretos, secretos dinámicos, motor **Transit** (cifrado como servicio), unseal por Shamir. Vault pasó a licencia BSL en 2023; OpenBao es el fork bajo Linux Foundation. | Transit como "llave de servidor" para CI/servidores; secretos dinámicos como respuesta ideal a fugas (credenciales de vida corta). | Operar Vault es pesado; Veil es local-first y lo usa como destinatario/destino, no lo reemplaza. |
| **Doppler** | SaaS de secretos, `doppler run`, sincronía a plataformas. | Integraciones de sincronía y DX de `run`. | El servidor ve los valores. Veil: el servidor (si existe) solo ve cifrado. |
| **Infisical** | Plataforma de secretos open-source (núcleo MIT), con escaneo de secretos integrado **(verificar)**. Históricamente anunció cifrado de extremo a extremo y luego cambió el modelo por defecto **(verificar)**. | Escaneo integrado + gestión; adaptador ya existe en Veil. | Veil no apunta a ser plataforma web; foco local + agentes. |
| **gitleaks** | Escáner por reglas regex + entropía, configuración TOML, `allowlist`, hook pre-commit, acción de GitHub (licencia requerida para organizaciones **(verificar)**). | Formato de reglas, allowlists por ruta/regex/commit, salida SARIF. | Sin verificación de vigencia; sin huellas de valores propios. Veil: reglas + huellas + contexto, y SARIF compatible. |
| **trufflehog** | Cientos de detectores por proveedor con **verificación en vivo** contra la API del proveedor; escanea git, S3, Docker, etc. | Detectores con verificación opcional (reduce falsos positivos drásticamente); escaneo de fuentes múltiples. | Verificar envía el secreto al proveedor (es legítimo, pero es salida de red): en Veil es **opt-in**. Licencia AGPL **(verificar)** → no copiar código, solo ideas. |
| **GitHub secret scanning / push protection** | Escaneo del lado servidor con patrones de socios y validación. | Es complementario y gratuito en repos públicos: Veil debe **recomendarlo**, no duplicarlo. | Solo ve lo que llega a GitHub; no ve agentes, portapapeles ni otros destinos. |
| **Canarytokens (Thinkst)** | Servicio (y código abierto autohospedable) de honeytokens: llaves AWS señuelo, URLs, DNS, documentos. | Tipos de canario y diseño de alertas; integración para llaves AWS señuelo. | Veil añade canarios **locales** (archivos señuelo vigilados) y canarios registrados en el motor de huellas (detectan exfiltración en transcripts/salidas). |
| **BlindKey** | Nombre ya usado por otro proyecto (por eso se descartó). No conozco sus detalles técnicos **(verificar)**. | — | — |
| **OneCLI** | Entiendo que es una pasarela/bóveda de credenciales para agentes que inyecta credenciales en la capa de red **(verificar)**. | Si se confirma: inyección en proxy para que el agente nunca tenga el valor ni en su entorno. | Veil ya inyecta en su proceso (`secret_use http`); un proxy de salida es F7. |
| **nono** | Entiendo que es un sandbox de capacidades para agentes basado en Landlock (Linux) y Seatbelt (macOS) **(verificar autoría y estado)**. | El patrón de sandbox del kernel sin root para contener al agente. | Veil no debe escribir su propio sandbox general: debe **generar perfiles** para sandboxes existentes (Claude Code sandbox, bubblewrap, Landlock, Seatbelt, nono si encaja). |

**Conclusión de la investigación.** Ninguno de estos combina (a) que el agente nunca vea valores, (b) prevención en todos los puntos de salida con huellas de valores propios, (c) atribución de quién pide un secreto y (d) formato portable con custodia moderna. La apuesta de Veil es **integrar** primitivas probadas (age, sops-style, gitleaks-style, sandboxes del SO), no reinventarlas.

---

## 4. Arquitectura objetivo

### 4.1 Componentes

```
                  ┌──────────────────────────── máquina del usuario ───────────────────────────┐
  agente (Claude) │  MCP @asteby/veil (TS) ──┐                                                  │
  hooks Claude ───┼─ veil hook … (Go) ───────┤   IPC autenticado (unix socket / named pipe)     │
  git hooks ──────┼─ veil scan/fix (Go) ─────┼──▶ veild (Go)  ── llaves: SE/TPM/YubiKey/llavero │
  VS Code ext ────┼─ cliente TS ─────────────┤     │  broker de valores + atribución de proceso  │
  shell/cliente ──┼─ veil run / guard ───────┘     │  motor de huellas + políticas + canarios    │
                  │                                │  log Merkle firmado + alertas               │
                  │                                └─▶ páginas 127.0.0.1 (reutiliza src/ui)      │
                  └───────────────┬─────────────────────────────────────────────────────────────┘
                                  │ solo cifrado / hashes / eventos firmados
              destinos opacos (git, S3, servidor de equipo, OPS, KMS, transparency log)
```

| Componente | Lenguaje | Rol |
|---|---|---|
| `core/` (`format`, `suites`, `scan`, `policy`, `keys`, `audit`) | Go | Única implementación criptográfica y del escáner. |
| `veil` (CLI) | Go | Comandos de usuario, hooks de git y de agentes, `run`, `guard`, `verify`, `import/export`. Binario estático. |
| `veild` (daemon) | Go | Broker de valores, caché desbloqueada, atribución, vigía de archivos, portapapeles, alertas, log. Socket `0600` en `$XDG_RUNTIME_DIR/veil/` (Linux), equivalente en macOS/Windows. |
| `@asteby/veil` MCP | TS | El servidor actual, migrado a cliente de `veild` (deja de abrir almacenes él mismo). Conserva páginas, esquemas, sinks. |
| `@asteby/veil` librería | TS | Cliente IPC + parser/verificador **solo de cabecera** (sin descifrado) para la extensión de editor y herramientas JS. |
| `asteby/veil-action` | Go (contenedor o binario) | GitHub Action: escaneo de PR/push, `veil verify`, política, SARIF. |
| `editors/vscode` | TS | Resaltado, vista de cabecera, "cifrar selección", diagnósticos del escáner, nunca muestra valores. |

**Por qué un daemon (y por qué no es nuevo).** La rama hermana ya introduce un **agente de sesión** con caché de KEK/DEK tras un socket unix `0600` (`src/crypto/keysource.ts`). `veild` es la evolución de ese agente, no un segundo proceso. Lo que añade: (1) Atribución: el daemon ve al proceso que pide (credenciales del par). (2) Caché desbloqueada en un solo proceso endurecido (`PR_SET_DUMPABLE=0`, memoria `mlock`, sin swap) en vez de en cada CLI. (3) Un solo punto para política, log y alertas. **Modo sin daemon:** la CLI funciona sola para `encrypt/decrypt/verify/scan` (CI, scripts), con desbloqueo por invocación.

**Por qué Go y no seguir en TS (resumen para D2).** Latencia de hook (arranque de Node ~decenas de ms vs. Go ~pocos ms; un pre-commit corre cientos de veces al día), binario único para Windows sin Node, llamadas al SO sin addons nativos (`prctl`, `SO_PEERCRED`, fanotify, ETW), y bibliotecas de referencia (`filippo.io/age`, `golang.org/x/crypto`, `crypto/mlkem`, `sigstore-go`, `fsnotify`). Costo: dos lenguajes en el repo y migrar las partes de `src/stores` que el daemon absorbe. Si el dueño prefiere un solo lenguaje, el plan es viable en TS con estas pérdidas: hooks más lentos, Argon2/ML-KEM sujetos a la versión de Node, y atribución/telemetría con addons nativos.

### 4.2 Diseño del monorepo propuesto

```
core/            Go: format/ suites/ scan/ policy/ keys/ audit/ ipc/
cmd/veil/        Go: CLI
cmd/veild/       Go: daemon
packages/mcp/    TS: servidor MCP (src/ actual)
packages/node/   TS: cliente + verificador de cabecera
action/          GitHub Action
editors/vscode/  extensión
spec/            FORMAT-VEIL-SPEC.md + vectors/ (JSON) + policy schema
bench/           corpus de evaluación del escáner + scripts de medición
fuzz/            corpus semilla de fuzzing
playbooks/       playbooks de rotación por proveedor
```

---

## 5. Pilar 1 — Cifrado automático al subir

**Objetivo:** que ningún valor sensible salga en claro por un camino que Veil pueda interceptar; y si sale, que se sepa.

### 5.1 Motor de detección (`core/scan`)

Cuatro detectores combinados con un **puntaje** (0–1) y una **explicación** que nunca incluye el valor:

| Detector | Cómo | Precisión esperada | Notas |
|---|---|---|---|
| **Valores conocidos (huellas)** | Compara tokens candidatos contra huellas HMAC de los valores de la bóveda y sus variantes (§5.2). | Muy alta (coincidencia exacta con un secreto real). | El más importante y el que nadie más tiene localmente. |
| **Proveedores** | Reglas por proveedor: prefijo, longitud, alfabeto y **checksum cuando existe** (los tokens nuevos de GitHub, p. ej., incluyen un CRC32 en sus últimos caracteres; npm también **(verificar alcance por proveedor)**). Stripe `sk_live_/rk_live_`, Mercado Pago `APP_USR-`, AWS `AKIA/ASIA` + secreto de 40, llaves privadas PEM/OpenSSH, JWT, URLs con credenciales, cadenas de conexión. | Alta con checksum; media sin él. | Formato de reglas compatible con gitleaks (importable) para no reinventar. |
| **Entropía + contexto** | Entropía de Shannon por alfabeto (hex, base64, base62) con umbrales distintos, longitud mínima, y **contexto**: nombre de la llave (`*_KEY`, `*SECRET*`, `password`), tipo de archivo, asignación vs. comentario. | Media; es el que más falsos positivos produce. | Exclusiones: hashes de integridad de lockfiles, SRI, UUIDs, hashes de commits, imágenes base64, fixtures marcados. |
| **Canarios** | Huellas de valores señuelo (§6.4). | Certeza (si aparece un canario, es una fuga o una lectura). | Alerta inmediata. |

**Verificación en vivo** (¿el token funciona?) contra el proveedor: **opt-in** por proveedor, nunca en hooks locales por defecto (latencia + salida de red), útil en CI y en barridos.

**Salidas:** texto humano, JSON y **SARIF** (para GitHub code scanning). Cada hallazgo: archivo, línea, columna, detector, regla, puntaje, huella truncada (no el valor), acción sugerida (`veil fix`).

### 5.2 Huellas de valores conocidos (diseño)

- Para cada secreto en la bóveda se calculan sus variantes (reutilizando `variantsOf` de `src/redact.ts`, portado a Go) y para cada variante `fp = HMAC-SHA-256(k_scan, "veil/1 fp" ‖ variante)[0..16]`.
- `k_scan` es una llave aleatoria del dispositivo en el llavero/SE. **Nunca** se guardan hashes sin llave: un SHA-256 de un PIN o contraseña corta se invierte por fuerza bruta.
- Las huellas viven en el daemon (y en un filtro Bloom con FPR configurado, p. ej. 1e-6, para el modo CLI sin daemon).
- **Tokenización** del texto a escanear: candidatos por regex (secuencias de alfabeto base64/hex/url-safe ≥ 8), líneas completas de PEM, valores tras `=`/`:` en formatos conocidos. Además, ventanas de base64 desplazadas (como `embeddedBase64`) para encontrar el valor dentro de blobs.
- **CI:** no se exporta `k_scan`. Se genera un conjunto de huellas con `k_ci` separado, guardado como secreto de CI (o en KMS); riesgo documentado: quien tenga `k_ci` y el conjunto puede confirmar adivinanzas de valores de baja entropía → solo se exportan huellas de secretos con entropía estimada ≥ 64 bits.
- **Valores cortos** (< 8 caracteres o baja entropía): no generan huellas (demasiados falsos positivos y riesgo de confirmación).

### 5.3 Git: hooks y filtro

| Pieza | Comportamiento |
|---|---|
| `pre-commit` | Escanea solo lo **staged** (`git diff --cached` en modo blob, no el árbol). Si un hallazgo cae en una ruta con `action = "auto-encrypt"` y formato conocido → cifra los valores y re-stagea; en otro caso → bloquea con mensaje y `veil fix <ruta>`. Objetivo p95 < 300 ms en un diff típico. |
| `pre-push` | Escanea el **rango de commits que se va a empujar** (atrapa commits hechos con `--no-verify` o desde otra máquina). Más lento pero raro. Bloquea; nunca reescribe historia (sin force-push: se indica cómo revertir y **rotar**, porque si el valor ya está en un commit local, ya está en disco). |
| `commit-msg` | Escanea el mensaje (sí, la gente pega llaves en mensajes). |
| Filtro `clean` | `.gitattributes`: `*.env filter=veil diff=veil merge=veil`. `clean` cifra por valor al hacer `git add` (el índice nunca tiene claro). **Re-cifrado estable:** si el valor no cambió respecto al blob en `HEAD`, se reutiliza el cifrado previo (no ruido en diffs, sin determinismo criptográfico). |
| Filtro `smudge` | **Por defecto no descifra** (D4): el árbol conserva el cifrado y los procesos consumen con `veil run`. Opt-in por ruta (`smudge = "decrypt"`) para quien lo necesite, con advertencia de que el agente podrá leer el archivo. |
| `diff=veil` (textconv) | Muestra `KEY: changed / added / removed` y huellas truncadas, nunca valores. |
| `merge=veil` | Driver de merge que resuelve por llave y recalcula el MAC del documento (evita el problema de conflictos de MAC global). |
| Instalación | Generaliza el `veilform env hook install` de la rama hermana (hoy solo `.env`) al escáner completo. `veil git install` escribe en `.git/hooks` **encadenando** hooks existentes; integración documentada con `pre-commit` (framework), `lefthook` y `husky`. Opción global `veil git install --global` vía `init.templateDir` (opt-in). |
| Servidor | `pre-receive` para Git autohospedado; GitHub Action para GitHub (§5.4). |

### 5.4 GitHub Action (`asteby/veil-action`)

- Disparadores: `pull_request`, `push`, `merge_group`. Escanea el diff del evento y, en `schedule`, el repo completo.
- Ejecuta `veil verify` sobre todos los `*.veil` y documentos con valores `veil:` (estructura canónica, destinatarios obligatorios por política —p. ej. "el destinatario de recuperación debe estar"—, firmas si la política las exige).
- Salida SARIF → code scanning; estado de check bloqueante; comentario opcional sin valores.
- Permisos mínimos (`contents: read`, `security-events: write`), fijada por SHA en la documentación, binario verificado por firma antes de ejecutarse.
- Complementa (no reemplaza) push protection de GitHub; la documentación recomienda activarlo.

### 5.5 Otros puntos de salida

| Punto | Mecanismo | Límite honesto |
|---|---|---|
| **Docker build context** | `veil scan --docker-context <dir> [-f Dockerfile]` evalúa el contexto **aplicando `.dockerignore`** como lo haría BuildKit; marca `.env`, llaves, volcados que entrarían. `veil fix` propone entradas para `.dockerignore` y `RUN --mount=type=secret`. `veil scan --image <tar>` revisa capas de una imagen exportada. | Solo si se invoca (hook en scripts/CI o `veil guard docker build`). |
| **S3 / rsync / scp / rclone** | `veil guard -- <comando>`: analiza argumentos, escanea fuentes locales, bloquea o pide confirmación. Integración opcional por alias de shell. | Envolturas: se pueden saltar. Es para errores honestos, no para un adversario. |
| **Vigía de archivos** | `veild` vigila (inotify/FSEvents/ReadDirectoryChangesW, sin root) los directorios de proyecto registrados, `~/.ssh`, `~/Downloads` y `/tmp` del usuario: nuevos `.env*`, llaves privadas sin passphrase, volcados (`*.sql`, `*.dump`, `*.bak`) con huellas conocidas, archivos de configuración con tokens (`~/.npmrc`, `~/.docker/config.json`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`). Acción: avisar → `veil absorb <archivo>` (mueve el valor a la bóveda y deja un `.veil` o una referencia). | Vigilar no es impedir: hay una ventana entre la escritura y el aviso. |
| **Portapapeles** | `veild` observa cambios (Wayland `wl-paste --watch`, X11 por sondeo, macOS `changeCount`, Windows `AddClipboardFormatListener`) y compara contra huellas; si coincide fuera de una copia hecha por Veil → alerta y limpieza opcional tras N s. Todo local. | Gestores de portapapeles y sincronía en la nube pueden capturarlo antes. |
| **Terminal / historial** | `veil shell-init` (bash/zsh/fish/pwsh): `preexec` que avisa de `export X=sk_live…`, `cat .env`, `echo $TOKEN`; barrido de `~/.*_history` por huellas (`veil sweep --history`) con limpieza asistida. | El scrollback de la terminal no se puede controlar. |
| **Transcripts del agente** | `veil sweep --agents`: barre transcripts locales de agentes (Claude Code guarda sesiones en `~/.claude/projects/**/*.jsonl` **(verificar ruta vigente)**) buscando huellas. Si un valor aparece → **el modelo lo vio** → alerta + playbook de rotación. También en vivo vía hook (§6.5). | Detecta después del hecho; el remedio es rotar. |

### 5.6 Políticas por proyecto (`.veil/policy.toml`)

- Archivo versionado en el repo; esquema en `spec/policy.schema.json`; `veil policy check` lo valida.
- **Modos:** `block` (por defecto global), `auto-encrypt` (solo rutas declaradas con formato conocido: dotenv, JSON, YAML, TOML, archivo entero), `warn` (solo para migraciones, con caducidad).
- **Excepciones** por huella (no por valor), con `reason` y `expires` obligatorios; comentarios en línea `# veil:allow reason="fixture"` revisables en PR.
- **Destinatarios por ruta** (p. ej. `team:backend`, `ci:github-oidc`, `recovery`), y `required_recipients` que `verify` exige.
- **Reglas para agentes** (`[agents]`): rutas que los hooks de agentes niegan; se compilan a `permissions.deny` y a perfiles de sandbox.
- **Respuesta** (`[response]`): qué hacer ante fuga (`alert`, `rotate:ask`, `rotate:auto` para proveedores con playbook automatizable).
- Ejemplo completo en el Apéndice A.

### 5.7 Falsos positivos y negativos: cómo medirlos

Ver §12. Resumen: corpus etiquetado (positivos sintéticos por proveedor + valores conocidos con variantes + negativos difíciles: lockfiles, hashes, UUIDs, base64 de imágenes, fixtures de proyectos OSS), métricas de precisión/recall por detector, presupuesto de FP por repositorio, y telemetría **local** de "falso positivo marcado por el usuario" (`veil allow`) que nunca sale de la máquina salvo opt-in.

---

## 6. Pilar 2 — Detección de lectura, canarios y respuesta

### 6.1 Principio

> Lo que no existe en claro no se puede leer en claro. Lo que sí existe en claro, se vigila; lo que se vigila sin privilegios, se correlaciona; y lo que no se puede atribuir, se **señuela**.

### 6.2 Telemetría de acceso: qué es viable y con qué privilegios

| Mecanismo | SO | Privilegios | ¿Ve lecturas? | ¿Da pid/binario? | ¿Puede bloquear? | Uso en Veil |
|---|---|---|---|---|---|---|
| **Credenciales del par en IPC** (`SO_PEERCRED`; `getpeereid`/`LOCAL_PEERPID`; `GetNamedPipeClientProcessId`) | Linux / macOS / Windows | Ninguno | Ve **peticiones al broker** | **Sí** (pid → `/proc/<pid>/exe`, árbol por `ppid`; `proc_pidpath` en macOS; `QueryFullProcessImageName` en Windows) | **Sí** (el broker decide) | **Primario.** |
| inotify (`IN_OPEN`, `IN_ACCESS`) | Linux | Ninguno | Sí (apertura/lectura) | **No** | No | Canarios locales (cualquier apertura es sospechosa); correlación débil con barrido de `/proc/*/fd`. |
| fanotify sin privilegios (Linux ≥ 5.13) | Linux | Ninguno | Sí, en marcas de inodo | Limitado **(verificar qué reporta en `pid` para escuchas sin privilegio)** | **No** (eventos de permiso requieren `CAP_SYS_ADMIN`) | Opcional si da pid. |
| fanotify con `CAP_SYS_ADMIN` (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`) | Linux | root/cap | Sí | Sí | **Sí** | Módulo privilegiado opcional (`veil-sentinel`). |
| auditd (reglas `-w ruta -p r`) | Linux | root | Sí | Sí (+ uid, exe, comm) | No | Alternativa privilegiada sencilla; Veil genera las reglas. |
| eBPF (LSM/kprobes en `openat`/`security_file_open`) | Linux | `CAP_BPF`+`CAP_PERFMON` (root en la práctica) | Sí | Sí, con árbol | Con BPF-LSM, sí | Futuro; complejidad alta. |
| FUSE (`veil mount`) | Linux/macOS (macFUSE/FUSE-T) | Ninguno (usa `fusermount3` setuid) | Sí, en el montaje | **Sí** (el kernel pasa pid/uid de quien pide) | **Sí** (puede esperar aprobación) | Opcional: vistas en claro **bajo demanda** con aprobación por proceso, para herramientas que exigen un archivo. |
| Landlock | Linux ≥ 5.13 | Ninguno | — | — | **Sí, preventivo** (el proceso se restringe a sí mismo y a sus hijos) | Sandbox del agente (`veil agent run`). |
| FSEvents | macOS | Ninguno | **No** (solo cambios) | No | No | Vigía de escrituras (§5.5). |
| Endpoint Security | macOS | Root + **entitlement de Apple** + extensión de sistema | Sí (`AUTH_OPEN`) | Sí | Sí | Solo si se obtiene el entitlement (proceso con Apple, incierto). |
| Seatbelt (`sandbox-exec`) | macOS | Ninguno | — | — | Sí, preventivo | Sandbox del agente (API marcada como obsoleta pero usada por herramientas actuales **(verificar)**). |
| ReadDirectoryChangesW | Windows | Ninguno | No (cambios) | No | No | Vigía de escrituras. |
| Auditoría de acceso a objetos (SACL) | Windows | Admin para configurar | Sí (eventos 4663) | Sí | No | Opcional; Veil genera la configuración. |
| ETW (proveedor de archivos de kernel) | Windows | Admin | Sí | Sí | No | Opcional. |
| Minifiltro de sistema de archivos | Windows | Driver firmado | Sí | Sí | Sí | Fuera de alcance (firma de drivers). |

**Conclusión:** sin privilegios, la atribución fiable solo existe **en el broker** (y en FUSE). Por eso D4: no dejar archivos en claro y hacer que leer un secreto signifique **pedírselo a `veild`**.

### 6.3 Atribución de proceso en el broker

Para cada petición (`get`, `run`, `decrypt`, `share`):

1. pid/uid/gid del par; ruta del ejecutable; hash del ejecutable (cacheado por inodo+mtime); línea de comandos; cwd.
2. **Árbol** de ancestros hasta `init`/`launchd`/`explorer`: se marca si algún ancestro es un agente conocido (binario `claude`, `node …/claude-code/…`, Cursor, Codex CLI, Aider…) o si el entorno del par contiene marcadores de agente (Claude Code define `CLAUDECODE=1` en sus subprocesos **(verificar)**). La lista de firmas de agentes es datos, no código.
3. **Decisión por política:** `allow` (perfil conocido: `veil run` lanzado por el usuario en una terminal), `ask` (página de aprobación que muestra **qué proceso** pide **qué nombre**; recordar por *hash de binario + árbol normalizado + nombre*), `deny` (descendiente de agente pidiendo un valor en claro → siempre deny; el agente debe usar `secret_use`).
4. Endurecimiento del daemon: `PR_SET_DUMPABLE=0` (bloquea `ptrace`/`/proc/<pid>/mem` del mismo usuario, salvo root), `mlock` de la caché, sin core dumps, `RLIMIT_CORE=0`; en macOS, hardened runtime; en Windows, DACL del proceso y del pipe.
5. **Límite:** un proceso del mismo usuario puede falsificar su `argv`/entorno y hacerse pasar por "terminal del usuario". La atribución es **evidencia**, no autenticación fuerte; las acciones de alto riesgo siempre requieren presencia del usuario (toque FIDO2, Touch ID, clic en la página).

### 6.4 Canarios / honeytokens

| Tipo | Cómo alerta | Requiere servicio | Privilegios |
|---|---|---|---|
| **Archivo señuelo local** (`.env.production.bak`, `id_rsa_old`, `credentials.old`) con valores plausibles | inotify `IN_OPEN` sobre un archivo que nada legítimo abre → alerta con contexto (qué procesos tenían ese directorio como cwd en ese momento, best-effort) | No | No |
| **Valor señuelo en la bóveda** registrado en el motor de huellas | Si aparece en un transcript, salida, portapapeles, commit o tráfico del proxy → **fuga confirmada** | No | No |
| **Llave AWS señuelo** | Uso de la llave en AWS → alerta del servicio de canarios (Canarytokens autohospedado o el servicio público) | Sí | No |
| **URL/DNS señuelo** (`DATABASE_URL=postgres://u:p@c-<id>.canary.<dominio>/db`, webhooks) | Resolución DNS o conexión al host del canario | Sí (verificador propio: DNS autoritativo + HTTP/TCP) | No |
| **Token señuelo de Veil** (`VEIL_TOKEN=veil_live_…`) | El servidor de equipo/sync reconoce el prefijo y alerta en cualquier intento de uso | Sí (servidor de Veil) | No |
| **Llave SSH señuelo** | Un honeypot SSH acepta solo esa llave y alerta | Sí | No |

- **Proveedores sin endpoint propio** (Stripe, Mercado Pago, GitHub): un token falso con su formato **no** alerta si alguien lo usa contra el proveedor, porque no vemos su tráfico. Por eso los canarios de proveedor solo sirven como **huella** (detectan copia/exfiltración en lo que Veil sí ve), no como trampa remota. Hay que decirlo claro en la UI.
- `veil canary plant --profile repo|home|server` coloca un conjunto coherente; `veil canary list/rotate/remove`.
- Los canarios se excluyen de los escáneres de Veil para no dispararse a sí mismos, pero sí cuentan en los barridos de exfiltración.

### 6.5 Bloqueo por política en agentes (Claude Code y otros)

Capas, de más débil a más fuerte:

1. **Instrucciones del MCP** (ya existe `SECURITY_NOTE`): el modelo coopera; no es control.
2. **`permissions.deny`** en `.claude/settings.json`: `Read(**/.env*)`, `Read(**/*.veil)`, `Read(~/.config/veil/**)`, `Bash(secret-tool:*)`, `Bash(security:*)`, `Bash(printenv:*)`, `Bash(env:*)`… `veil agent setup claude` las genera desde `.veil/policy.toml` y muestra el diff antes de escribir.
3. **Hook `PreToolUse`** (`veil hook claude-pretooluse`): recibe el JSON de la herramienta por stdin; niega `Read/Edit/Grep/Glob` sobre rutas protegidas y `Bash` con patrones de lectura (`cat|less|head|tail|grep|base64|xxd … <ruta protegida>`, `printenv`, volcado de `/proc/*/environ`) devolviendo `permissionDecision: "deny"` y un motivo que redirige a `secret_use`. Es un **tope**: se evade con ofuscación (`c''at`, intérpretes, `eval` de base64).
4. **Hook `UserPromptSubmit`**: si el usuario **pega un secreto en el chat** (huella o detector de proveedor), se bloquea el envío y se ofrece guardarlo con `secret_request`. Alto valor, bajo costo.
5. **Hook `PostToolUse`**: escanea la salida de la herramienta por huellas. Si hay coincidencia, el valor **ya entró al contexto** → alerta + playbook de rotación + bloqueo de la sesión. Es detección, no prevención.
6. **Sandbox** (la frontera real): `veil agent run claude` lanza el agente con un perfil donde las rutas de la bóveda, `~/.ssh`, `.env*` y el socket de administración del daemon **no existen** (bubblewrap/Landlock en Linux, Seatbelt en macOS, usuario aparte en Windows); solo se expone el socket del MCP. Donde exista, preferir el sandbox propio del cliente (Claude Code tiene sandbox de Bash con restricciones de sistema de archivos y red **(verificar cómo combina con reglas de lectura)**) y que Veil genere su configuración.
7. **Usuario del SO aparte** para el agente: la recomendación más fuerte para equipos.

### 6.6 Detección de exfiltración

| Canal | Mecanismo | Cobertura |
|---|---|---|
| Salidas de herramientas | Redactor actual + `PostToolUse` | Variantes conocidas; no transformaciones arbitrarias. |
| Prompts del usuario | `UserPromptSubmit` | Huellas + proveedores. |
| Transcripts guardados | `veil sweep --agents` periódico | Retrospectivo. |
| Red saliente del agente | **Proxy de salida opcional** (F7): el sandbox fuerza `HTTPS_PROXY` hacia `veild`; con CA local de confianza **solo dentro del sandbox** se inspeccionan cuerpos y cabeceras por huellas. Sin CA, solo SNI/host contra allowlist. | Solo herramientas que respetan el proxy dentro del sandbox; TLS con pinning queda ciego. Riesgo: una CA local es un activo sensible más. |
| Portapapeles, commits, historial | §5.5 | — |

### 6.7 Alertas

Canales: notificación del SO (libnotify/`osascript`/toast), página local con historial, **webhook firmado** (HMAC) para Slack/Discord/n8n, correo vía SMTP configurado, push a móvil vía ntfy u otro (opcional). Cada alerta: severidad, qué (nombre del secreto o canario, nunca valor), quién (proceso/árbol/agente), dónde, acción tomada, botón "fue legítimo" (alimenta la medición de falsos positivos). Limitación de frecuencia y agrupación.

### 6.8 Respuesta automática y playbooks de rotación

- **Playbook** = archivo declarativo por proveedor: `detect` (cómo reconocer el secreto), `revoke`, `mint`, `deploy` (reutiliza `secret_write`: `.env` local/SSH, GitHub, systemd), `verify`, `close`. Pasos de tipo `api` (con la credencial administrativa resuelta por el broker) o `web` (flujo ciego con `web_capture`/`web_login` cuando el proveedor solo lo permite desde su panel).
- **Por proveedor (a verificar uno por uno antes de prometer automatización):**
  - **AWS IAM**: crear llave nueva, desplegar, desactivar y borrar la vieja por API (`CreateAccessKey`, `UpdateAccessKey`, `DeleteAccessKey`): automatizable.
  - **GitHub**: los PAT se crean desde la UI; los tokens de GitHub App son de vida corta (mejor práctica: migrar a Apps). GitHub publicó una API de revocación de credenciales filtradas **(verificar alcance y disponibilidad)**.
  - **Stripe**: "roll key" desde el Dashboard; no tengo certeza de una API pública para rotar llaves secretas **(verificar)** → flujo `web` ciego.
  - **Mercado Pago**: renovación de credenciales desde el panel **(verificar API)** → flujo `web` ciego.
  - **Bases de datos**: `ALTER ROLE … PASSWORD` vía sink SQL existente + despliegue: automatizable.
  - **SSH**: `ssh_key_provision` con llave nueva + retiro de la vieja de `authorized_keys`: automatizable.
- Modos: `rotate:ask` (por defecto: prepara todo y pide un clic) y `rotate:auto` (solo playbooks marcados como seguros y probados).
- **Bloquear compartición**: ante fuga o canario disparado, el daemon congela los enlaces de compartir del secreto afectado (función de `feat/vault-sync-share`; aquí solo se define el evento `share.freeze`).
- Recomendación de diseño: preferir **credenciales de vida corta** (OIDC, STS, GitHub Apps, Vault dinámico); la mejor rotación es la que no hace falta.

### 6.9 Registro a prueba de manipulación

- Evolución de `audit.ts`: cada entrada es una hoja de un **árbol Merkle** (estilo RFC 6962/9162); cada N entradas o T minutos, un **checkpoint** (tamaño + raíz) **firmado con Ed25519** con una llave del dispositivo (no exportable si hay SE/TPM).
- **Anclaje opcional** del checkpoint (solo el hash): servidor de equipo, Sigstore Rekor (público), OpenTimestamps, o un repositorio git privado. Privacidad: un hash de checkpoint no revela contenido.
- `veil audit verify` comprueba cadena, firmas y anclas; `veil audit prove <entrada>` da prueba de inclusión.
- Límite honesto: un atacante con la llave de firma (mismo usuario sin hardware) puede reescribir **hacia adelante** desde el último ancla; el anclaje externo frecuente acota la ventana.
- Compatibilidad: el JSONL actual se importa como prefijo y se ancla en el primer checkpoint.

---

## 7. Pilar 3 — Formato `.veil`

Especificación detallada en [`FORMAT-VEIL-SPEC.md`](FORMAT-VEIL-SPEC.md). Resumen de decisiones:

### 7.1 ¿Formato propio o age?

| Opción | Pro | Contra |
|---|---|---|
| A. age tal cual + metadatos dentro del payload | Formato auditado y estable; herramientas existentes; menor superficie nueva. | Sin cabecera extensible para tipos de contenido, firmas, KMS, grupos umbral, metadatos cifrados separados; "verify sin descifrar" limitado. |
| **B. Contenedor propio con criptografía de age** (recomendada) | Cabecera TLV extensible y canónica; metadatos cifrados; firma; grupos umbral; destinatarios KMS; misma construcción de payload que age; **protocolo de plugins de age** para hardware. | Formato nuevo = superficie nueva que **debe** auditarse; ecosistema propio de herramientas. |
| C. HPKE (RFC 9180) puro para destinatarios | Agilidad estandarizada, modo PQ vía KEMs híbridos. | Menos ecosistema de plugins de hardware que age. |

Recomendación: **B**, usando HPKE como **suite de destinatario adicional** cuando haga falta agilidad (p. ej. el KEM híbrido) y exportación a age sin pérdidas cuando todos los destinatarios son X25519/passphrase.

### 7.2 Elementos

- **Bytes mágicos** `89 56 45 49 4C 0D 0A 1A` (`\x89VEIL\r\n\x1a`, al estilo PNG: detecta transferencias en modo texto y truncamiento). **Armadura** textual `-----BEGIN VEIL FILE-----`.
- **Versión** mayor/menor; **cabecera TLV** con bit "crítico" (un lector que no entiende un TLV crítico rechaza el archivo); orden canónico; **MAC de cabecera** HMAC-SHA-256 derivado de la llave de archivo.
- **Payload** STREAM (bloques de 64 KiB, ChaCha20-Poly1305 por defecto, AES-256-GCM como suite alternativa para hardware con AES-NI y FIPS).
- **Destinatarios múltiples**: X25519, passphrase (Argon2id; scrypt para importar), P-256 (SE/YubiKey PIV/TPM), FIDO2-PRF/hmac-secret, KMS (AWS/GCP/Vault Transit), grupo umbral (Shamir M-de-N anidado), plugin age, híbrido X25519+ML-KEM-768 (experimental).
- **Metadatos cifrados** (nombres, etiquetas, fechas, origen) en un TLV propio; públicos solo los mínimos para descifrar.
- **Firma opcional** (Ed25519) sobre cabecera + hash del payload cifrado → `veil verify` comprueba autoría e integridad **sin descifrar**.
- **Forma por valor** para `.env` (y luego YAML/JSON/TOML): se **adopta** el formato `veilform-env v1` de `feat/vault-sync-share` (cabecera `#/…`, valores `enc:v1:`, AAD con contexto y variable, MAC de documento, re-cifrado estable) y se proponen extensiones v1.1: destinatarios asimétricos y prefijos `#/veil-env v1` / `veil:1:` **[RENOMBRE]** (spec §10).
- **Tipo MIME** `application/vnd.asteby.veil` (registro en el árbol de vendedor de IANA, trámite ligero) y `application/vnd.asteby.veil+armor` para la armadura **[RENOMBRE]**; extensión `.veil`.
- **Asociaciones:** `shared-mime-info` (Linux), UTI exportado `com.asteby.veil` (macOS), ProgID en el instalador (Windows), `.gitattributes` (`*.veil binary diff=veil linguist-generated`), extensión de VS Code (resaltado de armadura y sobres, vista de cabecera, `verify` en guardado). **GitHub Linguist** acepta lenguajes nuevos solo con uso amplio en repos públicos (umbral del orden de cientos de repos **(verificar cifra exacta)**): no es un objetivo temprano.
- **Vectores de prueba** (positivos y negativos, estilo Wycheproof), **canonicalización** estricta (rechazar en vez de normalizar), **fuzzing** de todos los parsers y **fuzzing diferencial** entre el verificador Go y el TS.
- **Interoperabilidad:** `veil import/export` con age (directo), sops (vía biblioteca Go de sops o binario; mapea grupos de llaves a grupos umbral), dotenvx (requiere ECIES secp256k1: dependencia adicional o invocar `dotenvx` **(decidir)**). Migración desde `encrypted-file` v1.

---

## 8. Pilar 4 — Custodia de llaves

### 8.1 Jerarquía

```
Identidad de dispositivo (no exportable si hay hardware)
  └─ envuelve → Llave de bóveda / llaves de archivo (.veil)
Identidad de recuperación (Shamir 2-de-3: papel, YubiKey, persona de confianza)
  └─ destinatario obligatorio en cada .veil por política
Identidad de servidor/CI (KMS, sin humanos)
  └─ destinatario por ruta/entorno
```

### 8.2 Opciones de custodia

| Custodia | Mecanismo | Presencia del usuario | Estado del ecosistema | Prioridad |
|---|---|---|---|---|
| Llavero del SO | Secret Service, Keychain, DPAPI/Credential Manager | No (sesión desbloqueada) | Ya existe (falta Windows) | F2 |
| **Secure Enclave** (macOS/iOS) | P-256 no exportable; política biométrica | Touch ID opcional | Plugin age para SE existe de terceros **(verificar mantenimiento)** | F5 |
| **TPM 2.0** (Linux/Windows) | Llave P-256/RSA atada al TPM, sellado con PCR opcional | PIN opcional | `age-plugin-tpm` existe **(verificar estado)** | F5 |
| **YubiKey PIV** | P-256 en ranura PIV, política de toque/PIN | Toque | `age-plugin-yubikey` es maduro **(verificar)** | F5 |
| **FIDO2 hmac-secret / WebAuthn PRF** | Salida PRF de una credencial (incl. passkeys que soporten PRF) → KEK | Toque/biometría | Soporte de PRF variable por navegador/autenticador/proveedor de passkeys **(verificar matriz)**; hay plugins age de terceros **(verificar)** | F5 |
| **Passkeys sincronizadas** | PRF de una passkey en iCloud/Google/1Password | Biometría | Útil para recuperación multi-dispositivo; la sincronía la custodia el proveedor (dependencia de confianza a documentar) | F5 (investigar) |
| **KMS** (AWS KMS, GCP KMS, Vault/OpenBao Transit) | Envoltura de la llave de archivo; autenticación por OIDC en CI | No | Patrones estándar (sops lo hace) | F5/F6 |
| Passphrase | Argon2id (m=256 MiB, t=3, p=1 por defecto, ajustable) | Escribirla | Respaldo | F2 |

### 8.3 Umbral y aprobaciones M-de-N

- **Recuperación:** la identidad de recuperación es un **grupo umbral**: la llave de archivo se divide con Shamir sobre GF(2^8) en N partes, cada una envuelta a un destinatario distinto; se necesitan M para descifrar. Partes en papel (código QR/mnemotécnico con checksum), YubiKey, persona de confianza.
- **Compartición con aprobación M-de-N forzada criptográficamente:** el secreto compartible se cifra a un grupo umbral de aprobadores; para entregarlo a un nuevo destinatario, M aprobadores descifran **su parte** y la re-envuelven al destinatario (en su dispositivo, tras ver la solicitud en la página local). El servidor solo transporta partes cifradas. Alternativa más simple (aprobación por política del servidor) se documenta como **más débil**.
- **Rotación y revocación:** rotar destinatarios = re-envolver la llave de archivo (barato); revocar a alguien **exige rotar los valores** que pudo ver (no se puede "des-saber" un secreto). `veil rotate --recipients` y `veil revoke <identidad>` producen la lista de valores a rotar con sus playbooks.

### 8.4 Post-cuántico (investigación)

- Suite experimental: KEM híbrido **X25519 + ML-KEM-768** (construcción tipo X-Wing, borrador en el CFRG **(verificar estado del borrador)**; ML-KEM estandarizado en FIPS 203, 2024). Go incluye `crypto/mlkem` desde 1.24.
- Motivo: "cosechar ahora, descifrar después" afecta a archivos `.veil` en repos públicos o en la nube; las firmas PQ no son urgentes (la falsificación futura no afecta a datos pasados).
- **Criterio de adopción por defecto:** (1) especificación del KEM híbrido estable (RFC o equivalente), (2) vectores de prueba independientes, (3) al menos dos implementaciones interoperables, (4) soporte en age o en una biblioteca auditada que usemos, (5) costo de tamaño aceptable (~1,1 KB por destinatario) y (6) auditoría externa que cubra la suite. Hasta entonces: tras bandera `--pq`, marcado `experimental` en la cabecera.

---

## 9. Pilar 5 — Plataforma, equipo, OPS y CI

### 9.1 Plataformas

| | Linux | macOS | Windows |
|---|---|---|---|
| Llavero | Secret Service | Keychain | **Credential Manager/DPAPI (nuevo)** |
| IPC | Unix socket + `SO_PEERCRED` | Unix socket + `getpeereid`/`LOCAL_PEERPID` | Named pipe + `GetNamedPipeClientProcessId` |
| Vigía | inotify | FSEvents | ReadDirectoryChangesW |
| Sandbox agente | bubblewrap / Landlock | Seatbelt | Usuario aparte / AppContainer **(investigar)** |
| Paquetes | deb, rpm, AUR, Homebrew (Linuxbrew), tarball | Homebrew, pkg firmado y notarizado | winget, Scoop, MSI firmado |

### 9.2 Superficies

CLI (`veil`), MCP (`@asteby/veil`), librería (Go `core` y TS `packages/node`), GitHub Action, extensión de VS Code (y protocolo LSP simple para otros editores), y la API IPC del daemon (documentada y versionada para terceros).

### 9.3 Modo equipo

- **Servidor opcional y ciego:** almacena blobs `.veil`, directorio de llaves públicas, log de membresía firmado y eventos de auditoría firmados. **Nunca** valores ni llaves privadas. Las rutas de sincronía opaca de `feat/vault-sync-share` son la base de transporte.
- **Directorio de llaves con transparencia:** altas/bajas de miembros y dispositivos se registran en un log append-only firmado por un admin; los clientes verifican consistencia (evita que el servidor inyecte una llave falsa para un miembro).
- **Roles:** `owner`, `admin`, `member`, `ci`, `auditor` (solo ve auditoría). Los roles se **imponen criptográficamente** con destinatarios (a quién se cifra) y con firmas (quién puede cambiar membresía); el servidor solo aplica controles adicionales.
- **Aprobaciones:** M-de-N (§8.3) para compartir fuera del equipo, agregar destinatarios de producción, desactivar canarios.
- **Auditoría centralizada opcional:** los dispositivos envían checkpoints y eventos firmados (sin valores); el servidor ofrece vista y alertas de equipo.

### 9.4 CI y auto-releases sin humanos

- **OIDC → KMS:** el job de CI obtiene un token OIDC del proveedor (GitHub Actions), lo cambia por credenciales de vida corta de AWS/GCP y usa KMS para desenvolver la llave del archivo `.veil` del entorno (`ci:github-oidc` como destinatario KMS). Sin secretos de larga vida en GitHub.
- `veil run --env production -- <comando>` en CI inyecta valores en el entorno del proceso hijo; `veil ci mask` registra cada valor como máscara del log de Actions (`::add-mask::`) **antes** de que nada pueda imprimirlo.
- Publicación: npm **trusted publishing** por OIDC con procedencia (sin `NPM_TOKEN`) y firma keyless de binarios (§10).

### 9.5 Integración con OPS / hub de Asteby (propuesta para un PR en el repo de OPS)

Estado observado (OPS @ `e1d69037`): `AddonService.GetSettings` devuelve `installation.Settings` sin enmascarar vía `GET /api/addons/:key/settings`; settings en `jsonb` en claro; `AddonSettingDef.Type` ∈ {text, number, boolean, select}; `utils.Encrypt` existe (usado en `org_integration.go` y `ai_provider.go`) con llave por defecto fija y relleno/truncado de `ENCRYPTION_KEY`.

Propuesta:
1. **Tipo `secret`** en `AddonSettingDef` (`write_only: true`).
2. **Cifrado de sobre:** DEK por organización envuelta por una llave maestra con **id y versión** (KMS o `ENCRYPTION_KEY` derivada con HKDF, nunca rellenada); AEAD con **AAD = org_id ‖ addon_key ‖ setting_key ‖ versión**; cifrado guardado como `{"$veil": "veil:1:…"}` (mismo sobre que §7) para que Veil y OPS compartan formato.
3. **API:** `GET` devuelve `{"set": true, "updated_at": …, "fingerprint": "<HMAC truncado>"}` para campos `secret`; `PUT` es solo escritura; el valor en claro solo existe en el runtime del addon en el servidor.
4. **Fallar cerrado:** sin `ENCRYPTION_KEY` en producción, OPS no arranca (eliminar la llave por defecto). Migración que re-cifra los `jsonb` existentes y rota la llave maestra.
5. **Auditoría** de lecturas en runtime y de escrituras.
6. **Veil:** el adaptador `http-api` de OPS pasa a usar el endpoint de solo escritura y deja de leer valores de vuelta; los addons de OPS pueden declarar sus secretos como destinatarios KMS de la org.
- Restricción: OPS es producción; cambios en ramas/worktrees de OPS, sin push, revisados por el dueño.

---

## 10. Pilar 6 — Cadena de suministro y calidad

| Tema | Propuesta | Criterio de aceptación |
|---|---|---|
| Releases firmados | **cosign keyless** (Sigstore, identidad OIDC del workflow) para binarios y contenedor de la Action; **minisign** como firma adicional verificable sin red. `veil self-verify`. | Cada artefacto tiene firma + certificado + entrada en Rekor; instrucciones de verificación en README. |
| Procedencia | SLSA nivel 3 con el generador oficial de GitHub **(verificar nivel alcanzable)**; npm con `--provenance` vía trusted publishing. | Procedencia verificable con `slsa-verifier` / `npm audit signatures`. |
| SBOM | CycloneDX (o SPDX) por artefacto (syft o `cyclonedx-gomod`), adjunto y firmado. | SBOM en cada release. |
| Compilaciones reproducibles | Go: `-trimpath`, `CGO_ENABLED=0`, `-buildvcs`, `SOURCE_DATE_EPOCH`, toolchain fijado; job que recompila y compara hashes. | Dos builds independientes producen el mismo hash. |
| Dependencias mínimas | Go: stdlib + `x/crypto` + `x/sys` + `filippo.io/age` + `fsnotify` + un parser TOML. TS: MCP SDK + zod (como hoy). Política: cada dependencia nueva requiere justificación en el PR. | Lista de dependencias directas ≤ 10 en Go. |
| CI endurecido | Acciones fijadas por SHA, `permissions` mínimas, Renovate/Dependabot, OpenSSF Scorecard, `govulncheck`, `pnpm audit`. | Scorecard ≥ 8 **(meta)**. |
| Fuzzing | `go test -fuzz` para parsers (cabecera, armadura, sobre, documento, política, tokenizador del escáner) en CI corto y nocturno largo; postular a OSS-Fuzz cuando haya usuarios **(requisitos a verificar)**. | 0 crashes en 24 h de fuzzing nocturno por objetivo. |
| Pruebas de propiedad | Go `testing/quick` o `rapid`; TS ya tiene PRNG propio. Propiedades: `decrypt(encrypt(x)) = x`, canonicalización idempotente, ningún valor en salidas/logs/IPC de error, re-cifrado estable. | Suite en CI. |
| Pruebas de conformidad | Vectores en `spec/vectors/` corridos por Go y TS; vectores de interoperabilidad con age. | 100 % de vectores pasan en ambas implementaciones. |
| Auditoría externa | **Alcance:** formato y suites, `core/keys`, IPC del daemon, hooks de agente, páginas locales, Action. Firmas posibles: Trail of Bits, NCC Group, Cure53, Radically Open Security, X41 **(cotizar)**. **Presupuesto:** orden de magnitud de 2–4 semanas-persona; **estimación** de USD 25k–80k, no es cotización. Fondos para OSS: OSTIF, Open Technology Fund, Sovereign Tech Fund **(verificar elegibilidad)**. | Informe público y hallazgos resueltos antes de 1.0. |
| Divulgación | Mantener `SECURITY.md` (ya existe); añadir `security.txt`, GHSA para avisos, CVE vía GitHub como CNA; recompensas solo si el modelo de negocio lo permite (decisión del dueño). | — |
| Versiones | SemVer para software; **versión de formato independiente** (`.veil` 1.x); garantía: cualquier Veil ≥ 1.0 lee todos los formatos 1.x; escritura del formato nuevo solo tras una versión menor de lectura (lectores primero). Soporte de seguridad: última menor + anterior desde 1.0. | Documento `VERSIONING.md` en F0. |

---

## 11. Modelo de amenazas ampliado

### 11.1 Adversarios

| ID | Adversario | Capacidades |
|---|---|---|
| A1 | Modelo confundido o con inyección de prompt | Pide cualquier herramienta; redacta acciones engañosas. |
| A2 | Agente con shell libre bajo el mismo usuario | Lee/escribe todo lo del usuario, lanza procesos, edita binarios y rc, usa red. |
| A3 | Malware del mismo usuario | Como A2, persistente y sigiloso. |
| A4 | Root/administrador local malicioso | Todo. |
| A5 | Proveedor del modelo / almacenamiento de transcripts | Lee todo lo que entra al contexto. |
| A6 | Proveedor de almacenamiento/sync/servidor de equipo | Ve blobs, metadatos públicos, tiempos, tamaños. |
| A7 | Atacante de red | Intercepta tráfico no TLS, DNS. |
| A8 | Colaborador del repo (pasado o actual) | Historial de git, PRs. |
| A9 | Cadena de suministro | Dependencias, CI, releases. |
| A10 | Ladrón del dispositivo (apagado / bloqueado) | Acceso físico al disco. |

### 11.2 Garantías

| Propiedad | A1 | A2/A3 | A4 | A5 | A6 | A8 | A10 |
|---|---|---|---|---|---|---|---|
| El modelo no recibe valores por herramientas de Veil | **Garantiza** (pruebas de propiedad) | n/a | — | **Garantiza** para lo que pasa por Veil | — | — | — |
| Valores no salen en claro por git/CI | **Previene** (hooks, Action) | **Detecta** (pre-push/Action; los hooks locales se saltan) | No | — | — | **Previene** a futuro; **no** limpia el pasado | — |
| Cifrado en reposo | — | **No** si la bóveda está desbloqueada o la llave no requiere presencia; **sí** con llaves de hardware con toque por uso | No | — | **Garantiza** confidencialidad; **no** oculta tamaño/tiempos/nombres de archivo | Garantiza para `.veil` | **Garantiza** si la llave está en hardware o la passphrase es fuerte |
| Atribución de quién pide un valor | Garantiza (vía broker) | **Evidencia, no prueba** (puede suplantar) | No | — | — | — | — |
| Detección de lectura de archivos en claro | — | **Parcial**: canarios sí; atribución solo con privilegios | No | — | — | — | — |
| Integridad del log | — | **Detecta** reescrituras anteriores al último ancla externa | No (salvo ancla externa) | — | Detecta (firmas) | — | — |
| Compartir con aprobación M-de-N | — | Garantiza que <M aprobadores no bastan (cripto) | — | — | Garantiza (cripto) | — | — |

### 11.3 Lo que NO se puede garantizar (lista explícita)

1. **Un agente o malware con shell libre bajo el mismo usuario (A2/A3)** puede: reemplazar el binario `veil` o los hooks, modificar `~/.bashrc` para interceptar `veil run`, leer los archivos en claro que el usuario deja (`secret_write`), leer el entorno de procesos hijos, registrar lo que el usuario teclea en el navegador, y pedir al usuario aprobaciones engañosas. Veil **reduce y detecta**; la frontera real es **otro usuario del SO, contenedor, VM o sandbox del kernel**.
2. **Root** lo ve todo (salvo llaves que nunca salen del hardware, y aun así puede usarlas mientras estén desbloqueadas).
3. **El historial de git** ya publicado no se "des-publica": se rota el secreto.
4. **Transformaciones arbitrarias** de un valor (cifrar, partir, codificar exótico) vencen a cualquier detector de exfiltración.
5. **Un secreto ya visto** por el modelo, un colaborador o un proveedor no se puede revocar de su memoria: solo rotar.
6. **Los canarios de formato de proveedor** (Stripe falso, etc.) no alertan si se usan contra el proveedor.
7. **El proxy de salida** no ve tráfico que lo evita ni TLS con pinning.
8. **Metadatos:** tamaño, tiempos, cantidad de destinatarios (si no se usa modo anónimo) y nombres de archivo son visibles para A6.
9. **Memoria:** en Go y en JS no hay borrado garantizado de memoria; se reduce exposición (mlock, vida corta), no se elimina.
10. **Telemetría privilegiada** depende de que el usuario la instale y la mantenga; en macOS depende además de un entitlement de Apple.

THREAT-MODEL.md se reescribe en F0 con esta estructura (los §1–§7 actuales siguen siendo válidos para el MCP).

---

## 12. Métricas y cómo medirlas

| Métrica | Definición | Meta inicial | Cómo se mide |
|---|---|---|---|
| Recall de valores conocidos | % de apariciones de valores de la bóveda (y variantes soportadas) detectadas | ≥ 99,5 % | Corpus sintético que incrusta valores y variantes en archivos reales de OSS. |
| Recall de proveedores | % de tokens sintéticos válidos por proveedor detectados | ≥ 95 % por proveedor con checksum; ≥ 85 % sin checksum | Generadores por proveedor en `bench/corpus/positives`. |
| Falsos positivos | Hallazgos en negativos difíciles por 10 000 archivos | ≤ 1 (detectores de huella/proveedor); ≤ 10 (entropía) | `bench/corpus/negatives` (lockfiles, hashes, UUIDs, fixtures de N repos OSS fijados por commit). |
| Comparativa | Precisión/recall en el mismo corpus vs. gitleaks y trufflehog (sin verificación) | Informativo | Mismo arnés; publicar resultados con versión de cada herramienta. Considerar datasets académicos de secretos **(verificar disponibilidad y licencia, p. ej. SecretBench)**. |
| Latencia pre-commit | p50/p95 de `veil hook pre-commit` en diff de 20 archivos / 200 KB | p95 < 300 ms (sin daemon), < 100 ms (con daemon) | `bench/latency` en CI con runners fijos. |
| Throughput de escaneo | MB/s en repo completo | ≥ 50 MB/s por núcleo | Igual. |
| Vigía en reposo | CPU media del daemon sin actividad | < 1 % | Prueba de 1 h. |
| Tiempo de alerta canario local | Apertura del señuelo → notificación | < 2 s | Prueba E2E. |
| Fugas al modelo | Valores en cable JSON-RPC, logs, IPC de error | **0** | Pruebas de propiedad existentes extendidas al daemon. |
| Robustez de parsers | Crashes en fuzzing | 0 en 24 h por objetivo | Nocturno. |
| Tiempo de rotación | Detección → secreto rotado y desplegado (playbooks automatizables) | < 5 min con `rotate:ask` | Simulacros con APIs simuladas. |
| FP percibidos | `veil allow` por semana / hallazgos totales (local, opt-in para compartir) | < 5 % | Contador local. |

---

## 13. Roadmap por fases

Convenciones: una rama por PR, worktree por agente, sin force-push, merge (no rebase) en ramas publicadas, commits en español. **Dueño de archivos** = el único agente que puede modificar esos paths en esa fase; los demás solo leen. Las fases se pueden solapar cuando no comparten dueños.

### F0 — Fundaciones (1–2 semanas)

| PR / rama | Dueño de archivos | Contenido | Aceptación |
|---|---|---|---|
| `chore/rename-veil` | `package.json`, `src/**` (solo cadenas), `examples/**`, `e2e/**`, `test/**` | Renombrado con compatibilidad (§2.2). README lo actualiza `docs/readme-visuals`. | Tests verdes; se leen `VEILFORM_*`, `~/.config/veilform`, servicio de llavero `veilform` y archivos con `CHECK` v1. |
| `chore/monorepo` | raíz, `packages/mcp/**` (mueve `src/`), `core/` (esqueleto), `cmd/` | Estructura §4.2, `go.mod`, workspace pnpm. | CI corre Go y TS. |
| `ci/supply-chain` | `.github/workflows/**`, `VERSIONING.md` | SHA pins, Scorecard, goreleaser en seco, SBOM, cosign en seco. | Release candidato firmado en un fork/tag de prueba. |
| `docs/threat-model-v2` | `THREAT-MODEL.md`, `SECURITY.md` | §11. | Revisión del dueño. |
| `spec/format-v1-draft` | `spec/**` | Mover `docs/FORMAT-VEIL-SPEC.md` a `spec/`, esquema de política. | Revisión criptográfica interna. |

### F1 — Escáner, política y guardia de agentes (2–4 semanas) — *valor inmediato*

| PR / rama | Dueño | Contenido | Aceptación |
|---|---|---|---|
| `feat/scan-core` | `core/scan/**`, `bench/**` | Detectores, tokenizador, huellas HMAC, Bloom, SARIF, corpus y arnés. | Metas de §12 en el corpus v0. |
| `feat/policy` | `core/policy/**`, `spec/policy.schema.json` | Parser, validación, excepciones con caducidad. | Fuzz del parser; `veil policy check`. |
| `feat/git-hooks` | `cmd/veil/git*.go`, `core/gitx/**` | pre-commit/pre-push/commit-msg, instalación encadenada. | p95 < 300 ms; prueba con pre-commit/lefthook/husky. |
| `feat/agent-guard` | `cmd/veil/hook_*.go`, `core/agents/**` | Hooks `PreToolUse`, `UserPromptSubmit`, `PostToolUse`; `veil agent setup claude`; `veil sweep --agents/--history`. | Pruebas con JSON real de hooks; pegar un token en el prompt se bloquea; lectura de `.env` vía Read/cat/grep denegada en 20 variantes de prueba (y se documentan las que pasan). |
| `feat/mcp-fingerprints` | `packages/mcp/src/redact.ts`, `vault.ts` | El MCP alimenta huellas al motor (CLI hasta que exista daemon). | Pruebas de propiedad. |

### F2 — Formato `.veil` v1 (3–5 semanas)

| PR / rama | Dueño | Contenido | Aceptación |
|---|---|---|---|
| `feat/format-core` | `core/format/**`, `core/suites/**` | Cabecera, TLV, STREAM, X25519, passphrase (Argon2id/scrypt), armadura, metadatos cifrados, firma. | 100 % vectores; fuzz 24 h; revisión por segundo agente "rojo". |
| `feat/format-vectors` | `spec/vectors/**`, `packages/node/src/verify/**` | Vectores y verificador TS de cabecera. | Fuzz diferencial Go↔TS sin discrepancias. |
| `feat/verify-cli` | `cmd/veil/verify.go`, `encrypt.go`, `decrypt.go` | `veil encrypt/decrypt/verify/inspect`. | — |
| `feat/migrate-v1` | `core/migrate/**` | `encrypted-file` v1 → `.veil`. | Archivos v1 reales de prueba migran sin pérdida; rollback documentado. |
| `feat/interop-age` | `core/interop/age/**` | import/export age. | Ida y vuelta con `age` CLI. |
| **Coordinación** | — | Revisión cruzada con `feat/vault-sync-share`: destinatarios de §5 reutilizables en `#/recipient`, prefijos renombrados, vectores de `.env` v1 aportados por esa rama. | Acuerdo explícito en ambos PRs. |

### F3 — Auto-cifrado y CI (2–3 semanas)

| PR / rama | Dueño | Contenido | Aceptación |
|---|---|---|---|
| `feat/git-filter` | `core/gitx/filter/**` | clean/smudge/textconv/merge con re-cifrado estable. | Ningún diff espurio en 1 000 commits simulados; merge sin conflictos de MAC en casos de prueba. |
| `feat/env-doc-v1.1` | `core/format/envdoc/**` (Go) + coordinación con dueños de `src/envenc/**` | Port a Go de `veilform-env v1` (lectura/escritura idéntica a la de la rama hermana) + destinatarios asimétricos v1.1. | Vectores cruzados TS↔Go byte a byte. |
| `feat/run` | `cmd/veil/run.go` | `veil run`, `veil ci mask`. | Valores nunca en argv; prueba con `ps`. |
| `feat/action` | `action/**` | GitHub Action + SARIF. | Bloquea PR de prueba con secreto; tiempo < 30 s en repo mediano. |
| `feat/guard-docker` | `core/exits/**` | Contexto Docker, `veil guard` para s3/rsync/scp. | Corpus de contextos. |
| `feat/interop-sops-dotenvx` | `core/interop/{sops,dotenvx}/**` | Importación. | Archivos de ejemplo de cada herramienta. |

### F4 — Broker, atribución, canarios y log (4–6 semanas)

| PR / rama | Dueño | Contenido | Aceptación |
|---|---|---|---|
| `feat/daemon-ipc` | `cmd/veild/**`, `core/ipc/**` | Evolución del agente de sesión de la rama hermana: socket/pipe, credenciales del par, árbol, endurecimiento, misma API de caché. | Atribución correcta de `claude`→`bash`→`veil get` en pruebas; `ptrace` del mismo usuario falla. |
| `feat/mcp-client` | `packages/mcp/src/stores/**`, `vault.ts` | MCP usa el daemon. | E2E existentes verdes. |
| `feat/watch-clipboard` | `core/watch/**` | Vigía y portapapeles. | CPU < 1 %. |
| `feat/canaries` | `core/canary/**` | Locales + registro en huellas + integración Canarytokens. | Alerta < 2 s. |
| `feat/alerts` | `core/alert/**`, `packages/mcp/src/ui/**` (página de alertas) | Canales §6.7. | Webhook firmado verificable. |
| `feat/audit-merkle` | `core/audit/**` | Merkle, checkpoints firmados, anclas, import del JSONL. | Reescritura detectada tras ancla. |
| `feat/agent-sandbox` | `core/sandbox/**` | `veil agent run` (bwrap/Landlock/Seatbelt). | El agente no puede listar la bóveda; MCP sigue funcionando. |

### F5 — Custodia (4–6 semanas)

`feat/keys-hw` (plugins age: YubiKey, TPM, SE, FIDO2), `feat/keys-kms` (AWS/GCP/Vault Transit/OpenBao), `feat/keys-shamir` (grupos umbral, papel), `feat/keychain-windows`, `feat/rotate-revoke`. Aceptación: cada custodia con pruebas en hardware real documentadas (matriz de dispositivos) y simuladores en CI.

### F6 — Equipo, OPS, CI sin humanos (6–8 semanas)

`feat/team-server` (servidor ciego, directorio con transparencia), `feat/approvals-mofn`, `feat/audit-central`, `feat/ci-oidc`, y en el repo de OPS: `feat/addon-secret-settings` (§9.5, dueño: agente de OPS, revisado por el dueño). Aceptación: el servidor de equipo nunca recibe un valor (prueba de propiedad sobre todo su tráfico); OPS: `GET` enmascara, sin llave por defecto.

### F7 — Avanzado (continuo)

`feat/sentinel-linux` (fanotify/auditd privilegiado), `feat/etw-windows`, `feat/playbooks` (AWS, DB, SSH primero; GitHub/Stripe/Mercado Pago vía flujo web), `feat/egress-proxy`, `feat/pq-hybrid` (experimental), `feat/vscode`.

### 1.0

Auditoría externa con hallazgos resueltos; formato `.veil` 1.0 congelado; métricas de §12 publicadas; política de soporte vigente.

### Reglas para agentes en paralelo

- Un agente por fila; worktree propio; nunca editar archivos fuera de su columna "Dueño".
- Cambios a `spec/**` solo por el dueño de la spec; los demás abren issue/PR de propuesta.
- Cada PR de criptografía tiene un **segundo agente revisor** con instrucción adversarial y la lista de vectores negativos.
- Commits en español, sin líneas de atribución, sin push hasta que el dueño lo pida.

---

## 14. Riesgos

| Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|
| Formato propio con un error criptográfico | Media | Muy alto | Construcción de age, vectores, fuzz, revisión adversarial, auditoría antes de 1.0, bandera `experimental` hasta entonces. |
| Fatiga por falsos positivos → usuarios desactivan hooks | Alta | Alto | Huellas primero, entropía conservadora, excepciones fáciles con caducidad, medición §12. |
| Confusión del nombre "Veil" con herramienta ofensiva; antivirus que marcan el binario | Media | Medio | Verificar antes de D1; firmas de código; reputación en Microsoft SmartScreen. |
| Dos lenguajes elevan costo de mantenimiento | Media | Medio | Un solo lugar para criptografía (Go); TS solo cliente y verificador. |
| Divergencia con `feat/vault-sync-share` | Media | Alto | Punto de alineación §1.3 antes de congelar bytes. |
| Falsa sensación de seguridad frente a A2 | Alta | Alto | Mensajes honestos en UI y docs; `veil doctor` que dice qué capas están activas y cuáles no. |
| Dependencia de plugins age de terceros para hardware | Media | Medio | Fijar versiones, verificar firmas, alternativa nativa en Go para YubiKey/TPM si se abandonan. |
| Entitlement de Endpoint Security no concedido | Alta | Bajo | No depender de él. |
| Aumento de superficie del daemon (IPC) | Media | Alto | Protocolo mínimo, fuzz del IPC, socket 0600, auditoría. |
| Cambios de API de Claude Code (hooks) | Media | Medio | Pruebas de contrato con fixtures de JSON de hooks; versión mínima soportada documentada. |

---

## 15. Decisiones SOLO del dueño

1. **Nombre** (Veil / alternativo), y si se renombra el repo de GitHub ahora.
2. **Licencia:** MIT actual vs. Apache-2.0 (concesión explícita de patentes, común en herramientas de seguridad) vs. AGPL para el servidor de equipo (protege contra SaaS cerrado) / modelo dual. Afecta qué código ajeno se puede reutilizar (p. ej. no se puede copiar código AGPL a un núcleo MIT).
3. **Modelo de negocio / OSS:** todo abierto; núcleo abierto + servidor de equipo alojado de pago; o abierto con soporte. Define si existen servidores de canarios/verificación operados por Asteby.
4. **Alcance de telemetría:** recomendado **ninguna por defecto**; opt-in explícito para métricas agregadas de falsos positivos. Nunca valores, rutas ni nombres de secretos.
5. **Lenguaje del núcleo** (D2): Go + TS vs. todo TS.
6. **Formato propio vs. age** (D3).
7. **Comportamiento por defecto** (D4/D5): sin texto plano en el árbol y bloqueo por defecto.
8. **Servicios operados por Asteby:** canarios DNS/HTTP, servidor de equipo, ancla de logs. Costo, privacidad y responsabilidad legal.
9. **Presupuesto y momento de la auditoría externa**; programa de recompensas sí/no.
10. **Prioridad del arreglo en OPS** (§9.5) frente al roadmap de Veil.
11. **Componentes privilegiados** (root/drivers/entitlements): ¿se ofrecen?
12. **Plataformas oficiales** en 1.0 (¿Windows desde el inicio?).

---

## 16. Datos por verificar

Antes de citarlos en documentación pública: versión de Node con Argon2 y ML-KEM; estado del soporte post-cuántico en age; licencia de la acción de gitleaks para organizaciones y licencia de trufflehog; modelo de cifrado actual de Infisical; soporte multi-llave de dotenvx; driver de merge de sops; qué son exactamente BlindKey, OneCLI y nono; marcador de entorno `CLAUDECODE` y ruta de transcripts de Claude Code; combinación del sandbox de Claude Code con reglas de lectura; comportamiento de fanotify sin privilegios respecto al pid; estado de `sandbox-exec` en macOS; API de revocación de credenciales de GitHub; APIs de rotación de Stripe y Mercado Pago; umbral de Linguist; matriz de soporte de WebAuthn PRF; estado de los plugins age (YubiKey, TPM, SE, FIDO2); estado del borrador X-Wing; nivel SLSA alcanzable; elegibilidad para OSS-Fuzz y fondos de auditoría; marca "Veil" y "Veil Framework"; choques del binario `veil`.

---

## 17. Apéndices

### Apéndice A — Ejemplo de `.veil/policy.toml`

```toml
version = 1
default_action = "block"            # block | auto-encrypt | warn

[[protect]]
paths   = [".env", ".env.*", "!.env.example"]
format  = "dotenv"
action  = "auto-encrypt"
recipients = ["team:backend", "ci:github-oidc", "recovery"]
smudge  = "keep-encrypted"          # keep-encrypted | decrypt (opt-in)

[[protect]]
paths  = ["**/*.pem", "**/id_*", "!**/*.pub", "**/*.sql", "**/*.dump"]
action = "block"

[scan]
detectors = ["known-values", "providers", "entropy", "canaries"]
entropy   = { base64_min_bits = 4.3, hex_min_bits = 3.0, min_len = 20 }
verify_online = false               # verificación en vivo, solo CI y opt-in

[[scan.allow]]
fingerprint = "fp1:3f9a0c…"         # nunca el valor
reason  = "fixture de pruebas públicas"
expires = "2027-01-01"

[agents]
deny_read = [".env*", "**/*.veil", "~/.ssh/**", "~/.config/veil/**"]
deny_bash = ["printenv", "env", "secret-tool", "security"]
sandbox   = "recommended"           # off | recommended | required

[response]
on_leak   = ["alert", "freeze-shares", "rotate:ask"]
alert     = ["desktop", "webhook:ops-alerts"]

[verify]
required_recipients = ["recovery"]
require_signature   = false
```

### Apéndice B — Hook `PreToolUse` de Claude Code (forma)

```json
{
  "hooks": {
    "PreToolUse":       [{ "matcher": "Read|Edit|Grep|Glob|Bash", "hooks": [{ "type": "command", "command": "veil hook claude-pretooluse" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "veil hook claude-prompt" }] }],
    "PostToolUse":      [{ "matcher": "*", "hooks": [{ "type": "command", "command": "veil hook claude-posttooluse" }] }]
  }
}
```

Salida de denegación (stdout del hook):

```json
{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny",
  "permissionDecisionReason": "Ruta protegida por Veil (.env). Usa secret_use con ${secret:NOMBRE}." } }
```

### Apéndice C — Glosario

**Huella:** HMAC truncado de un valor (o variante) con llave local. **Broker:** `veild`, único proceso que entrega valores. **Canario:** valor o archivo señuelo cuyo uso o lectura alerta. **Sobre por valor:** cifrado de un solo valor dentro de un documento legible. **Grupo umbral:** destinatario compuesto que requiere M de N partes.
