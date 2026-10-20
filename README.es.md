# veilform

**Que un agente de IA pida, guarde y use credenciales sin verlas jamás.**

[English](README.md) · [Modelo de amenazas](THREAT-MODEL.md) · [Política de seguridad](SECURITY.md) · [Cambios](CHANGELOG.md)

`veilform` es un servidor [MCP](https://modelcontextprotocol.io) de código abierto (stdio, TypeScript). Cuando el agente necesita una API key, una contraseña o cualquier dato sensible, manda **solo metadatos** (el esquema de un formulario). Se abre en tu navegador una página servida en `http://127.0.0.1`; escribes ahí los valores y van directo al destino que configuraste (llavero del sistema, archivo cifrado, `.env`, servidor remoto por SSH, Vault/Infisical/1Password/OPS, una API HTTP, una tabla de Postgres…). El agente solo recibe `{request_id, status, stored:[nombres]}`.

Después el agente escribe `${secret:STRIPE_KEY}` y este servidor lo resuelve **dentro de su propio proceso, en el momento de usarlo**, después de que apruebas la acción exacta en otra página local.

## Herramientas

| Herramienta | El modelo manda | El modelo recibe |
|---|---|---|
| `secret_request` | título, campos (`secret`/`text`/`select`/`textarea`), destino | `{request_id, status, stored}` |
| `blind_input` | esquema rico (secciones, número/moneda/fecha/select/multiselect/booleano/archivo, condiciones `showIf`, tablas repetibles con importación CSV o pegado desde hoja de cálculo) + sink (`store`, `http`, `sql`, `file`, `ops-dataload`, `callback`) | `{status, rows_written, ids, field_errors:[{field, code}]}` |
| `blind_input_preview` | esquema (+ sink) | validación + URL local con maqueta sin valores |
| `secret_list` / `secret_delete` / `secret_rotate` | nombre / filtros | nombres + metadatos (creado, último uso, caducidad, rotación pendiente, etiquetas, proyecto) |
| `secret_use` | `exec` (argv o shell aprobado) / `http`, con `${secret:nombre}` | código de salida + salida **redactada** |
| `secret_write` | nombres + destino (`env-file` local/SSH, `json`, `yaml`, `systemd`, `github`, `clipboard`), `dry_run` | `{written, target, keys:[{key, action: created/updated}]}` |
| `secret_wait` | id | resultado estructural final |
| `web_capture` / `web_login` | sitio, pasos (`navigate/click/wait/fill/press`), extractor | `{stored:[nombre]}` o `{failed_step, error_code}` — nunca texto de la página |
| `ssh_key_provision` / `ssh_exec` | host, alias de llave / comando + env con `${secret:x}` | huellas y prueba de acceso / salida redactada |

## Instalación

Requisitos: Node ≥ 20.11 — nada más. Se usa el llavero del sistema cuando funciona (Linux: `secret-tool` del paquete `libsecret-tools` + GNOME Keyring/KWallet; macOS: `security`); si no funciona, Veil usa su propio almacén cifrado y no hace falta instalar nada (ver [Primer uso](#primer-uso)). Opcionales: `playwright-core` + Chromium (`web_capture`), `psql` (sinks SQL), `gh` (secretos de GitHub), OpenSSH. `veilform doctor` dice exactamente qué falta y el comando para instalarlo.

```bash
pnpm install && pnpm build
claude mcp add veilform -- node /ruta/a/veilform/dist/cli.js
# cuando esté publicado:  claude mcp add veilform -- npx -y veilform
```

## Primer uso

```bash
npx veilform init          # publicado como @asteby/veil: npx @asteby/veil init
```

`init` ejecuta el diagnóstico, muestra un plan y, cuando confirmas (`--yes` para no preguntar, `--dry-run` para solo verlo), aplica **solo cambios de tu usuario**: crea `~/.config/veilform` (0700), corrige permisos y escribe un `config.json` cuyo destino por defecto **funciona sin instalar nada**:

- Llavero del sistema utilizable → `local` = llavero con `fallback: "auto"` (si el llavero falla después, los valores van al almacén cifrado de Veil).
- Llavero ausente, bloqueado o no soportado → `local` = almacén cifrado de Veil (`encrypted-file` con `key: {source: "master"}`, archivo `~/.config/veilform/local-vault.json`).

Nunca ejecuta `sudo` ni pide secretos. Los comandos que necesitan privilegios (p. ej. `sudo apt install -y libsecret-tools`) se imprimen para que los copies. El `postinstall` opcional solo muestra una pista; con `VEILFORM_POSTINSTALL=init` ejecuta `init --dry-run` al instalar.

**El almacén cifrado de Veil** es un solo archivo en el formato `encrypted-file` existente: AES-256-GCM por valor (el nombre va como AAD), llave derivada con argon2id (Node ≥ 24.7; si no, scrypt N=2^17) de una **contraseña maestra**:

1. La primera vez que un valor tiene que ir ahí, la página local (127.0.0.1) te pide **definir la contraseña maestra ahí mismo** — nunca en el chat, en argumentos MCP ni en argv. También puedes hacerlo antes: `veilform unlock`, `veilform init --master` o la herramienta MCP `local_unlock`.
2. Al desbloquear solo se guarda en memoria la **llave derivada**: en el agente de sesión (`veilform agent`) si está activo — entonces todos los procesos de Veil la comparten y `veilform lock` la olvida — o dentro del proceso MCP durante `localVault.unlockMinutes` (15 por defecto).
3. Más adelante, cuando el llavero funcione, puedes guardar ahí la llave derivada para abrir el almacén sin escribir la contraseña: `veilform unlock --save-keychain` (`--forget-keychain` lo deshace). `veilform unlock --change-password` vuelve a cifrar todo con otra contraseña.
4. Nunca se escribe texto plano en disco; los valores y la contraseña maestra se registran en la lista de borrado antes que nada y nunca llegan a respuestas, logs ni a la auditoría.

> **Si olvidas la contraseña maestra los datos no se pueden recuperar** — es intencional, no hay puerta trasera. Guárdala en tu gestor de contraseñas o en papel y respalda `local-vault.json` (sin la contraseña no sirve de nada). Para una copia cifrada fuera de la máquina usa `veilform export` / `vault_sync`.

Si el destino por defecto es el llavero y falla durante un `secret_request`, la página **ofrece continuar con el almacén cifrado** (pidiendo — o creando — la contraseña maestra en esa misma página) en vez de fallar, y muestra el comando exacto para arreglar el llavero de forma permanente. Pon `fallback: "never"` en un destino `keychain` para prohibirlo.

## Solución de problemas

Ejecuta `veilform doctor` (o la herramienta MCP de solo lectura `doctor`; `--json` para máquinas). Revisa Node/cripto (argon2id), el backend de llavero (secret-tool, sesión D-Bus, proveedor de Secret Service y si el llavero por defecto está desbloqueado en Linux; `security` en macOS; en Windows el backend de Credential Manager está previsto y se usa el almacén cifrado), el destino por defecto, el almacén cifrado y el agente de sesión, los permisos de `~/.config/veilform`, y ssh/git/gh/psql/Chromium para las funciones que los usan. Cada problema trae su impacto y el comando exacto para tu distribución (apt, dnf, pacman, zypper, apk, brew, winget). No ejecuta nada con privilegios ni pide nada secreto.

Los errores son estructurados — `{error, code, help:{en,es}, fix:{en,es,command, alternative}}` — en las respuestas MCP, y traducidos en la página local:

| Código | Qué pasa | Arreglo |
|---|---|---|
| `keychain_unavailable` | `secret-tool` no instalado (`reason: missing_tool`), sin sesión D-Bus (`no_dbus`, SSH/sin escritorio) o sin Secret Service (`no_service`) | `sudo apt install -y libsecret-tools` (o dnf/pacman/…), `dbus-run-session -- $SHELL`, `gnome-keyring-daemon --start --components=secrets` — o `veilform init` |
| `keychain_locked` | el llavero está bloqueado o esperando un diálogo de desbloqueo | desbloquea "Inicio de sesión" en Contraseñas y claves (`seahorse`); macOS: `security unlock-keychain` |
| `keychain_unsupported` | aún no hay backend de llavero en este SO (Windows) | `veilform init` (almacén cifrado) |
| `passphrase_required` | el almacén cifrado está bloqueado | MCP `local_unlock` o `veilform unlock` |
| `master_password_not_set` | el almacén cifrado aún no tiene contraseña maestra | defínela en la página local (`veilform unlock`) |
| `destination_not_configured` | el destino no está en `config.json` | `veilform init` o agrégalo |
| `wrong_key` / `too_many_attempts` | contraseña maestra incorrecta / bloqueo temporal tras 5 fallos | reintenta más tarde |

Variables opcionales: `VEILFORM_HOME` (por defecto `~/.config/veilform`), `VEILFORM_CONFIG`, `VEILFORM_AGENT` (etiqueta que se escribe en la auditoría).

La configuración es una **allowlist**: copia [`examples/config.example.json`](examples/config.example.json) a `~/.config/veilform/config.json` y deja solo lo necesario. Sin archivo hay un único destino, `local` (llavero del SO con `fallback: "ask"`: si el llavero falla, la página ofrece el almacén cifrado de Veil). Verifícala con `veilform check-config` y `veilform doctor`.

Endurecimiento recomendado en Claude Code (`.claude/settings.json`): niega a las herramientas propias del agente lo que este servidor protege, p. ej. `"deny": ["Read(~/.config/veilform/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

## Ejemplos

**Llave de Stripe y una llamada:** `secret_request({title:"Stripe", fields:[{name:"STRIPE_KEY", label:"Llave secreta"}]})` → la pegas en la página local → `secret_use({action:"http", url:"https://api.stripe.com/v1/balance", headers:{Authorization:"Bearer ${secret:STRIPE_KEY}"}})` → la página de aprobación muestra exactamente esa petición → `{http_status:200, body:"…"}` (si la API repite la llave, sale como `[REDACTED:STRIPE_KEY]`).

**Token de Mercado Pago al `.env` de producción por SSH:**
`secret_write({name:"MP_ACCESS_TOKEN", target:{kind:"env-file", host:"prod-vps", path:"/etc/myapp/myapp.env", key:"MP_ACCESS_TOKEN"}, dry_run:true})` → `{changes:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}`. Sin `dry_run`, tras tu aprobación (la primera vez por destino), cambia solo esa clave conservando comentarios y el resto, sube el archivo por stdin a un temporal, `chmod 0600`, `chown`/respaldo opcionales y `mv` atómico. El modelo recibe `{written:true, target, keys}`.

**Sacar el token del panel de Mercado Pago sin que el modelo lo vea:** `web_capture({site:"mercadopago", name:"MP_ACCESS_TOKEN", steps:[{wait:"text=Credenciales de producción", timeout_ms:600000},{click:"text=Mostrar"}], extract:{selector:"[data-testid=access-token]", regex:"(APP_USR-[\\w-]+)"}})`. Se abre una ventana de Chromium **propia del MCP**; **tú** inicias sesión (contraseña y 2FA nunca pasan por el modelo); puedes ajustar los pasos en la página de aprobación; el valor va del DOM al almacén.

**Llave SSH para un VPS nuevo:** `ssh_key_provision({host:"prod-vps", alias:"deploy_key", password:true})` → la página muestra la huella del host para compararla con tu proveedor, pide la contraseña de un solo uso, instala la llave pública y prueba el acceso. Luego `ssh_exec({host:"prod-vps", command:"systemctl restart myapp"})`.

**Precios USD de una tienda en lote:** `blind_input` con una tabla `rows:[sku, price(money USD)]` y sink `{type:"sql", database:"appdb", table:"public.product_prices", mode:"upsert", rows:"rows", columns:{sku:"${sku}", price_usd:"${price}", list:"mayoreo"}, dry_run:true}`. Pegas las filas desde Excel/Sheets; los valores viajan como datos de `COPY … FROM STDIN` a una tabla temporal tipada y un `INSERT … SELECT` en una sola transacción (nunca como texto SQL). El modelo recibe `{rows_validated:120}` y luego `{rows_written:120, ids:[…]}`.

**Credenciales de pago:** `secret_request` con destino `ops-mercadopago` (adaptador `ops-addon-settings`) o `infisical`: el valor va del navegador al almacén remoto, servidor a servidor.

**Datos sensibles de clientes:** `blind_input` con `nombre, email, rfc (pattern), teléfono` y sink `http` a tu CRM; el modelo solo recibe los ids creados.

## Flujo de seguridad

1. El modelo llama con metadatos. Destinos, hosts, rutas, tablas y sitios deben estar en tu configuración.
2. El enlace de un solo uso `http://127.0.0.1:<puerto>/p/<token de 256 bits>` llega por **elicitation por URL de MCP** si el cliente la soporta; si no, se devuelve para que el cliente/agente lo muestre (y se abre con `xdg-open`/`open` si `ui.openBrowser`). El primer navegador que lo abre lo amarra con una cookie HttpOnly; caduca en 10 min.
3. Llenas o apruebas. Token CSRF + verificación de Origin/Host + CSP estricta con nonce; nada de terceros; sin autocompletado.
4. Los valores van al destino desde este proceso (stdin/env, nunca argv; nunca en logs).
5. Las respuestas son estructurales; un filtro final elimina cualquier valor manejado y sus codificaciones.
6. Cada uso queda en la auditoría (JSONL encadenado por hash: sesión, agente, cliente, acción, huella, nombres). `veilform verify-audit` verifica la cadena.

Lee [THREAT-MODEL.md](THREAT-MODEL.md) para lo que **no** se protege — en particular: un comando aprobado que exfiltre el valor, malware con tu mismo usuario, y **usar otro navegador que el modelo sí ve** (p. ej. una extensión de navegador manejada por el agente) para abrir una página que muestra un secreto. **Cuándo NO usar un navegador visible para el modelo:** en paneles de credenciales (Mercado Pago, Stripe, WooCommerce, hosting) y en cualquier página que muestre llaves, tokens o datos personales; usa `web_capture`/`web_login`.

## Desarrollo

```bash
pnpm install
pnpm typecheck && pnpm lint && pnpm test
pnpm test:e2e
```

Desviaciones del diseño original (documentadas): el llavero usa los CLI del sistema en lugar de `@napi-rs/keyring`; `encrypted-file` usa AES-256-GCM + scrypt de Node en lugar de age/libsodium; las pruebas de propiedades usan un PRNG con semilla en lugar de `fast-check`. Las tres porque había que construir sin red con las dependencias en caché, y así las dependencias de ejecución son solo el SDK de MCP y zod.

## Licencia

[MIT](LICENSE)

## Sync y compartir

*(respaldo/sincronización cifrados, compartir por token y archivos `.env` cifrados — añadido en 0.2.0)*

**Nuevas herramientas MCP** (devuelven solo nombres, conteos e ids; las passphrases y los tokens se escriben/muestran en la página local):

| Herramienta | Qué hace |
|---|---|
| `vault_export` / `vault_sync` / `vault_import` / `vault_rekey` | Bundle cifrado de la bóveda a un archivo `.vfb` o a un destino; restauración con integridad, anti-rollback y detección de conflictos; rotación de la KEK |
| `share_create` / `share_list` / `share_revoke` / `share_import` | Compartir secretos elegidos por token (caducidad, máximo de lecturas, passphrase opcional); revocar (+ rotar); importar a ciegas en la bóveda de otro agente |
| `env_status` / `env_unlock` / `env_encrypt` / `env_edit` / `env_diff` / `env_rotate` | `.env` cifrados aptos para git; `secret_use({env_file})` y `secret_write({from:{kind:"env-enc"}})` los usan sin que el modelo vea valores |

**Bundle** (`manifest.json` + `o/<id aleatorio>` por secreto, o un solo `.vfb`): una llave de datos (DEK) AES-256-GCM aleatoria por secreto, envuelta por una KEK = HKDF(argon2id/scrypt(passphrase) ‖ archivo de llave / llavero opcional). Nombres y metadatos viven solo en el índice cifrado; la cabecera (versión, id del bundle, `seq` monótono, parámetros de llave, sha256 de cada objeto) es el AAD del índice: bundles con objetos intercambiados, truncados, editados o antiguos (rollback) se rechazan. Cada secreto lleva un reloj vectorial: `vault_sync` nunca sobrescribe en silencio un cambio concurrente (`strategy`: `report`, `keep-local`, `take-remote`, `keep-both`).

**Destinos** (`sync.targets` en la config, lista permitida): `dir`, `ssh` (host de `ssh.hosts`), `git` (repo privado; `git` por argv, credenciales de tu ssh-agent/credential helper), `s3` (S3/R2/MinIO, SigV4 propio), `webdav`, `http`. Las credenciales de los destinos son referencias al almacén local (`tokenRef`, `accessKeyRef`…), nunca en línea. Ejemplo de configuración en la sección en inglés.

**Token** = `vfs1://<destino>/<share_id>#<llave>` — la llave va en el fragmento de la URL (nunca se envía a un servidor). Con `require_passphrase` el bundle se cifra con HKDF(llave ‖ argon2id(passphrase)); la caducidad y el máximo de lecturas van en la cabecera autenticada. Una persona lo abre con `veilform share open` (página local, token en el fragmento o pegado, valores ocultos de nuevo a los N s); otro agente usa `share_import({token_file})` y después `secret_use`.

**`.env` cifrado** (cabecera `#/veilform-env v1`, `CLAVE="enc:v1:…"` por valor, comentarios/orden conservados, MAC de todo el archivo, N destinatarios):

```bash
veilform env keygen ~/.config/veilform/keys/miapp.key        # 0600, fuera del repo
veilform env encrypt .env.production --key-file ~/.config/veilform/keys/miapp.key   # + passphrase por TTY
veilform env hook install                                     # el pre-commit rechaza .env en claro
veilform run --env .env.production -- node server.js           # valores solo en el entorno del hijo; salida redactada
veilform env unlock .env.production --status                  # qué métodos de desbloqueo sirven aquí (sin valores)
veilform env share .env.production --expires 1h --max-views 1 # token que desbloquea SOLO este archivo
```

Métodos de desbloqueo: archivo de llave (`--key-file`, `VEILFORM_KEY_FILE`, `env.keyFiles`), llavero del SO (`env.keychain`), credencial de systemd (`LoadCredential=veilform-key:…`, ver [`examples/systemd/`](examples/systemd/)), agente de sesión (`veilform agent`, `veilform lock`), passphrase (TTY o página local, intentos limitados), token de compartir. Límites y comparación con age/sops/1Password/Vault: [THREAT-MODEL.md §8](THREAT-MODEL.md#8-sync-sharing-and-encrypted-env-files).
