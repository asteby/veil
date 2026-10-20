# secret-intake-mcp

**Que un agente de IA pida, guarde y use credenciales sin verlas jamás.**

[English](README.md) · [Modelo de amenazas](THREAT-MODEL.md) · [Política de seguridad](SECURITY.md) · [Cambios](CHANGELOG.md)

`secret-intake-mcp` es un servidor [MCP](https://modelcontextprotocol.io) de código abierto (stdio, TypeScript). Cuando el agente necesita una API key, una contraseña o cualquier dato sensible, manda **solo metadatos** (el esquema de un formulario). Se abre en tu navegador una página servida en `http://127.0.0.1`; escribes ahí los valores y van directo al destino que configuraste (llavero del sistema, archivo cifrado, `.env`, servidor remoto por SSH, Vault/Infisical/1Password/OPS, una API HTTP, una tabla de Postgres…). El agente solo recibe `{request_id, status, stored:[nombres]}`.

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

Requisitos: Node ≥ 20.11. En Linux el destino `keychain` usa `secret-tool` (paquete `libsecret-tools`); macOS usa `security`. Opcionales: `playwright-core` + Chromium (`web_capture`), `psql` (sinks SQL), `gh` (secretos de GitHub), OpenSSH.

```bash
pnpm install && pnpm build
claude mcp add secret-intake -- node /ruta/a/secret-intake-mcp/dist/cli.js
# cuando esté publicado:  claude mcp add secret-intake -- npx -y secret-intake-mcp
```

Variables opcionales: `SECRET_INTAKE_HOME` (por defecto `~/.config/secret-intake`), `SECRET_INTAKE_CONFIG`, `SECRET_INTAKE_AGENT` (etiqueta que se escribe en la auditoría).

La configuración es una **allowlist**: copia [`examples/config.example.json`](examples/config.example.json) a `~/.config/secret-intake/config.json` y deja solo lo necesario. Sin archivo hay un único destino, `local` (llavero del SO). Verifícala con `secret-intake-mcp check-config`.

Endurecimiento recomendado en Claude Code (`.claude/settings.json`): niega a las herramientas propias del agente lo que este servidor protege, p. ej. `"deny": ["Read(~/.config/secret-intake/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

## Ejemplos

**Llave de Stripe y una llamada:** `secret_request({title:"Stripe", fields:[{name:"STRIPE_KEY", label:"Llave secreta"}]})` → la pegas en la página local → `secret_use({action:"http", url:"https://api.stripe.com/v1/balance", headers:{Authorization:"Bearer ${secret:STRIPE_KEY}"}})` → la página de aprobación muestra exactamente esa petición → `{http_status:200, body:"…"}` (si la API repite la llave, sale como `[REDACTED:STRIPE_KEY]`).

**Token de Mercado Pago al `.env` de producción por SSH:**
`secret_write({name:"MP_ACCESS_TOKEN", target:{kind:"env-file", host:"godnutrition", path:"/etc/gods-store/gods-store.env", key:"MP_ACCESS_TOKEN"}, dry_run:true})` → `{changes:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}`. Sin `dry_run`, tras tu aprobación (la primera vez por destino), cambia solo esa clave conservando comentarios y el resto, sube el archivo por stdin a un temporal, `chmod 0600`, `chown`/respaldo opcionales y `mv` atómico. El modelo recibe `{written:true, target, keys}`.

**Sacar el token del panel de Mercado Pago sin que el modelo lo vea:** `web_capture({site:"mercadopago", name:"MP_ACCESS_TOKEN", steps:[{wait:"text=Credenciales de producción", timeout_ms:600000},{click:"text=Mostrar"}], extract:{selector:"[data-testid=access-token]", regex:"(APP_USR-[\\w-]+)"}})`. Se abre una ventana de Chromium **propia del MCP**; **tú** inicias sesión (contraseña y 2FA nunca pasan por el modelo); puedes ajustar los pasos en la página de aprobación; el valor va del DOM al almacén.

**Llave SSH para un VPS nuevo:** `ssh_key_provision({host:"godnutrition", alias:"gods_deploy", password:true})` → la página muestra la huella del host para compararla con tu proveedor, pide la contraseña de un solo uso, instala la llave pública y prueba el acceso. Luego `ssh_exec({host:"godnutrition", command:"systemctl restart gods-store"})`.

**Precios USD de God's Nutrition en lote:** `blind_input` con una tabla `rows:[sku, price(money USD)]` y sink `{type:"sql", database:"gods", table:"public.product_prices", mode:"upsert", rows:"rows", columns:{sku:"${sku}", price_usd:"${price}", list:"mayoreo"}, dry_run:true}`. Pegas las filas desde Excel/Sheets; los valores viajan como datos de `COPY … FROM STDIN` a una tabla temporal tipada y un `INSERT … SELECT` en una sola transacción (nunca como texto SQL). El modelo recibe `{rows_validated:120}` y luego `{rows_written:120, ids:[…]}`.

**Credenciales de pago:** `secret_request` con destino `ops-mercadopago` (adaptador `ops-addon-settings`) o `infisical`: el valor va del navegador al almacén remoto, servidor a servidor.

**Datos sensibles de clientes:** `blind_input` con `nombre, email, rfc (pattern), teléfono` y sink `http` a tu CRM; el modelo solo recibe los ids creados.

## Flujo de seguridad

1. El modelo llama con metadatos. Destinos, hosts, rutas, tablas y sitios deben estar en tu configuración.
2. El enlace de un solo uso `http://127.0.0.1:<puerto>/p/<token de 256 bits>` llega por **elicitation por URL de MCP** si el cliente la soporta; si no, se devuelve para que el cliente/agente lo muestre (y se abre con `xdg-open`/`open` si `ui.openBrowser`). El primer navegador que lo abre lo amarra con una cookie HttpOnly; caduca en 10 min.
3. Llenas o apruebas. Token CSRF + verificación de Origin/Host + CSP estricta con nonce; nada de terceros; sin autocompletado.
4. Los valores van al destino desde este proceso (stdin/env, nunca argv; nunca en logs).
5. Las respuestas son estructurales; un filtro final elimina cualquier valor manejado y sus codificaciones.
6. Cada uso queda en la auditoría (JSONL encadenado por hash: sesión, agente, cliente, acción, huella, nombres). `secret-intake-mcp verify-audit` verifica la cadena.

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
