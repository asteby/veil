# Especificación del formato `.veil` — borrador `1-draft.0`

> **Estado:** borrador para revisión. **No implementado.** No usar para datos reales hasta que exista una implementación con vectores de prueba publicados y una revisión criptográfica externa.
> **Relación:** acompaña a [`ENGINEERING-PLAN-NEXT-GEN.md`](ENGINEERING-PLAN-NEXT-GEN.md) §7. El nombre "Veil" es una propuesta del dueño aún sin confirmar **[RENOMBRE]**: si cambia, cambian los bytes mágicos, las etiquetas `veil/1 …` de derivación de llaves, el prefijo `veil:1:` y el tipo MIME. Por eso **el nombre debe fijarse antes de congelar esta especificación**.
> **Alineación:** la forma por valor (§10) adopta el formato `veilform-env v1` que implementa la rama `feat/vault-sync-share` y solo propone extensiones; los formatos de bundle de sincronía y de compartir (`vfs1://`) también son de esa rama y aquí solo se referencian (`CONTENT_KIND` 4).

Las palabras DEBE, NO DEBE, DEBERÍA y PUEDE se usan con el sentido de RFC 2119.

---

## 1. Objetivos y no-objetivos

**Objetivos**

1. Confidencialidad e integridad de un contenido para uno o más destinatarios.
2. Cabecera extensible con **agilidad criptográfica** controlada (identificadores de suite, no negociación en línea).
3. Metadatos **cifrados** por defecto; públicos solo los necesarios para descifrar.
4. **Verificación sin descifrar** de estructura, canonicalidad, destinatarios requeridos y, si existe, firma de autor.
5. Streaming de archivos grandes con memoria acotada.
6. Una forma **por valor** apta para `.env`/YAML/JSON en git, con diffs legibles y re-cifrado estable.
7. Interoperabilidad con age (misma construcción de payload; protocolo de plugins) y rutas de importación desde sops y dotenvx.
8. Codificación **canónica única**: dos implementaciones conformes producen y aceptan exactamente lo mismo.

**No-objetivos**

- Ocultar el tamaño aproximado, el momento de modificación o la existencia del archivo (hay relleno opcional, §8.4).
- Autenticar al remitente sin firma: igual que age, cualquiera con la llave pública de un destinatario puede crear un archivo para él. La autenticidad requiere la firma opcional (§9).
- Negociación interactiva de algoritmos.

---

## 2. Notación

- `u8`, `u16`, `u32`, `u64`: enteros sin signo **big-endian** de ancho fijo.
- `‖`: concatenación. `len16(x)`: `u16(longitud de x) ‖ x`.
- `HKDF(ikm, salt, info, L)`: HKDF-SHA-256 (RFC 5869).
- `HMAC(k, m)`: HMAC-SHA-256.
- `AEAD`: según la suite (§6). Nonce de 12 bytes. Etiqueta de 16 bytes.
- Etiquetas de dominio: cadenas ASCII sin terminador, p. ej. `"veil/1 header"`.

---

## 3. Estructura del archivo binario

```
+--------------------+---------------------------------------------------------+
| magic        [8]   | 89 56 45 49 4C 0D 0A 1A   ("\x89VEIL\r\n\x1a")          |
| ver_major    u8    | 0x01                                                    |
| ver_minor    u8    | 0x00                                                    |
| header_len   u32   | longitud del bloque TLV, 1 .. 1 048 576                 |
| header       [..]  | secuencia de TLV (§4)                                   |
| header_mac   [32]  | HMAC(hmac_key, magic ‖ ver_major ‖ ver_minor ‖          |
|                    |      header_len ‖ header)                               |
| payload      [..]  | STREAM (§7)                                             |
| trailer      [..]  | opcional (§9): TLVs ‖ u32 trailer_len ‖ "VEILEND\0"     |
+--------------------+---------------------------------------------------------+
```

- Los bytes mágicos siguen el patrón de PNG: el byte alto detecta transferencias de 7 bits, `\r\n` y `\x1a` detectan conversiones de fin de línea y truncamiento en modo texto.
- **`ver_major`** cambia solo con cambios incompatibles. Un lector DEBE rechazar un `ver_major` desconocido.
- **`ver_minor`** añade TLVs/suites compatibles. Un lector DEBE aceptar un `ver_minor` mayor siempre que pueda procesar todos los TLV **críticos** presentes.
- La presencia de trailer se indica con el TLV `FLAGS` (§4.2, bit 0). Si el bit está activo, los últimos 8 bytes del archivo DEBEN ser `"VEILEND\0"`.

---

## 4. Cabecera TLV

### 4.1 Codificación

```
TLV := type u16 ‖ length u32 ‖ value[length]
```

- **Bit crítico:** `type & 0x8000`. Un lector que encuentra un TLV crítico desconocido DEBE rechazar el archivo. Un TLV no crítico desconocido DEBE ignorarse (sigue cubierto por el MAC).
- **Orden canónico:** los TLV DEBEN aparecer en orden **estrictamente creciente** de `type & 0x7FFF`, salvo los tipos marcados como *repetibles*, que DEBEN ser contiguos y conservan el orden en que se escribieron.
- Un tipo no repetible DEBE aparecer como máximo una vez.
- `length` DEBE coincidir exactamente con el contenido; no se permiten bytes sobrantes dentro de `value`.
- Límites del lector (DEBEN ser configurables, con estos mínimos aceptados): `header_len` ≤ 1 MiB; ≤ 256 destinatarios; anidamiento de grupos umbral ≤ 2.

### 4.2 Registro de tipos (v1)

| Tipo | Nombre | Crítico | Repetible | Público | Contenido |
|---|---|---|---|---|---|
| `0x8001` | `PAYLOAD_SUITE` | sí | no | sí | `u16 aead_id ‖ u8 chunk_log2` (v1: `chunk_log2 = 16`) |
| `0x8002` | `PAYLOAD_SALT` | sí | no | sí | 16 bytes aleatorios |
| `0x8003` | `RECIPIENT` | sí | **sí** | sí | §5 |
| `0x0004` | `FLAGS` | no | no | sí | `u32`: bit0 = hay trailer; bit1 = relleno aplicado; bit2 = experimental; resto DEBE ser 0 |
| `0x0005` | `CONTENT_KIND` | no | no | sí | `u8` (§8.1). Omitirlo equivale a `opaque` y es lo recomendado si el tipo es sensible |
| `0x8006` | `ENCRYPTED_META` | sí | no | cifrado | `AEAD(meta_key, nonce=0¹², meta_tlvs, aad="veil/1 meta")` (§8.2) |
| `0x0007` | `SIGNER_HINT` | no | no | sí | `u16 sig_alg ‖ key_id[8]` (§9) |
| `0x0008` | `POLICY_ID` | no | no | sí | 16 bytes (id opaco de la política del proyecto; permite a `verify` exigir reglas) |
| `0x7F00`–`0x7FFF` | privados/experimentales | no | — | — | Uso local; NO DEBEN aparecer en archivos intercambiados |

`PAYLOAD_SUITE`, `PAYLOAD_SALT` y al menos un `RECIPIENT` son obligatorios.

---

## 5. Destinatarios

### 5.1 Estructura común

```
RECIPIENT.value := rtype u16 ‖ rflags u16 ‖ [key_id[8] si rflags.bit0] ‖ body
```

- `key_id` = primeros 8 bytes de `SHA-256("veil/1 keyid" ‖ llave_pública_codificada)`. Si se omite (modo **anónimo**), el lector prueba sus identidades contra cada destinatario de ese tipo.
- `rflags` bits distintos de bit0 DEBEN ser 0 en v1.
- Cada destinatario envuelve la misma **llave de archivo** `file_key` de **16 bytes** (igual que age, para compatibilidad con su protocolo de plugins; las llaves de trabajo de 32 bytes se derivan con HKDF).
- `wrapped` = `ChaCha20-Poly1305(wrap_key, nonce=0¹², file_key, aad="")` → 32 bytes. Cada `wrap_key` es único por destinatario y archivo, por lo que el nonce fijo es seguro.

### 5.2 Tipos

| rtype | Nombre | body | Derivación de `wrap_key` |
|---|---|---|---|
| `0x0001` | `X25519` | `eph_pub[32] ‖ wrapped[32]` | `ss = X25519(eph_priv, R)`; rechazar `ss` todo ceros; `HKDF(ss, eph_pub ‖ R, "veil/1 x25519", 32)` |
| `0x0002` | `PASSPHRASE` | `kdf u8 ‖ params ‖ salt[16] ‖ wrapped[32]` | `kdf=1` Argon2id: `params = u32 m_kib ‖ u32 t ‖ u8 p`; `kdf=2` scrypt (solo importación): `params = u8 log2N ‖ u32 r ‖ u32 p`. Salida 32 bytes con sal `"veil/1 pass" ‖ salt` |
| `0x0003` | `P256` | `eph_pub_compressed[33] ‖ wrapped[32]` | ECDH P-256; `HKDF(ss, eph ‖ R_compressed, "veil/1 p256", 32)`. Para Secure Enclave, YubiKey PIV y TPM |
| `0x0004` | `FIDO2_PRF` | `len16(rp_id) ‖ len16(cred_id) ‖ prf_salt[32] ‖ wrapped[32]` | `prf = PRF(cred, prf_salt)` (WebAuthn PRF / CTAP2 hmac-secret); `HKDF(prf, prf_salt, "veil/1 fido2-prf", 32)` |
| `0x0005` | `KMS` | `provider u8 ‖ len16(key_ref) ‖ len16(kms_ciphertext)` | El KMS cifra `file_key` con contexto de cifrado `{"veil":"1","salt":hex(PAYLOAD_SALT)}`. `provider`: 1 AWS KMS, 2 GCP KMS, 3 Vault Transit, 4 OpenBao Transit |
| `0x0006` | `THRESHOLD` | `m u8 ‖ n u8 ‖ n × len16(RECIPIENT.value anidado)` | Cada anidado envuelve una **parte** Shamir (GF(2⁸), polinomio de AES) de `file_key`: `x u8 ‖ y[16]`, cifrada como `wrapped` de 17 + 16 = 33 bytes. `1 ≤ m ≤ n ≤ 255`, `x` distintos y ≠ 0 |
| `0x0007` | `AGE_PLUGIN` | `len16(plugin_name) ‖ len16(args) ‖ len16(stanza_body)` | Delegado al plugin de age `age-plugin-<name>`; el cuerpo es el de su stanza. Permite YubiKey/TPM/SE/FIDO2 vía plugins existentes |
| `0x0010` | `XWING_EXP` | `enc[1120] ‖ wrapped[32]` | **Experimental** (FLAGS.bit2 DEBE estar activo). KEM híbrido X25519 + ML-KEM-768 tipo X-Wing **(verificar borrador vigente)**; `HKDF(ss, enc, "veil/1 xwing-exp", 32)` |

### 5.3 Reglas

- Si hay un destinatario `PASSPHRASE`, DEBE ser el **único** (misma regla que age: evita mezclar un secreto de baja entropía con destinatarios de llave pública y deja clara la semántica).
- Un lector DEBE comprobar el `header_mac` con **cada** `file_key` candidato obtenido y aceptar solo el que valide. Si ninguno valida → `error:header_mac`.
- Un lector NO DEBE revelar qué destinatario falló (mismo código de error).

---

## 6. Suites

| `aead_id` | AEAD | Estado |
|---|---|---|
| `0x0001` | ChaCha20-Poly1305 (RFC 8439) | **Por defecto** |
| `0x0002` | AES-256-GCM | Opcional (aceleración por hardware, entornos FIPS) |
| `0xFF00`–`0xFFFF` | Experimentales | Requieren FLAGS.bit2 |

Derivaciones comunes a partir de `file_key` (16 bytes) y `PAYLOAD_SALT`:

```
hmac_key    = HKDF(file_key, "",            "veil/1 header",  32)
payload_key = HKDF(file_key, PAYLOAD_SALT,  "veil/1 payload", 32)
meta_key    = HKDF(file_key, PAYLOAD_SALT,  "veil/1 meta",    32)
```

**Agilidad sin degradación:** la suite y la versión están dentro del área cubierta por `header_mac`. Los lectores DEBEN aplicar una **lista mínima aceptada** configurable (p. ej. rechazar `scrypt` con `log2N < 17` o Argon2id con `m_kib < 65536`) para impedir archivos deliberadamente débiles.

---

## 7. Payload (STREAM)

Igual que age: bloques de `2^chunk_log2` bytes de texto plano (v1: 65 536).

```
nonce_i = u88(i) ‖ last_flag        (11 bytes de contador big-endian + 1 byte: 0x00 / 0x01)
chunk_i = AEAD(payload_key, nonce_i, plaintext_i, aad="")
```

- Todos los bloques salvo el último DEBEN tener exactamente `2^chunk_log2` bytes de texto plano.
- El último bloque DEBE tener `last_flag = 0x01`. Un bloque final vacío solo se permite si es el **único** bloque (contenido vacío).
- Truncamiento o reordenamiento producen fallo de autenticación (el contador y la bandera de último van en el nonce).
- El lector DEBE abortar al primer fallo y NO DEBE liberar texto plano de bloques no autenticados al consumidor final hasta que el bloque se autentique (streaming por bloque autenticado).

---

## 8. Contenido y metadatos

### 8.1 `CONTENT_KIND`

| Valor | Tipo | Payload |
|---|---|---|
| 0 | `opaque` | Bytes arbitrarios |
| 1 | `vault` | Secuencia de entradas `ENTRY` (§8.3) |
| 2 | *reservado* | (Antes: cabecera de documentos por valor; la forma por valor usa el formato de §10, no este contenedor) |
| 3 | `ssh-private-key` | Llave privada OpenSSH |
| 4 | `share-bundle` | Reservado para una futura encapsulación del paquete de compartir de `feat/vault-sync-share` (hoy JSON `veilform-share` v1) |
| 5 | `audit-checkpoint` | Checkpoint de log Merkle |

### 8.2 `ENCRYPTED_META`

Contenido descifrado: TLVs con las mismas reglas de §4.1:

| Tipo | Nombre | Contenido |
|---|---|---|
| `0x0001` | `KIND` | `u8` real (aunque el público se omita) |
| `0x0002` | `NAME` | UTF-8 NFC, ≤ 255 bytes |
| `0x0003` | `MEDIA_TYPE` | Tipo MIME del texto plano |
| `0x0004` | `CREATED_MS` | `u64` |
| `0x0005` | `LABELS` | Secuencia de `len16(utf8)` ordenada y sin duplicados |
| `0x0006` | `PLAINTEXT_LEN` | `u64` (obligatorio si FLAGS.bit1) |
| `0x0007` | `PRODUCER` | `len16("veil/<versión>")` |
| `0x0008` | `SEQUENCE` | `u64` contador monotónico para detectar **rollback** (el lector compara con el último visto, guardado en su llavero) |

### 8.3 Entradas de bóveda (`vault`)

```
ENTRY := len16(name_utf8_nfc) ‖ u16 entry_flags ‖ len16(meta_tlvs) ‖ u32 value_len ‖ value
```

Ordenadas por `name` (orden de bytes), sin duplicados. Toda la bóveda está bajo un solo payload, por lo que borrar o cambiar una entrada invalida la autenticación (corrige H-02/H-03 del plan).

### 8.4 Relleno

Si FLAGS.bit1: el texto plano se rellena con ceros hasta la longitud Padmé de `PLAINTEXT_LEN`; el lector DEBE comprobar que los bytes de relleno son cero.

---

## 9. Firma opcional y `veil verify`

### 9.1 Trailer

```
trailer := TLVs ‖ u32 trailer_tlvs_len ‖ "VEILEND\0"
```

| Tipo | Nombre | Contenido |
|---|---|---|
| `0x8101` | `SIGNATURE` | `u16 sig_alg ‖ key_id[8] ‖ sig` (`sig_alg = 1`: Ed25519, 64 bytes) |
| `0x0102` | `SIGNER_CERT` | Opcional: certificado/identidad (p. ej. Sigstore) |

Mensaje firmado:

```
"veil/1 sig" ‖ SHA-512(magic … header_mac) ‖ SHA-512(payload completo cifrado) ‖ SHA-512(trailer TLVs excepto SIGNATURE)
```

La firma cubre el **cifrado**: cualquiera con la llave pública del firmante comprueba autoría e integridad sin la llave de descifrado. NO prueba nada sobre el texto plano frente a un firmante malicioso (podría firmar un archivo cuyo `file_key` no conoce nadie).

### 9.2 Qué comprueba `veil verify` sin llaves

1. Bytes mágicos, versión, límites.
2. Canonicalidad completa de la cabecera (orden, duplicados, longitudes, bits reservados en 0, TLV críticos conocidos).
3. Estructura de cada destinatario (longitudes por tipo, `m ≤ n`, `x` distintos, regla de passphrase única).
4. Que los **destinatarios requeridos** por la política (por `key_id`) están presentes.
5. Estructura del payload por longitudes (tamaños de bloque coherentes con el tamaño del archivo) y del trailer.
6. Firma (si existe y se aporta la llave del firmante o la política la conoce).
7. Suites dentro de la lista mínima aceptada.

Con llave, `veil verify --decrypt-check` además valida `header_mac`, todos los bloques y `ENCRYPTED_META`, **sin escribir** el texto plano.

---

## 10. Forma por valor (documentos `.env`, YAML, JSON, TOML)

> **Base: el formato `veilform-env v1` que la rama `feat/vault-sync-share` está implementando** (`src/envenc/format.ts` en `/home/user/projects/veilform-vault`, trabajo sin commitear al 2026-10-19). Esta sección **no** define un formato competidor: resume ese diseño y propone extensiones compatibles para v1.1. Si la rama hermana cambia su formato antes de integrarse, manda la rama hermana y esta sección se actualiza.

### 10.1 Resumen del formato de la rama hermana (tal como está en su código)

```dotenv
#/veilform-env v1
#/context .env.production
#/recipient key:3f1c0a9e5b7d2c44 <base64url(JSON {w})>
#/recipient pass <base64url(JSON {kdf, w})>
#/mac <base64url HMAC>
# database
export DB_URL="enc:v1:<base64url(nonce12 ‖ ct ‖ tag16)>"
PORT=3000
```

- DEK aleatorio de 32 bytes por archivo; cada valor con AES-256-GCM, nonce aleatorio de 96 bits y **AAD = `"veilform-env/v1/value\0" ‖ contexto ‖ "\0" ‖ KEY`** (el contexto por defecto es el nombre del archivo): un valor movido a otra variable u otro archivo/entorno no descifra.
- Se cifra el **texto original del lado derecho** (comillas, escapes, multilínea): descifrar restaura el archivo byte a byte. Comentarios, orden y **nombres de variables quedan en claro** a propósito (diffs revisables).
- `#/mac` = HMAC-SHA-256 con llave `HKDF(DEK, "veilform-env/v1", "mac\0" ‖ contexto)` sobre JSON canónico de `{v, context, ids de destinatarios ordenados, [(KEY, ciphertext)…] en orden}`: detecta altas, bajas, reordenamientos, duplicados y valores intercambiados.
- Destinatarios **simétricos**: `pass` (Argon2id o scrypt con límites mínimos y máximos) y `key:<id>` (llave cruda: archivo de llave, llavero, credencial de systemd, llave de servidor). El DEK se envuelve con AES-256-GCM y AAD `"veilform-env/v1/wrap\0" ‖ contexto ‖ "\0" ‖ id`.
- **Re-cifrado estable**: con el mismo DEK, los valores sin cambio conservan su cifrado previo.

Este diseño cubre los requisitos de git (diffs mínimos, integridad de documento, ligadura al nombre). Se adopta como **forma por valor de Veil**.

### 10.2 Extensiones propuestas para `v1.1` (compatibles hacia atrás)

1. **Destinatarios asimétricos.** Nuevos ids de línea `#/recipient x25519:<key_id> …`, `p256:<key_id> …`, `kms:<proveedor>:<key_id> …`, `plugin:<nombre>:<key_id> …`, `threshold:<id> …`, cuyo blob es un `RECIPIENT.value` de §5 en base64url envolviendo el **mismo DEK de 32 bytes** (la envoltura de §5 se generaliza a `len(file_key) ∈ {16, 32}`). Motivo: hoy cualquiera que pueda **cifrar** para el archivo también puede **descifrarlo** (destinatarios simétricos); con llaves públicas, un compañero, la CI o un agente pueden añadir valores sin poder leer los demás.
   - Un lector v1 que encuentra un id desconocido **falla** (`unknown recipient type`), lo cual es correcto (equivale a un TLV crítico). Por eso los escritores DEBEN conservar al menos un destinatario v1 (`pass` o `key:`) mientras haya lectores v1 en el equipo, o declarar la versión mínima en la política.
2. **Prefijos [RENOMBRE].** Antes de la primera publicación: cabecera `#/veil-env v1` y prefijo `veil:1:` en lugar de `#/veilform-env v1` y `enc:v1:` (este último es genérico y podría chocar con otras herramientas). Si la rama hermana ya publicó archivos, los lectores DEBEN aceptar ambas grafías; los escritores usan la nueva.
3. **Huella de destinatario obligatoria por política.** `veil verify` comprueba que los ids requeridos (`recovery`, `ci`) estén presentes sin descifrar nada (la línea `#/recipient` es pública).
4. **Driver de merge.** Como el MAC cubre todo el documento, cada edición lo cambia; `merge=veil` resuelve por llave y recalcula el MAC (requiere el DEK; sin él, el conflicto se reporta por llave).

### 10.3 YAML/JSON/TOML

Mismo esquema: los valores cifrados son cadenas `"veil:1:…"` (o `"enc:v1:…"` en v1), el contexto por defecto es el nombre del archivo, la ruta de ligadura es el **puntero JSON** (RFC 6901) en lugar del nombre de variable, y la cabecera va en una llave reservada de nivel superior (`"$veil"` en JSON; `_veil` en YAML/TOML). Los editores existentes (`src/fileformats.ts`) preservan comentarios y orden. A coordinar con la rama hermana, que hoy solo cubre `.env`.

### 10.4 ¿Por qué no usar el contenedor binario `.veil` para `.env`?

Porque un `.env` cifrado entero pierde los diffs por variable y la revisión en PR. El contenedor binario (§3–§9) es para **archivos completos** (llaves SSH, volcados, adjuntos, bóvedas, checkpoints); la forma por valor es para **documentos de configuración**. Ambas comparten tipos de destinatario (§5) y política.

---

## 11. Armadura textual

```
-----BEGIN VEIL FILE-----
<base64 estándar con relleno, líneas de exactamente 64 caracteres salvo la última>
-----END VEIL FILE-----
```

- Solo `LF`. Sin espacios. Base64 **canónico** (bits de relleno a cero). Cualquier otra cosa DEBE rechazarse (no normalizar).
- Tipo MIME: `application/vnd.asteby.veil` (binario), `application/vnd.asteby.veil+armor` **(propuesta; registrar en el árbol de vendedor de IANA)** [RENOMBRE].
- Entrada para `file(1)` / libmagic:

```
0   string   \x89VEIL\r\n\x1a   Veil encrypted file
>8  byte     x                  \b, version %d
>9  byte     x                  \b.%d
0   string   -----BEGIN\ VEIL\ FILE-----   Veil encrypted file (armored)
```

- Asociaciones: shared-mime-info (`*.veil`, glob + magic), UTI `com.asteby.veil` conforme a `public.data`, ProgID `Asteby.Veil.1`; en git: `*.veil binary diff=veil`.

---

## 12. Compatibilidad, migración e interoperabilidad

| Origen/destino | Dirección | Método | Pérdidas |
|---|---|---|---|
| `encrypted-file` v1 (veilform 0.1) | importar | Leer v1 (`CHECK = "veilform:v1"`, scrypt o llave cruda del llavero) → `vault` | Ninguna; se gana integridad global y metadatos cifrados |
| `veilform-env v1` (rama hermana) | leer/escribir | Es la forma por valor de Veil (§10); v1.1 solo añade destinatarios y prefijos | Ninguna |
| Bundle de sincronía `manifest.json` + `o/<oid>` (rama hermana) | leer/escribir | Se mantiene como formato de sincronía; `.veil` no lo reemplaza en 1.0. Unificación solo si aporta (decisión post-1.0) | — |
| Compartir `veilform-share` v1 / `vfs1://` (rama hermana) | leer/escribir | Igual; `CONTENT_KIND` 4 queda reservado | — |
| age | importar | Descifrar con identidad age (biblioteca) → `opaque` | Ninguna |
| age | exportar | Solo si todos los destinatarios son `X25519`, `PASSPHRASE` scrypt o `AGE_PLUGIN`; los metadatos cifrados y la firma se pierden (avisar) | Metadatos, firma, grupos umbral, KMS |
| sops (YAML/JSON/ENV) | importar | Biblioteca de sops o binario; grupos de llaves con umbral → `THRESHOLD`; KMS → `KMS` | MAC de sops se reemplaza por `doc mac` |
| sops | exportar | Documento sops con destinatarios age | Grupos/KMS según soporte de sops |
| dotenvx | importar | Descifrar ECIES secp256k1 con `.env.keys` (dependencia ECIES o invocación de `dotenvx`) **(decidir)** | Ninguna |
| dotenvx | exportar | No previsto en v1 | — |

**Reglas de evolución**

- `ver_minor` nuevo: solo TLVs no críticos, suites nuevas o destinatarios nuevos. Los lectores se publican **antes** que los escritores (una versión menor de margen).
- Una suite se puede **deprecar** (los lectores avisan) y luego **retirar** solo en un `ver_major` nuevo.
- Las etiquetas de dominio incluyen `1` (major): un `ver_major` 2 usa `veil/2 …`.

---

## 13. Vectores de prueba

Ubicación: `spec/vectors/*.json`. Esquema por vector:

```json
{
  "id": "x25519-single-small",
  "description": "Un destinatario X25519, 37 bytes de texto plano",
  "deterministic_inputs": {
    "file_key": "hex16", "payload_salt": "hex16",
    "ephemeral_secrets": ["hex32"], "recipient_identities": ["veil-secret-key-…"],
    "plaintext": "hex"
  },
  "file": "hex o armadura",
  "expect": "ok | error:<código>"
}
```

Conjuntos mínimos antes de congelar:

- **Positivos:** vacío; 1 byte; exactamente 64 KiB; 64 KiB + 1; varios destinatarios mezclados; anónimo; passphrase Argon2id y scrypt; P-256; KMS (simulado); umbral 2-de-3 con cada combinación; metadatos completos; relleno; firma; armadura; documentos `.env` v1 de la rama hermana (vectores aportados por ella) y v1.1 con destinatario X25519.
- **Negativos** (código esperado): mágico inválido, `ver_major` desconocido, TLV desordenado, duplicado, crítico desconocido, longitud sobrante, bits reservados, passphrase junto a otro destinatario, X25519 con secreto compartido cero, `m > n`, `x` repetido, `header_mac` alterado, bloque truncado, bloque final vacío no único, bloque reordenado, último bloque sin bandera, trailer sin `VEILEND\0`, firma inválida, base64 no canónico en armadura, `CR` en armadura, Argon2id por debajo del mínimo, documento `.env` con `mac` que no coincide, valor movido a otra variable o a otro contexto, destinatario v1.1 desconocido para un lector v1.
- **Interop:** archivos age generados por `age` CLI e importados; exportaciones leídas por `age` CLI.

Códigos de error estables: `bad_magic`, `unsupported_version`, `noncanonical`, `unknown_critical`, `limits`, `bad_recipient`, `no_identity`, `header_mac`, `payload_auth`, `truncated`, `bad_trailer`, `bad_signature`, `weak_params`, `bad_armor`, `doc_mac`.

---

## 14. Canonicalización y fuzzing

- **Rechazar, no normalizar**: cualquier entrada no canónica es error. Así `parse(serialize(x)) = x` y `serialize(parse(b)) = b` para todo `b` aceptado (propiedad probada).
- Objetivos de fuzzing (Go nativo): `ParseHeader`, `ParseRecipient`, `ParseArmor`, `ParseTrailer`, `ParseEnvDoc`, `ParseValueEnvelope`, `ParseMeta`, `ParseVaultEntries`, `DecryptStream` (con llave fija).
- **Fuzzing diferencial**: verificador Go vs. verificador TS de cabecera: misma decisión de aceptar/rechazar y mismo código de error para cada entrada.
- Corpus semilla: todos los vectores.

---

## 15. Consideraciones de seguridad

1. **Compromiso de llave:** ChaCha20-Poly1305 y AES-GCM no comprometen la llave; un remitente malicioso con varios destinatarios podría intentar que cada uno obtenga un `file_key` distinto. El `header_mac` (HMAC-SHA-256 con llave derivada de `file_key`) actúa como compromiso: solo un `file_key` lo valida en la práctica. Las llaves de payload y metadatos se derivan del `file_key` comprometido.
2. **Sin autenticidad de remitente** salvo firma (§9). Las políticas de proyecto PUEDEN exigir firma.
3. **Metadatos públicos:** número y tipo de destinatarios, `key_id` (si no se usa modo anónimo), suites, tamaño aproximado, `KMS.key_ref`. Documentar en la UI.
4. **Rollback:** sin `SEQUENCE` (§8.2) y sin estado local, un archivo antiguo válido es indistinguible de uno nuevo. Las bóvedas DEBERÍAN usar `SEQUENCE` con el último valor guardado en el llavero del dispositivo.
5. **DoS:** límites de §4.1 y parámetros máximos de KDF configurables (un archivo con Argon2id de 4 GiB no debe tumbar al lector).
6. **Passphrase:** Argon2id con mínimos; la passphrase es respaldo, no custodia principal.
7. **Post-cuántico:** solo `XWING_EXP` y solo protege la envoltura de `file_key`; con 16 bytes de `file_key` el margen frente a Grover es el de una llave simétrica de 128 bits **(revisar en la auditoría si conviene subir a 32 bytes en v2, a costa de compatibilidad con plugins de age)**.
8. **Canales laterales:** comparación de MAC y de texto plano (re-cifrado estable) en tiempo constante.
9. **Memoria:** el texto plano y `file_key` deben vivir el mínimo tiempo posible; las implementaciones no pueden garantizar borrado en lenguajes con recolector.

---

## 16. Preguntas abiertas

1. ¿`file_key` de 16 bytes (compatibilidad con plugins de age) o 32 (margen PQ)? Propuesta: 16 en v1.
2. ¿HPKE (RFC 9180) como envoltura genérica para P-256 y el KEM híbrido, en vez de construcciones ad hoc? Ventaja: estándar y vectores existentes.
3. ¿Firma con Sigstore (identidad OIDC) además de Ed25519?
4. Formato exacto de `share-bundle` (lo define `feat/vault-sync-share`).
5. En la forma por valor, el MAC de la rama hermana cubre `(KEY, rhs)` de **todas** las líneas `KEY=valor` (incluidas las no cifradas, que en su diseño no deberían existir dentro de un documento cifrado). ¿Se permiten valores en claro mezclados (p. ej. `PORT=3000`) bajo política? Si sí, deben seguir cubiertos por el MAC.
6. ¿Se unifica el bundle de sincronía con el contenedor `.veil` después de 1.0, o se mantienen como formatos hermanos?
