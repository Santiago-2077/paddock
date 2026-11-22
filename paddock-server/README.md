# Paddock — servidor vulnerable local (lab de ciberseguridad)

Servidor HTTP **local** en Python stdlib (`http.server` + `sqlite3`), objetivo de los
escenarios del protocolo. **Vulnerabilidades intencionales y documentadas** para un
ejercicio académico autorizado (Tecmilenio). Solo uso local, datos ficticios. **No desplegar.**

## Arranque
```bash
python3 seed.py                              # crea/reinicia paddock.db con datos ficticios
SAFE_MODE=false python3 server.py            # VULNERABLE (demostrar explotación)
SAFE_MODE=true  python3 server.py            # CORREGIDO (contraste §4.6)
```
Escucha en `http://127.0.0.1:3000` (env `PORT` para cambiarlo).

## Tokens de prueba (rutas admin)
```bash
python3 tools/mint_token.py all              # admin | participante | expired | tampered
```
Firmados RS256 con la clave local `keys/private.json`; el servidor verifica contra
`keys/jwks.json`. Para Cognito real: cambiar `PADDOCK_ISS`, `PADDOCK_AUD` y apuntar
`PADDOCK_JWKS` al JWKS del User Pool (ver `auth.py`).

## Mapa vulnerabilidad → endpoint → caso de prueba
| Caso | Endpoint | Vuln (SAFE_MODE=false) | Corregido (SAFE_MODE=true) |
|------|----------|------------------------|-----------------------------|
| VULN-SQL-01  | `GET /api/vehicles/search?q=&category=` | `q`/`category` concatenados → inyección SQL (boolean + UNION exfil) | parametrizado + whitelist |
| VULN-VAL-01  | `POST /api/registrations` | persiste sin revalidar placas/categoría | valida schema en servidor (422) |
| VULN-LOAD-01 | `POST /api/registrations` | sin rate-limit (objetivo de carga) | — |
| AUTH-01..05  | `GET /api/admin/reports`, `/api/admin/registrations` | nunca vulnerables; exigen JWT válido + grupo `Admin` | igual |

## Verificación rápida (curl)
```bash
# SQLi: inyectado devuelve MÁS filas que el filtro legítimo
curl 'localhost:3000/api/vehicles/search?q=ABC-123-D'                 # 1
curl "localhost:3000/api/vehicles/search?q=%27%20OR%20%271%27=%271"    # 3
# bypass: 201 en vuln, 422 en safe
curl -XPOST localhost:3000/api/registrations -H 'Content-Type: application/json' \
     -d '{"plate":"###","categoryId":99999,"ownerName":"X"}'
# admin: 200 con token Admin, 401/403 en el resto
T=$(python3 tools/mint_token.py admin | sed -n 2p)
curl -H "Authorization: Bearer $T" localhost:3000/api/admin/reports
```

## Archivos
- `server.py` — router + endpoints (vulns comentadas, gobernadas por `SAFE_MODE`)
- `db.py` — SQLite (modelo de `../cars/paddock_cdmx.sql`)
- `seed.py` — datos ficticios del protocolo (§4.5)
- `auth.py` — verificación JWT RS256 contra JWKS local (Python puro)
- `tools/mint_token.py` — generador de tokens de prueba
- `keys/` — `private.pem`, `private.json` (firma), `jwks.json` (verificación)
