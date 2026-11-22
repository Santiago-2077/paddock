# Paddock — Lab de Ciberseguridad

Entorno experimental **local** para demostrar, de forma controlada, tres vulnerabilidades
sobre una app de gestión de un *car meet*. Proyecto académico de la asignatura de
Ciberseguridad (Universidad Tecmilenio).

> ⚠️ **Vulnerabilidades intencionales.** El servidor contiene fallos deliberados y
> documentados, gobernados por el flag `SAFE_MODE`, para contrastar versión vulnerable
> vs. corregida. **Solo uso local, datos ficticios. No desplegar en ninguna red ni nube.**

---

## Arquitectura

```
Mac (host local)
├─ Servidor Paddock vulnerable   (Python stdlib + SQLite)   http://127.0.0.1:3000
│    └─ paddock.db  (seed de datos ficticios)
└─ Cliente atacante iOS          (SwiftUI, Simulator)        → URLSession → :3000
        └─ bitácora de evidencia in-app (export JSON)
```

| Pieza | Protocolo | Implementación real | Motivo |
|-------|-----------|---------------------|--------|
| Servidor Paddock | Android/Kotlin | **Python stdlib + SQLite** local en el Mac | sin emulador Android; reproducible, cero dependencias |
| Cliente atacante | iOS/Swift | **iOS/SwiftUI** (`PaddockAttacker`, target `PaddockAttacker`) | igual al protocolo |
| Identidad (Cognito) | Amazon Cognito | **stub JWT local** (RS256 + JWKS local) | probar AUTH sin cuenta AWS; intercambiable por Cognito real |

---

## Estructura del repositorio

```
paddock/
├─ proyecto ciberseguridad/     Protocolo (docx/pdf) y diagramas UML del proyecto
├─ cars/                        App web PHP/MySQL original (referencia de diseño y modelo de datos)
│   ├─ site/                    HTML + CSS + JS + APIs PHP (api-inscripcion, api-pases, admin)
│   └─ paddock_cdmx.sql         Esquema MySQL base (adaptado a SQLite en el servidor)
├─ paddock-server/              ★ Servidor vulnerable local (Python)
│   ├─ server.py                router + endpoints (vulns gobernadas por SAFE_MODE)
│   ├─ db.py                    capa SQLite
│   ├─ seed.py                  datos ficticios del protocolo
│   ├─ auth.py                  verificación JWT RS256 contra JWKS local (Python puro)
│   ├─ tools/mint_token.py      generador de tokens de prueba
│   ├─ keys/                    private.pem · private.json (firma) · jwks.json (verificación)
│   └─ README.md                detalle del servidor
└─ PaddockAttacker/            ★ Cliente atacante iOS (Xcode 27)
    ├─ PaddockAttacker/
    │   ├─ PaddockClient.swift   cliente HTTP (URLSession)
    │   ├─ EvidenceLog.swift     bitácora de evidencia + redacción + export JSON
    │   ├─ Scenarios.swift       orquestador de escenarios + prueba de carga
    │   └─ ContentView.swift     interfaz
    └─ Info.plist               ATS: NSAllowsLocalNetworking (http a localhost)
```

---

## Requisitos

- macOS con **Python 3.10+** (viene con el sistema; sin librerías externas)
- **Xcode 27+** con un simulador de iOS (target de despliegue iOS 27.2)
- `openssl` solo si quieres regenerar las llaves (ya vienen generadas)

---

## Puesta en marcha

### 1. Servidor Paddock (terminal)

```bash
cd paddock-server
python3 seed.py                       # crea/reinicia paddock.db con datos ficticios
SAFE_MODE=false python3 server.py     # versión VULNERABLE (demostrar explotación)
# SAFE_MODE=true python3 server.py    # versión CORREGIDA (contraste)
```

Queda escuchando en `http://127.0.0.1:3000`. Variable `PORT` para cambiar el puerto.

### 2. Cliente atacante iOS (Xcode)

1. Abrir `PaddockAttacker/PaddockAttacker.xcodeproj`.
2. Seleccionar el target **PaddockAttacker** y un simulador de iPhone.
3. ▶︎ Run.
4. En la app: **Probar conexión** (debe decir `OK`), luego ejecutar cada escenario.
5. Compartir la bitácora con el botón ⬆︎ (export JSON) como evidencia.

> El simulador comparte la red del Mac, por eso alcanza `127.0.0.1:3000`. El `Info.plist`
> habilita HTTP en claro hacia loopback (`NSAllowsLocalNetworking`).

---

## Escenarios (protocolo §5)

| Caso | Endpoint | Qué demuestra | Esperado (vuln / safe) |
|------|----------|---------------|------------------------|
| **VULN-SQL-01** | `GET /api/vehicles/search?q=&category=` | Inyección SQL: `q`/`category` concatenados. Booleano `' OR '1'='1` + `UNION` para fuga de otra tabla | más filas / sin diferencia |
| **VULN-VAL-01** | `POST /api/registrations` | Bypass: el servicio persiste sin revalidar placas/categoría (validación vivía solo en la UI) | 201 / 422 |
| **VULN-LOAD-01** | `POST /api/registrations` | Carga de origen único con límites: ≤60 s, ≤20 concurrentes, ≤1500 reqs, auto-corte si error-rate>40% (10 s) o p95>5 s (15 s) | ↑ latencia/errores |
| **AUTH-01** | `GET /api/admin/reports` | Token Admin válido | **200** |
| **AUTH-02** | `GET /api/admin/reports` | Sin token | **401** |
| **AUTH-03** | `GET /api/admin/reports` | Token con firma alterada | **401** |
| **AUTH-04** | `GET /api/admin/reports` | Token expirado | **401** |
| **AUTH-05** | `GET /api/admin/reports` | Token válido sin grupo Admin (Participante) | **403** |

Las rutas `/api/admin/*` **nunca** son vulnerables: exigen JWT válido + grupo `Admin` en ambos modos.

---

## Verificación rápida (curl)

```bash
# SQLi: la inyección devuelve MÁS filas que el filtro legítimo
curl 'http://127.0.0.1:3000/api/vehicles/search?q=ABC-123-D'               # 1 fila
curl "http://127.0.0.1:3000/api/vehicles/search?q=%27%20OR%20%271%27=%271"  # 3 filas

# Bypass: 201 en modo vulnerable, 422 en modo seguro
curl -XPOST http://127.0.0.1:3000/api/registrations \
     -H 'Content-Type: application/json' \
     -d '{"plate":"###","categoryId":99999,"ownerName":"X"}'

# Admin: 200 con token Admin
T=$(curl -s 'http://127.0.0.1:3000/api/_lab/token?kind=admin' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -H "Authorization: Bearer $T" http://127.0.0.1:3000/api/admin/reports
```

---

## Migrar el stub a Amazon Cognito real

El cliente iOS y el servidor no cambian; solo se ajusta la verificación en `paddock-server/auth.py`
(o por variables de entorno):

```bash
export PADDOCK_ISS="https://cognito-idp.<region>.amazonaws.com/<userPoolId>"
export PADDOCK_AUD="<app-client-id>"
export PADDOCK_JWKS="<ruta al JWKS del User Pool>"   # .well-known/jwks.json
```

Y los tokens dejan de pedirse a `/api/_lab/token` para obtenerse del Hosted UI / SDK Amplify.

---

## Datos ficticios (protocolo §4.5)

- Usuarios: `Jane Admin` (grupo Admin), `Pedro Participante`
- Vehículos: `ABC-123-D` (Classic), `XYZ-987-A` (Modified), `SUP-444-B` (JDM)
- Categorías: Classic · Modified · JDM · Muscle · Euro

**Ningún dato real se utiliza.** La bitácora del cliente redacta tokens JWT y recorta
las respuestas a un extracto no sensible.

---

## Equipo

Alexis Osmar Payan Carvajal · Noe Alexandro Munguía Gómez · Santiago Vidal Sánchez Martínez · Santiago Gutierrez Rivera
Docente: Dr. Jordi González — Ingeniería en Desarrollo de Software, Universidad Tecmilenio.
