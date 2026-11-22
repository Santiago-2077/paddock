# Documentación — Cliente atacante iOS (Paddock Lab)

Documento de referencia sobre la aplicación iOS del laboratorio Paddock. Sirve como base
para elaborar la presentación del proyecto. Cubre propósito, arquitectura, cada componente,
flujo de datos, escenarios de ataque, manejo de evidencia y cómo se ejecuta.

- **Asignatura:** Ciberseguridad — Universidad Tecmilenio
- **Rol de la app:** cliente atacante (protocolo §4.1, §4.2)
- **Objetivos relacionados:** OE2 (cliente atacante repetible) y OE4 (ejecución de pruebas)
- **Proyecto Xcode:** `PaddockAttacker` · target `PaddockAttacker` · SwiftUI · iOS 27.2 · Xcode 27

---

## 1. Propósito y rol en el proyecto

El protocolo divide el laboratorio en dos aplicaciones locales que se comunican por HTTP:

1. **Servidor Paddock** (vulnerable) — objetivo de los ataques. En este proyecto corre en el
   Mac (Python + SQLite, puerto 3000).
2. **Cliente atacante iOS** — *esta app*. Genera interacciones controladas que demuestran
   los escenarios de explotación y registra la evidencia.

La app **no** es la aplicación Paddock para usuarios finales: es la herramienta del atacante.
Su valor académico es hacer cada explotación **repetible y evidenciable** (OE2 exige poder
ejecutar cada escenario al menos 3 veces con el mismo procedimiento).

---

## 2. Arquitectura de la app

Cuatro archivos Swift, responsabilidad única cada uno, en capas:

```
┌──────────────────────────────────────────────────────┐
│ ContentView.swift        (Capa de presentación / UI)  │
│   · lista de escenarios, métricas de carga, bitácora  │
└───────────────┬──────────────────────────────────────┘
                │ llama
┌───────────────▼──────────────────────────────────────┐
│ ScenarioRunner (Scenarios.swift)   (Orquestación)     │
│   · define los 8 escenarios                           │
│   · ejecuta y mide (incl. prueba de carga)            │
└───────┬───────────────────────────┬──────────────────┘
        │ usa                        │ escribe
┌───────▼─────────────┐   ┌──────────▼──────────────────┐
│ PaddockClient.swift │   │ EvidenceLog.swift           │
│ (Transporte HTTP)   │   │ (Bitácora de evidencia)     │
│  · URLSession async │   │  · redacción JWT/PII        │
│  · GET/POST/headers │   │  · export a JSON            │
└─────────────────────┘   └─────────────────────────────┘
```

Patrón: **MVVM ligero**. La vista observa el estado (`@Observable`), el `ScenarioRunner` es
el *view-model* que coordina, `PaddockClient` aísla la red y `EvidenceLog` aísla la evidencia.

---

## 3. Componentes en detalle

### 3.1 `PaddockClient.swift` — transporte HTTP

- `struct PaddockClient: Sendable` con la `baseURL` del servidor.
- `URLSession` efímera, timeout 10 s.
- Método genérico `request(method:path:query:jsonBody:bearer:)` → devuelve `HTTPResult`.
- `HTTPResult` (Sendable): método, URL, cuerpo enviado, **status HTTP**, cuerpo de respuesta,
  **tiempo transcurrido** (latencia) y error.
- Atajos de dominio: `searchVehicles(q:category:)`, `register(_:)`, `adminReports(bearer:)`,
  `labToken(kind:)`.
- Los métodos son `nonisolated` para permitir **concurrencia real** durante la prueba de carga
  (el proyecto usa `SWIFT_DEFAULT_ACTOR_ISOLATION=MainActor`, que por defecto serializaría).

> Punto para la presentación: **la latencia se mide aquí**, por petición, y alimenta el p95
> de la prueba de carga.

### 3.2 `EvidenceLog.swift` — bitácora de evidencia

- `@Observable final class EvidenceLog` con un arreglo de `Evidence`.
- `Evidence` (Codable): id, timestamp, escenario (`VULN-SQL-01`…), método, URL, cuerpo,
  status, **extracto de respuesta** y nota de veredicto.
- `record(scenario:result:note:)` crea una entrada por petición.
- **Redacción (cumple protocolo §5 "sin datos sensibles"):**
  - oculta `Bearer <token>` → `Bearer «token-oculto»`
  - oculta cualquier JWT (`eyJ…`) → `«jwt-oculto»`
  - recorta el cuerpo a 600 caracteres (extracto)
- `exportJSON()` → bitácora completa en JSON legible (para adjuntar como evidencia).

### 3.3 `Scenarios.swift` — orquestación y medición

- `enum Scenario` con los 8 casos (título y descripción de cada uno).
- `struct LoadLimits` — límites del protocolo para la carga (ver §6).
- `@Observable class LoadMetrics` — métricas vivas: enviadas, ok, fallidas, en vuelo, **p95 (ms)**,
  **error rate**, tiempo, motivo de corte.
- `@MainActor @Observable class ScenarioRunner`:
  - `run(_:log:)` ejecuta un escenario discreto y registra evidencia.
  - `runLoad(log:limits:)` ejecuta la prueba de carga con auto-corte.
  - `cancel()` para detención manual.

### 3.4 `ContentView.swift` — interfaz

- `NavigationStack` con una `List` de secciones:
  1. **Servidor objetivo** — campo de `baseURL` editable + botón "Probar conexión" (`/health`).
  2. **Escenarios** — un botón por caso; muestra `ProgressView` mientras corre.
  3. **Carga en vivo** — cuadrícula de métricas + botón "Detener".
  4. **Bitácora** — entradas con color por status (verde 2xx, naranja 4xx, rojo 5xx/err).
- Barra superior: **exportar bitácora** (`ShareLink`, JSON) y **limpiar**.

---

## 4. Flujo de datos (una ejecución)

```
Usuario toca un escenario
      │
      ▼
ScenarioRunner.run(scenario)
      │  construye la petición del escenario
      ▼
PaddockClient.request(...) ──HTTP──▶ Servidor Paddock (:3000)
      │                               (vulnerable o seguro según SAFE_MODE)
      ◀────────── HTTPResult ─────────┘  (status, cuerpo, latencia)
      │
      ├─▶ evalúa veredicto (p.ej. ¿201 inesperado? ¿más filas?)
      ▼
EvidenceLog.record(...)  →  entrada en bitácora (redactada)
      │
      ▼
ContentView se refresca (observación) y muestra el resultado
```

---

## 5. Escenarios implementados

| Caso | Acción de la app | Evidencia / veredicto |
|------|------------------|-----------------------|
| **VULN-SQL-01** | 3 peticiones: búsqueda benigna (control), inyección booleana `q=' OR '1'='1`, y `UNION` por `category` | compara conteo de filas; detecta fuga de la tabla `categorias` |
| **VULN-VAL-01** | `POST /api/registrations` con `{plate:"###", categoryId:99999, ownerName:"X"}` | 201 = aceptado pese a datos inválidos (vulnerable); 422 = rechazado (seguro) |
| **VULN-LOAD-01** | ráfaga concurrente contra el registro (ver §6) | métricas p95/error-rate + motivo de corte |
| **AUTH-01** | pide token Admin a `/api/_lab/token`, llama a `/api/admin/reports` | espera **200** |
| **AUTH-02** | llama sin token | espera **401** |
| **AUTH-03** | token con firma alterada (`tampered`) | espera **401** |
| **AUTH-04** | token expirado | espera **401** |
| **AUTH-05** | token de Participante (sin grupo Admin) | espera **403** |

Cada caso escribe en la bitácora un veredicto `✓ esperado N` / `✗ esperaba N, obtuvo M`,
lo que facilita demostrar repetibilidad (OE2).

> Nota: los tokens se obtienen del endpoint de laboratorio `/api/_lab/token`, que sustituye
> a la emisión de Amazon Cognito en el entorno local. La verificación JWT (firma/iss/aud/exp/
> grupo) la hace el servidor; la app solo transporta el token.

---

## 6. Prueba de carga (VULN-LOAD-01) — mecánica

Demuestra **degradación de disponibilidad local** (no es un DDoS). Origen único: la app iOS.

**Límites (protocolo §5, punto 4):**

| Límite | Valor |
|--------|-------|
| Duración máxima | 60 s |
| Concurrencia máxima | 20 tareas |
| Solicitudes máximas | 1500 |
| Auto-corte por errores | error-rate > 40 % sostenido 10 s |
| Auto-corte por latencia | p95 > 5 s sostenido 15 s |
| Corte manual | botón "Detener" |

**Cómo funciona:**
- Un `withTaskGroup` mantiene hasta 20 peticiones en vuelo; al terminar una, lanza la siguiente
  mientras se cumplan los límites.
- Cada respuesta actualiza métricas y dos ventanas deslizantes (10 s para error-rate, 15 s para p95).
- Al cerrar, registra en la bitácora un **resumen** (enviadas, ok, fallidas, p95, error-rate, corte).

**Evidencia esperada:** comparar p95 en reposo (línea base PN-01) contra p95 bajo carga. Es
satisfactoria si el p95 al menos se duplica o el error-rate supera 10 %.

---

## 7. Red y seguridad en la app

- **ATS:** iOS bloquea HTTP en claro por defecto. `Info.plist` habilita
  `NSAppTransportSecurity → NSAllowsLocalNetworking = true`, que permite loopback
  (`127.0.0.1`) sin TLS. Solo afecta a red local.
- **Simulador y red:** el simulador de iOS comparte la red del Mac, por eso `127.0.0.1:3000`
  del simulador llega al servidor del host.
- **No se almacenan secretos:** la app no persiste tokens; los pide al vuelo y la bitácora
  los redacta antes de mostrarlos/exportarlos.
- **Alcance:** la app solo ataca al servidor local del laboratorio con datos ficticios.

---

## 8. Cómo ejecutar (para el demo en vivo)

1. **Servidor** (terminal):
   ```bash
   cd paddock-server
   python3 seed.py
   SAFE_MODE=false python3 server.py      # vulnerable
   ```
2. **App** (Xcode): abrir `PaddockAttacker`, target `PaddockAttacker`, elegir un simulador de iPhone, ▶︎ Run.
3. En la app: **Probar conexión** → `OK`. Ejecutar cada escenario. Exportar bitácora (⬆︎).
4. **Contraste:** reiniciar el servidor con `SAFE_MODE=true` y repetir SQLi/bypass → ahora
   bloqueados. Esto demuestra la corrección (protocolo §4.6).

---

## 9. Limitaciones y trabajo futuro

- La identidad usa un **stub JWT local**, no Amazon Cognito real (se cablea cambiando
  `PADDOCK_ISS`/`PADDOCK_AUD`/`PADDOCK_JWKS` en el servidor; la app no cambia).
- La "bitácora en puerto 4000" del protocolo se implementa como bitácora **in-app + export**
  (no abre un socket 4000); se podría añadir un `NWListener` si se requiere literalmente.
- Las métricas de carga son del lado cliente; para evidencia formal conviene cruzar con
  Logcat/consola del servidor.

---

## 10. Guion sugerido para la presentación

Orden propuesto de diapositivas (una idea por slide):

1. **Portada** — Paddock Lab, equipo, asignatura.
2. **Contexto** — app de car meet, datos personales/vehículo en juego.
3. **Objetivo del cliente iOS** — demostrar 3 vulnerabilidades de forma repetible (OE2/OE4).
4. **Arquitectura del lab** — diagrama servidor ↔ cliente iOS (§2 de este doc + Figura 1 del protocolo).
5. **Arquitectura de la app** — las 4 capas (diagrama §2).
6. **PaddockClient** — cómo se envían las peticiones y se mide la latencia.
7. **EvidenceLog** — qué se registra y cómo se redacta (captura de la bitácora).
8. **VULN-SQL-01** — benigno vs inyectado (captura: diferencia de filas).
9. **VULN-VAL-01** — 201 con datos inválidos (captura).
10. **VULN-LOAD-01** — métricas p95/error-rate + límites y auto-corte (captura del panel).
11. **AUTH-01..05** — tabla de resultados 200/401/403 (captura de la bitácora).
12. **Contraste SAFE_MODE** — mismo ataque, ahora bloqueado.
13. **Conclusiones** — qué se demostró, correcciones, trabajo futuro (Cognito real).

**Capturas recomendadas:** pantalla principal con la lista de escenarios, bitácora con un
resultado SQLi, panel de carga con métricas, y bitácora de AUTH. (Simulador: `⌘S` guarda captura.)

---

### Referencia de archivos

| Archivo | Responsabilidad |
|---------|-----------------|
| `PaddockAttacker/PaddockAttacker/PaddockClient.swift` | transporte HTTP, medición de latencia |
| `PaddockAttacker/PaddockAttacker/EvidenceLog.swift` | bitácora, redacción, export JSON |
| `PaddockAttacker/PaddockAttacker/Scenarios.swift` | escenarios, orquestación, prueba de carga |
| `PaddockAttacker/PaddockAttacker/ContentView.swift` | interfaz |
| `PaddockAttacker/Info.plist` | excepción ATS para localhost |
