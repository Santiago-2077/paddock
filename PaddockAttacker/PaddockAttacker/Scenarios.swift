import Foundation
import Observation

/// Catálogo de escenarios del protocolo (§5).
enum Scenario: String, CaseIterable, Identifiable {
    case sqli      = "VULN-SQL-01"
    case bypass    = "VULN-VAL-01"
    case load      = "VULN-LOAD-01"
    case auth01    = "AUTH-01"
    case auth02    = "AUTH-02"
    case auth03    = "AUTH-03"
    case auth04    = "AUTH-04"
    case auth05    = "AUTH-05"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .sqli:   return "Inyección SQL en búsqueda"
        case .bypass: return "Bypass de validación (solo UI)"
        case .load:   return "Carga controlada (origen único)"
        case .auth01: return "Admin válido → 200"
        case .auth02: return "Sin token → 401"
        case .auth03: return "Token alterado → 401"
        case .auth04: return "Token expirado → 401"
        case .auth05: return "Participante → 403"
        }
    }

    var detail: String {
        switch self {
        case .sqli:   return "Compara búsqueda benigna vs. inyectada (q=' OR '1'='1 y UNION)."
        case .bypass: return "POST con placas/categoría inválidas sin pasar por la UI."
        case .load:   return "Ráfaga ≤60s, ≤20 concurrentes, ≤1500 reqs, auto-corte."
        default:      return "Ruta protegida GET /api/admin/reports."
        }
    }
    var isLoad: Bool { self == .load }
}

/// Límites de la prueba de carga (protocolo VULN-LOAD-01, punto 4).
struct LoadLimits {
    var maxDuration: TimeInterval = 60
    var maxConcurrency = 20
    var maxRequests = 1500
    var abortErrorRate = 0.40     // >40% sostenido 10 s
    var abortErrorWindow: TimeInterval = 10
    var abortP95ms: Double = 5000 // p95 > 5 s sostenido 15 s
    var abortP95Window: TimeInterval = 15
}

/// Métricas vivas de la carga.
@Observable final class LoadMetrics {
    var sent = 0
    var ok = 0
    var failed = 0
    var inFlight = 0
    var p95ms = 0.0
    var errorRate = 0.0
    var elapsed = 0.0
    var stopReason = ""
}

@MainActor
@Observable
final class ScenarioRunner {
    var baseURL: String = "http://127.0.0.1:3000"
    var isRunning = false
    var current: String = ""
    let metrics = LoadMetrics()
    private var cancelLoad = false

    var client: PaddockClient { PaddockClient(baseURL: baseURL) }

    func cancel() { cancelLoad = true }

    // MARK: escenarios discretos

    func run(_ s: Scenario, log: EvidenceLog) async {
        guard !isRunning else { return }
        isRunning = true; current = s.rawValue
        defer { isRunning = false; current = "" }
        let c = client

        switch s {
        case .sqli:
            let benign = await c.searchVehicles(q: "ABC-123-D")
            log.record(scenario: s.rawValue, result: benign, note: "Búsqueda benigna (control)")
            let inj = await c.searchVehicles(q: "' OR '1'='1")
            log.record(scenario: s.rawValue, result: inj,
                       note: "Inyección booleana. \(Self.countNote(benign, inj))")
            let union = await c.searchVehicles(
                category: "zzz' UNION SELECT nombre,nombre,nombre,nombre,nombre,nombre,nombre FROM categorias-- ")
            log.record(scenario: s.rawValue, result: union,
                       note: "UNION: fuga de la tabla categorias si es vulnerable.")

        case .bypass:
            let r = await c.register(["plate": "###", "categoryId": 99999, "ownerName": "X"])
            log.record(scenario: s.rawValue, result: r,
                       note: r.status == 201 ? "ACEPTADO pese a placas/categoría inválidas (vulnerable)."
                                             : "Rechazado (modo seguro).")

        case .auth01: await auth(s, kind: "admin", log: log, expect: 200)
        case .auth02: await auth(s, kind: nil,     log: log, expect: 401)
        case .auth03: await auth(s, kind: "tampered", log: log, expect: 401)
        case .auth04: await auth(s, kind: "expired",  log: log, expect: 401)
        case .auth05: await auth(s, kind: "participante", log: log, expect: 403)

        case .load:
            await runLoad(log: log)
        }
    }

    private func auth(_ s: Scenario, kind: String?, log: EvidenceLog, expect: Int) async {
        let c = client
        var token: String? = nil
        if let kind { token = await c.labToken(kind: kind) }
        let r = await c.adminReports(bearer: token)
        let verdict = r.status == expect ? "✓ esperado \(expect)" : "✗ esperaba \(expect), obtuvo \(r.status)"
        log.record(scenario: s.rawValue, result: r, note: verdict)
    }

    private static func countNote(_ a: HTTPResult, _ b: HTTPResult) -> String {
        func count(_ r: HTTPResult) -> Int {
            guard let d = r.body.data(using: .utf8),
                  let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let n = o["count"] as? Int else { return -1 }
            return n
        }
        let ca = count(a), cb = count(b)
        guard ca >= 0, cb >= 0 else { return "" }
        return cb > ca ? "Inyección devolvió \(cb) vs \(ca) (vulnerable)." : "Sin diferencia (\(cb) vs \(ca))."
    }

    // MARK: carga (VULN-LOAD-01) con límites y auto-corte

    func runLoad(log: EvidenceLog, limits: LoadLimits = LoadLimits()) async {
        cancelLoad = false
        let m = metrics
        m.sent = 0; m.ok = 0; m.failed = 0; m.inFlight = 0
        m.p95ms = 0; m.errorRate = 0; m.elapsed = 0; m.stopReason = ""
        let c = client
        let start = Date()
        var times: [Double] = []
        var window: [(t: Date, ok: Bool, ms: Double)] = []

        func elapsed() -> TimeInterval { Date().timeIntervalSince(start) }
        func canStart() -> Bool {
            !cancelLoad && m.sent < limits.maxRequests && elapsed() < limits.maxDuration && m.stopReason.isEmpty
        }
        func payload() -> [String: Any] {
            ["ownerName": "Load", "plate": "LD\(Int.random(in: 0..<1_000_000))", "categoryId": 1]
        }
        func p95(_ xs: [Double]) -> Double {
            guard !xs.isEmpty else { return 0 }
            let s = xs.sorted(); return s[min(s.count - 1, Int(0.95 * Double(s.count)))]
        }

        await withTaskGroup(of: HTTPResult.self) { group in
            var active = 0
            while active < limits.maxConcurrency && canStart() {
                let p = payload(); group.addTask { await c.register(p) }
                m.sent += 1; active += 1
            }
            m.inFlight = active

            for await r in group {
                active -= 1
                let ms = r.elapsed * 1000
                let good = (200...399).contains(r.status)
                times.append(ms)
                window.append((Date(), good, ms))
                good ? (m.ok += 1) : (m.failed += 1)

                // ventanas deslizantes
                let errCut = Date().addingTimeInterval(-limits.abortErrorWindow)
                let p95Cut = Date().addingTimeInterval(-limits.abortP95Window)
                window.removeAll { $0.t < p95Cut && $0.t < errCut }
                let errWin = window.filter { $0.t >= errCut }
                let p95Win = window.filter { $0.t >= p95Cut }

                m.p95ms = p95(times)
                m.errorRate = times.isEmpty ? 0 : Double(m.failed) / Double(m.ok + m.failed)
                m.elapsed = elapsed()

                // auto-corte "sostenido": la ventana debe cubrir el lapso
                if m.stopReason.isEmpty, errWin.count > 10,
                   (errWin.last!.t.timeIntervalSince(errWin.first!.t)) >= limits.abortErrorWindow {
                    let er = Double(errWin.filter { !$0.ok }.count) / Double(errWin.count)
                    if er > limits.abortErrorRate { m.stopReason = "error-rate \(Int(er*100))% > 40% sostenido" }
                }
                if m.stopReason.isEmpty, p95Win.count > 10,
                   (p95Win.last!.t.timeIntervalSince(p95Win.first!.t)) >= limits.abortP95Window {
                    if p95(p95Win.map { $0.ms }) > limits.abortP95ms { m.stopReason = "p95 > 5s sostenido" }
                }

                if canStart() {
                    let p = payload(); group.addTask { await c.register(p) }
                    m.sent += 1; active += 1
                }
                m.inFlight = active
            }
        }

        if m.stopReason.isEmpty {
            m.stopReason = cancelLoad ? "cancelado manualmente"
                : (elapsed() >= limits.maxDuration ? "límite de tiempo (60s)" : "límite de \(limits.maxRequests) reqs")
        }
        // evidencia resumen (sin PII)
        let summary = HTTPResult(
            method: "LOAD", url: baseURL + "/api/registrations", requestBody: nil,
            status: m.failed == 0 ? 200 : 207,
            body: "enviadas=\(m.sent) ok=\(m.ok) fallidas=\(m.failed) " +
                  "p95=\(Int(m.p95ms))ms errorRate=\(Int(m.errorRate*100))% corte=\(m.stopReason)",
            elapsed: m.elapsed, error: nil)
        log.record(scenario: Scenario.load.rawValue, result: summary,
                   note: "Resumen de carga. p95 base vs. bajo carga = evidencia de disponibilidad.")
    }
}
