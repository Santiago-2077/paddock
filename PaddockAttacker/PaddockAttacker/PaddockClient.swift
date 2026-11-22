import Foundation

/// Resultado de una petición HTTP (Sendable para usarse entre tareas).
struct HTTPResult: Sendable {
    let method: String
    let url: String
    let requestBody: String?
    let status: Int
    let body: String
    let elapsed: TimeInterval
    let error: String?

    var statusLabel: String { status < 0 ? "ERR" : String(status) }
}

/// Cliente del laboratorio: envía solicitudes HTTP al servidor Paddock local.
/// Todas las peticiones de explotación salen de aquí (rol atacante iOS, protocolo §4.2).
struct PaddockClient: Sendable {
    var baseURL: String

    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 10
        c.waitsForConnectivity = false
        return URLSession(configuration: c)
    }()

    // MARK: peticiones genéricas (nonisolated -> concurrencia real en carga)

    nonisolated func request(method: String,
                             path: String,
                             query: [String: String] = [:],
                             jsonBody: [String: Any]? = nil,
                             bearer: String? = nil) async -> HTTPResult {
        var comps = URLComponents(string: baseURL + path) ?? URLComponents()
        if !query.isEmpty {
            comps.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
        }
        let urlStr = comps.url?.absoluteString ?? (baseURL + path)
        guard let url = comps.url else {
            return HTTPResult(method: method, url: urlStr, requestBody: nil,
                              status: -1, body: "", elapsed: 0, error: "URL inválida")
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        var bodyStr: String? = nil
        if let jsonBody {
            let data = try? JSONSerialization.data(withJSONObject: jsonBody)
            req.httpBody = data
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            bodyStr = data.flatMap { String(data: $0, encoding: .utf8) }
        }
        if let bearer {
            req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }

        let start = Date()
        do {
            let (data, resp) = try await Self.session.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            let text = String(data: data, encoding: .utf8) ?? ""
            return HTTPResult(method: method, url: urlStr, requestBody: bodyStr,
                              status: code, body: text,
                              elapsed: Date().timeIntervalSince(start), error: nil)
        } catch {
            return HTTPResult(method: method, url: urlStr, requestBody: bodyStr,
                              status: -1, body: "", elapsed: Date().timeIntervalSince(start),
                              error: error.localizedDescription)
        }
    }

    // MARK: atajos de dominio

    nonisolated func searchVehicles(q: String = "", category: String = "") async -> HTTPResult {
        var qp: [String: String] = [:]
        if !q.isEmpty { qp["q"] = q }
        if !category.isEmpty { qp["category"] = category }
        return await request(method: "GET", path: "/api/vehicles/search", query: qp)
    }

    nonisolated func register(_ payload: [String: Any]) async -> HTTPResult {
        await request(method: "POST", path: "/api/registrations", jsonBody: payload)
    }

    nonisolated func adminReports(bearer: String?) async -> HTTPResult {
        await request(method: "GET", path: "/api/admin/reports", bearer: bearer)
    }

    /// Obtiene un token de prueba del endpoint de laboratorio (sustituye a Cognito en local).
    nonisolated func labToken(kind: String) async -> String? {
        let r = await request(method: "GET", path: "/api/_lab/token", query: ["kind": kind])
        guard r.status == 200,
              let data = r.body.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj["token"] as? String
    }
}
