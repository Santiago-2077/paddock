import Foundation
import Observation

/// Una entrada de la bitácora de evidencia (protocolo: solicitud, respuesta,
/// códigos HTTP y extractos NO sensibles). Codable para exportar a JSON.
struct Evidence: Identifiable, Codable, Sendable {
    var id = UUID()
    var timestamp: Date = Date()
    var scenario: String      // p.ej. "VULN-SQL-01"
    var method: String
    var url: String
    var requestBody: String?
    var status: Int
    var responseExcerpt: String
    var note: String

    var statusLabel: String { status < 0 ? "ERR" : String(status) }
}

/// Bitácora observable del cliente atacante. Redacta tokens/PII y recorta la
/// respuesta a un extracto, cumpliendo "evidencia sin datos sensibles" (§5).
@Observable
final class EvidenceLog {
    private(set) var entries: [Evidence] = []

    func record(scenario: String, result: HTTPResult, note: String = "") {
        let excerpt = Self.redact(result.body)
        entries.insert(
            Evidence(scenario: scenario,
                     method: result.method,
                     url: Self.redact(result.url),
                     requestBody: result.requestBody.map(Self.redact),
                     status: result.status,
                     responseExcerpt: result.error.map { "⚠︎ \($0)" } ?? excerpt,
                     note: note),
            at: 0)
    }

    func clear() { entries.removeAll() }

    /// Exporta toda la bitácora como JSON legible.
    func exportJSON() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        enc.dateEncodingStrategy = .iso8601
        guard let data = try? enc.encode(entries),
              let str = String(data: data, encoding: .utf8) else { return "[]" }
        return str
    }

    // MARK: redacción

    private static let maxLen = 600
    private static let bearerRE = try! NSRegularExpression(
        pattern: "(?i)(bearer\\s+)[A-Za-z0-9._-]+")
    private static let jwtRE = try! NSRegularExpression(
        pattern: "eyJ[A-Za-z0-9._-]{20,}")

    /// Oculta tokens JWT y recorta a un extracto no sensible.
    static func redact(_ s: String) -> String {
        var out = s
        let range = { NSRange(out.startIndex..<out.endIndex, in: out) }
        out = bearerRE.stringByReplacingMatches(
            in: out, range: range(), withTemplate: "$1«token-oculto»")
        out = jwtRE.stringByReplacingMatches(
            in: out, range: range(), withTemplate: "«jwt-oculto»")
        if out.count > maxLen {
            out = String(out.prefix(maxLen)) + "…[\(out.count) chars]"
        }
        return out
    }
}
