import SwiftUI

struct ContentView: View {
    @State private var runner = ScenarioRunner()
    @State private var log = EvidenceLog()
    @State private var health = "—"

    var body: some View {
        NavigationStack {
            List {
                serverSection
                scenariosSection
                if !runner.metrics.stopReason.isEmpty || runner.current == Scenario.load.rawValue {
                    loadSection
                }
                evidenceSection
            }
            .navigationTitle("Paddock · Atacante")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: log.exportJSON(),
                              preview: SharePreview("bitacora.json")) {
                        Image(systemName: "square.and.arrow.up")
                    }.disabled(log.entries.isEmpty)
                }
            }
        }
    }

    // MARK: servidor

    private var serverSection: some View {
        Section("Servidor objetivo") {
            TextField("http://127.0.0.1:3000", text: $runner.baseURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.callout.monospaced())
            HStack {
                Button("Probar conexión") {
                    Task {
                        let r = await runner.client.request(method: "GET", path: "/health")
                        health = r.status == 200 ? "OK · \(r.body)" : "falló (\(r.statusLabel))"
                    }
                }
                Spacer()
                Text(health).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    // MARK: escenarios

    private var scenariosSection: some View {
        Section("Escenarios") {
            ForEach(Scenario.allCases) { s in
                Button {
                    Task { await runner.run(s, log: log) }
                } label: {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(s.rawValue) · \(s.title)").font(.subheadline.bold())
                            Text(s.detail).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if runner.current == s.rawValue { ProgressView() }
                        else { Image(systemName: "play.circle").foregroundStyle(.tint) }
                    }
                }
                .disabled(runner.isRunning)
            }
        }
    }

    // MARK: carga

    private var loadSection: some View {
        Section("Carga en vivo") {
            let m = runner.metrics
            grid(m)
            if runner.current == Scenario.load.rawValue {
                Button(role: .destructive) { runner.cancel() } label: {
                    Label("Detener", systemImage: "stop.circle")
                }
            }
            if !m.stopReason.isEmpty {
                Text("Corte: \(m.stopReason)").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func grid(_ m: LoadMetrics) -> some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
            GridRow { stat("Enviadas", "\(m.sent)"); stat("En vuelo", "\(m.inFlight)") }
            GridRow { stat("OK", "\(m.ok)"); stat("Fallidas", "\(m.failed)") }
            GridRow { stat("p95", "\(Int(m.p95ms)) ms"); stat("Error", "\(Int(m.errorRate*100))%") }
            GridRow { stat("Tiempo", String(format: "%.1f s", m.elapsed)); Color.clear.frame(height: 1) }
        }
    }

    private func stat(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading) {
            Text(k).font(.caption2).foregroundStyle(.secondary)
            Text(v).font(.callout.monospaced().bold())
        }
    }

    // MARK: bitácora

    private var evidenceSection: some View {
        Section {
            if log.entries.isEmpty {
                Text("Sin evidencia aún. Ejecuta un escenario.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(log.entries) { e in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(e.scenario).font(.caption.bold())
                            Spacer()
                            Text("\(e.method) · \(e.statusLabel)")
                                .font(.caption.monospaced())
                                .foregroundStyle(statusColor(e.status))
                        }
                        Text(e.note).font(.caption2).foregroundStyle(.secondary)
                        Text(e.responseExcerpt).font(.caption2.monospaced()).lineLimit(4)
                    }.padding(.vertical, 2)
                }
            }
        } header: {
            HStack {
                Text("Bitácora (\(log.entries.count))")
                Spacer()
                if !log.entries.isEmpty {
                    Button("Limpiar") { log.clear() }.font(.caption)
                }
            }
        }
    }

    private func statusColor(_ s: Int) -> Color {
        switch s {
        case 200...299: return .green
        case 400...499: return .orange
        case 500...599, ..<0: return .red
        default: return .secondary
        }
    }
}

#Preview {
    ContentView()
}
