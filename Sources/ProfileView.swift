import SwiftUI
import UniformTypeIdentifiers

struct ProfileView: View {
    @State private var isImporting: Bool = false
    @State private var summary: ProfileSummary?
    @State private var statusMessage: String = ""
    @State private var statusIsError: Bool = false

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Button(action: { isImporting = true }) {
                        Text("Import Provisioning Profile")
                            .fontWeight(.semibold)
                            .frame(maxWidth: .infinity)
                    }
                } footer: {
                    Text("Provisioning profiles are issued and signed by Apple. This reads an existing profile; it cannot create a device valid one.")
                }

                if let summary = summary {
                    Section(header: Text("Profile")) {
                        detailRow(title: "Name", value: summary.name)
                        detailRow(title: "Application Identifier", value: summary.applicationIdentifier)
                        detailRow(title: "Team Name", value: summary.teamName)
                        detailRow(title: "Team Identifier", value: summary.teamIdentifier)
                    }

                    Section(header: Text("Validity")) {
                        if let creationDate = summary.creationDate {
                            detailRow(title: "Created", value: dateFormatter.string(from: creationDate))
                        }
                        if let expirationDate = summary.expirationDate {
                            detailRow(title: "Expires", value: dateFormatter.string(from: expirationDate))
                        }
                        detailRow(
                            title: "Status",
                            value: summary.isExpired ? "Expired" : "Valid",
                            valueColor: summary.isExpired ? .red : .green
                        )
                    }

                    Section(header: Text("Contents")) {
                        detailRow(
                            title: "Provisioned Devices",
                            value: summary.provisionedDeviceCount.map(String.init) ?? "All (distribution)"
                        )
                        detailRow(title: "Developer Certificates", value: String(summary.certificateCount))
                    }
                }

                if !statusMessage.isEmpty {
                    Section {
                        Text(statusMessage)
                            .foregroundColor(statusIsError ? .red : .green)
                    }
                }
            }
            .navigationTitle("Profile Inspector")
            .fileImporter(
                isPresented: $isImporting,
                allowedContentTypes: [.data, .item],
                allowsMultipleSelection: false
            ) { result in
                handleImport(result)
            }
        }
        .navigationViewStyle(.stack)
    }

    private func detailRow(title: String, value: String, valueColor: Color = .primary) -> some View {
        HStack(alignment: .top) {
            Text(title)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .foregroundColor(valueColor)
                .multilineTextAlignment(.trailing)
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        statusMessage = ""
        statusIsError = false

        switch result {
        case .failure(let error):
            statusIsError = true
            statusMessage = error.localizedDescription
        case .success(let urls):
            guard let url = urls.first else {
                statusIsError = true
                statusMessage = "No file was selected."
                return
            }

            let accessing = url.startAccessingSecurityScopedResource()
            defer {
                if accessing {
                    url.stopAccessingSecurityScopedResource()
                }
            }

            do {
                let data = try Data(contentsOf: url)
                let parsed = try ProfileInspector.summarize(profileData: data)
                summary = parsed
                statusIsError = false
                statusMessage = "Read \(url.lastPathComponent)."
            } catch {
                summary = nil
                statusIsError = true
                statusMessage = error.localizedDescription
            }
        }
    }
}
