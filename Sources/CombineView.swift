import SwiftUI
import UniformTypeIdentifiers

struct CombineView: View {
    @State private var certificateData: Data?
    @State private var certificateName: String = ""
    @State private var privateKeyData: Data?
    @State private var privateKeyName: String = ""
    @State private var password: String = ""
    @State private var outputName: String = "identity"

    @State private var isImportingCertificate: Bool = false
    @State private var isImportingKey: Bool = false

    @State private var isGenerating: Bool = false
    @State private var statusMessage: String = ""
    @State private var statusIsError: Bool = false

    @State private var shareItems: [URL] = []
    @State private var isSharing: Bool = false

    private var canGenerate: Bool {
        certificateData != nil && privateKeyData != nil && !isGenerating
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    importRow(
                        title: "Certificate",
                        detail: certificateName.isEmpty ? "No file selected" : certificateName,
                        isLoaded: certificateData != nil
                    ) {
                        isImportingCertificate = true
                    }

                    importRow(
                        title: "Private Key",
                        detail: privateKeyName.isEmpty ? "No file selected" : privateKeyName,
                        isLoaded: privateKeyData != nil
                    ) {
                        isImportingKey = true
                    }
                } header: {
                    Text("Inputs")
                } footer: {
                    Text("Use the .cer the authority issued and the .key produced with your signing request.")
                }

                Section(header: Text("Output")) {
                    TextField("File Name", text: $outputName)
                        .autocorrectionDisabled(true)
                    SecureField("Export Password", text: $password)
                    Text("Leave empty to create a container without a password.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                Section {
                    Button(action: startCombine) {
                        HStack {
                            if isGenerating {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text(isGenerating ? "Combining" : "Combine into PKCS12")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(!canGenerate)
                }

                if !statusMessage.isEmpty {
                    Section {
                        Text(statusMessage)
                            .foregroundColor(statusIsError ? .red : .green)
                    }
                }
            }
            .navigationTitle("Combine Identity")
            .fileImporter(
                isPresented: $isImportingCertificate,
                allowedContentTypes: [.data, .item],
                allowsMultipleSelection: false
            ) { result in
                loadFile(result) { data, name in
                    certificateData = data
                    certificateName = name
                }
            }
            .fileImporter(
                isPresented: $isImportingKey,
                allowedContentTypes: [.data, .item],
                allowsMultipleSelection: false
            ) { result in
                loadFile(result) { data, name in
                    privateKeyData = data
                    privateKeyName = name
                }
            }
            .sheet(isPresented: $isSharing) {
                ShareSheet(items: shareItems)
            }
        }
        .navigationViewStyle(.stack)
    }

    private func importRow(title: String, detail: String, isLoaded: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .foregroundColor(.primary)
                    Text(detail)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Image(systemName: isLoaded ? "checkmark.circle.fill" : "square.and.arrow.down")
                    .foregroundColor(isLoaded ? .green : .accentColor)
            }
        }
    }

    private func loadFile(_ result: Result<[URL], Error>, assign: (Data, String) -> Void) {
        statusMessage = ""
        statusIsError = false

        switch result {
        case .failure(let error):
            statusIsError = true
            statusMessage = error.localizedDescription
        case .success(let urls):
            guard let url = urls.first else { return }
            let accessing = url.startAccessingSecurityScopedResource()
            defer {
                if accessing {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            do {
                let data = try Data(contentsOf: url)
                assign(data, url.lastPathComponent)
            } catch {
                statusIsError = true
                statusMessage = error.localizedDescription
            }
        }
    }

    private func startCombine() {
        guard let certificateData = certificateData, let privateKeyData = privateKeyData else {
            return
        }

        isGenerating = true
        statusMessage = ""
        statusIsError = false

        let passwordValue = password
        let baseName = sanitizedFileName(from: outputName)
        let friendlyName = baseName

        Task.detached(priority: .userInitiated) {
            do {
                let data = try IdentityCombiner.combine(
                    certificateData: certificateData,
                    privateKeyData: privateKeyData,
                    password: passwordValue,
                    friendlyName: friendlyName
                )
                let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(baseName).p12")
                try data.write(to: url, options: .atomic)
                await MainActor.run {
                    shareItems = [url]
                    isGenerating = false
                    statusIsError = false
                    statusMessage = "Combined into a \(data.count) byte identity. Save the file."
                    isSharing = true
                }
            } catch {
                await MainActor.run {
                    isGenerating = false
                    statusIsError = true
                    statusMessage = error.localizedDescription
                }
            }
        }
    }

    private func sanitizedFileName(from value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let filtered = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        let result = String(filtered)
        return result.isEmpty ? "identity" : result
    }
}
