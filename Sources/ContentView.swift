import SwiftUI
import UniformTypeIdentifiers

struct PKCS12File: FileDocument {
    static var readableContentTypes: [UTType] { [.pkcs12] }

    var data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        self.data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct ContentView: View {
    @State private var commonName: String = "iOS Signing Certificate"
    @State private var password: String = ""
    @State private var selectedKeySize: Int = 2048
    @State private var validityInDays: Int = 3650

    @State private var isGenerating: Bool = false
    @State private var statusMessage: String = ""
    @State private var statusIsError: Bool = false

    @State private var generatedDocument: PKCS12File?
    @State private var isExporting: Bool = false
    @State private var exportFileName: String = "certificate"

    private let availableKeySizes: [Int] = [2048, 4096]

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Certificate Details")) {
                    TextField("Common Name", text: $commonName)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.words)

                    Picker("Key Size", selection: $selectedKeySize) {
                        ForEach(availableKeySizes, id: \.self) { size in
                            Text("\(size) bits").tag(size)
                        }
                    }

                    Stepper(value: $validityInDays, in: 365...7300, step: 365) {
                        Text("Validity: \(validityInDays / 365) years")
                    }
                }

                Section(header: Text("Protection")) {
                    SecureField("Export Password", text: $password)
                    Text("Leave empty to create a container without a password.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                Section {
                    Button(action: startGeneration) {
                        HStack {
                            if isGenerating {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text(isGenerating ? "Generating" : "Generate PKCS12 File")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(isGenerating || commonName.trimmingCharacters(in: .whitespaces).isEmpty)
                }

                if !statusMessage.isEmpty {
                    Section {
                        Text(statusMessage)
                            .foregroundColor(statusIsError ? .red : .green)
                    }
                }
            }
            .navigationTitle("P12 Maker")
            .fileExporter(
                isPresented: $isExporting,
                document: generatedDocument,
                contentType: .pkcs12,
                defaultFilename: exportFileName
            ) { result in
                switch result {
                case .success(let url):
                    statusIsError = false
                    statusMessage = "Saved to \(url.lastPathComponent)."
                case .failure(let error):
                    statusIsError = true
                    statusMessage = error.localizedDescription
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    private func startGeneration() {
        isGenerating = true
        statusMessage = ""
        statusIsError = false

        let request = P12GenerationRequest(
            commonName: commonName.trimmingCharacters(in: .whitespacesAndNewlines),
            password: password,
            keySizeInBits: UInt32(selectedKeySize),
            validityInDays: validityInDays
        )
        let sanitizedName = sanitizedFileName(from: request.commonName)

        Task.detached(priority: .userInitiated) {
            do {
                let data = try P12Generator.generate(request: request)
                await MainActor.run {
                    generatedDocument = PKCS12File(data: data)
                    exportFileName = sanitizedName
                    isGenerating = false
                    statusIsError = false
                    statusMessage = "Generated \(data.count) bytes. Choose a location to save."
                    isExporting = true
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
        return result.isEmpty ? "certificate" : result
    }
}
