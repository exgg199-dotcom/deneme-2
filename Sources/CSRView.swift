import SwiftUI
import UIKit

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

struct CSRView: View {
    @State private var commonName: String = "iOS Development"
    @State private var emailAddress: String = ""
    @State private var organization: String = ""
    @State private var country: String = ""
    @State private var selectedKeySize: Int = 2048

    @State private var isGenerating: Bool = false
    @State private var statusMessage: String = ""
    @State private var statusIsError: Bool = false

    @State private var shareItems: [URL] = []
    @State private var isSharing: Bool = false

    private let availableKeySizes: [Int] = [2048, 4096]

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Request Subject")) {
                    TextField("Common Name", text: $commonName)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.words)

                    TextField("Email Address (optional)", text: $emailAddress)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)

                    TextField("Organization (optional)", text: $organization)
                        .autocorrectionDisabled(true)

                    TextField("Country Code (optional)", text: $country)
                        .autocorrectionDisabled(true)
                        .textInputAutocapitalization(.characters)
                }

                Section(header: Text("Key")) {
                    Picker("Key Size", selection: $selectedKeySize) {
                        ForEach(availableKeySizes, id: \.self) { size in
                            Text("\(size) bits").tag(size)
                        }
                    }
                }

                Section {
                    Button(action: startGeneration) {
                        HStack {
                            if isGenerating {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text(isGenerating ? "Generating" : "Generate Signing Request")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(isGenerating || commonName.trimmingCharacters(in: .whitespaces).isEmpty)
                } footer: {
                    Text("Produces a certificate signing request and its private key. Keep the private key: you pair it with the certificate the authority issues.")
                }

                if !statusMessage.isEmpty {
                    Section {
                        Text(statusMessage)
                            .foregroundColor(statusIsError ? .red : .green)
                    }
                }
            }
            .navigationTitle("Signing Request")
            .sheet(isPresented: $isSharing) {
                ShareSheet(items: shareItems)
            }
        }
        .navigationViewStyle(.stack)
    }

    private func startGeneration() {
        isGenerating = true
        statusMessage = ""
        statusIsError = false

        let request = CSRGenerationRequest(
            subject: CSRSubject(
                commonName: commonName.trimmingCharacters(in: .whitespacesAndNewlines),
                emailAddress: emailAddress,
                organization: organization,
                country: country
            ),
            keySizeInBits: UInt32(selectedKeySize)
        )
        let baseName = sanitizedFileName(from: request.subject.commonName)

        Task.detached(priority: .userInitiated) {
            do {
                let bundle = try CSRGenerator.generate(request: request)
                let urls = try writeBundleToTemporaryFiles(bundle: bundle, baseName: baseName)
                await MainActor.run {
                    shareItems = urls
                    isGenerating = false
                    statusIsError = false
                    statusMessage = "Generated the request and private key. Save both files."
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

    private func writeBundleToTemporaryFiles(bundle: CSRBundle, baseName: String) throws -> [URL] {
        let directory = FileManager.default.temporaryDirectory
        let requestURL = directory.appendingPathComponent("\(baseName).certSigningRequest")
        let keyURL = directory.appendingPathComponent("\(baseName).key")
        try bundle.certificateSigningRequest.write(to: requestURL, options: .atomic)
        try bundle.privateKey.write(to: keyURL, options: .atomic)
        return [requestURL, keyURL]
    }

    private func sanitizedFileName(from value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let filtered = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        let result = String(filtered)
        return result.isEmpty ? "request" : result
    }
}
