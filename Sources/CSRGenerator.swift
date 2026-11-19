import Foundation
import OpenSSL

enum CSRGeneratorError: Error, LocalizedError {
    case requestCreationFailed
    case subjectConfigurationFailed
    case signingFailed
    case encodingFailed

    var errorDescription: String? {
        switch self {
        case .requestCreationFailed:
            return "The certificate signing request could not be created."
        case .subjectConfigurationFailed:
            return "The request subject could not be configured."
        case .signingFailed:
            return "The certificate signing request could not be signed."
        case .encodingFailed:
            return "The request output could not be encoded."
        }
    }
}

struct CSRSubject {
    var commonName: String
    var emailAddress: String
    var organization: String
    var country: String
}

struct CSRGenerationRequest {
    var subject: CSRSubject
    var keySizeInBits: UInt32
}

struct CSRBundle {
    var certificateSigningRequest: Data
    var privateKey: Data
}

struct CSRGenerator {
    private static let multiByteStringAscii: Int32 = 0x1000 | 1

    static func generate(request: CSRGenerationRequest) throws -> CSRBundle {
        let privateKey = try CryptoKeyFactory.generatePrivateKey(sizeInBits: request.keySizeInBits)
        defer { EVP_PKEY_free(privateKey) }

        guard let signingRequest = X509_REQ_new() else {
            throw CSRGeneratorError.requestCreationFailed
        }
        defer { X509_REQ_free(signingRequest) }

        X509_REQ_set_version(signingRequest, 0)

        guard X509_REQ_set_pubkey(signingRequest, privateKey) == 1 else {
            throw CSRGeneratorError.requestCreationFailed
        }

        guard let subjectName = X509_REQ_get_subject_name(signingRequest) else {
            throw CSRGeneratorError.subjectConfigurationFailed
        }

        try addSubjectEntry(to: subjectName, field: "CN", value: request.subject.commonName)

        let email = request.subject.emailAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        if !email.isEmpty {
            try addSubjectEntry(to: subjectName, field: "emailAddress", value: email)
        }

        let organization = request.subject.organization.trimmingCharacters(in: .whitespacesAndNewlines)
        if !organization.isEmpty {
            try addSubjectEntry(to: subjectName, field: "O", value: organization)
        }

        let country = request.subject.country.trimmingCharacters(in: .whitespacesAndNewlines)
        if !country.isEmpty {
            try addSubjectEntry(to: subjectName, field: "C", value: country)
        }

        guard X509_REQ_sign(signingRequest, privateKey, EVP_sha256()) > 0 else {
            throw CSRGeneratorError.signingFailed
        }

        let requestData = try encodePEM { bio in
            PEM_write_bio_X509_REQ(bio, signingRequest)
        }
        let keyData = try encodePEM { bio in
            PEM_write_bio_PrivateKey(bio, privateKey, nil, nil, 0, nil, nil)
        }

        return CSRBundle(certificateSigningRequest: requestData, privateKey: keyData)
    }

    private static func addSubjectEntry(to name: OpaquePointer, field: String, value: String) throws {
        let valueBytes = Array(value.utf8)
        let outcome = valueBytes.withUnsafeBufferPointer { buffer -> Int32 in
            X509_NAME_add_entry_by_txt(
                name,
                field,
                multiByteStringAscii,
                buffer.baseAddress,
                Int32(buffer.count),
                -1,
                0
            )
        }
        guard outcome == 1 else {
            throw CSRGeneratorError.subjectConfigurationFailed
        }
    }

    private static func encodePEM(_ write: (OpaquePointer) -> Int32) throws -> Data {
        guard let memoryMethod = BIO_s_mem(), let bio = BIO_new(memoryMethod) else {
            throw CSRGeneratorError.encodingFailed
        }
        defer { BIO_free(bio) }

        guard write(bio) == 1 else {
            throw CSRGeneratorError.encodingFailed
        }

        var result = Data()
        let chunkSize = 4096
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer -> Int32 in
                BIO_read(bio, rawBuffer.baseAddress, Int32(chunkSize))
            }
            if bytesRead <= 0 {
                break
            }
            result.append(contentsOf: buffer[0..<Int(bytesRead)])
        }

        guard !result.isEmpty else {
            throw CSRGeneratorError.encodingFailed
        }
        return result
    }
}
