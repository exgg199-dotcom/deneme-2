import Foundation
import OpenSSL

enum P12GeneratorError: Error, LocalizedError {
    case keyGenerationFailed
    case certificateCreationFailed
    case subjectNameFailed
    case signingFailed
    case packagingFailed
    case encodingFailed

    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed:
            return "The private key could not be generated."
        case .certificateCreationFailed:
            return "The certificate structure could not be created."
        case .subjectNameFailed:
            return "The certificate subject could not be configured."
        case .signingFailed:
            return "The certificate could not be self signed."
        case .packagingFailed:
            return "The PKCS12 container could not be assembled."
        case .encodingFailed:
            return "The PKCS12 container could not be encoded."
        }
    }
}

struct P12GenerationRequest {
    var commonName: String
    var password: String
    var keySizeInBits: UInt32
    var validityInDays: Int
}

struct P12Generator {
    private static let aes256CbcNid: Int32 = 419
    private static let multiByteStringAscii: Int32 = 0x1000 | 1

    private static let evpPkeyRsaIdentifier: Int32 = 6
    private static let evpPkeyOperationKeygen: Int32 = 1 << 2
    private static let evpPkeyControlRsaKeygenBits: Int32 = 0x1000 + 3

    static func generate(request: P12GenerationRequest) throws -> Data {
        guard let keyContext = EVP_PKEY_CTX_new_id(evpPkeyRsaIdentifier, nil) else {
            throw P12GeneratorError.keyGenerationFailed
        }
        defer { EVP_PKEY_CTX_free(keyContext) }

        guard EVP_PKEY_keygen_init(keyContext) == 1 else {
            throw P12GeneratorError.keyGenerationFailed
        }

        guard EVP_PKEY_CTX_ctrl(
            keyContext,
            evpPkeyRsaIdentifier,
            evpPkeyOperationKeygen,
            evpPkeyControlRsaKeygenBits,
            Int32(request.keySizeInBits),
            nil
        ) > 0 else {
            throw P12GeneratorError.keyGenerationFailed
        }

        var generatedKey: OpaquePointer?
        guard EVP_PKEY_keygen(keyContext, &generatedKey) == 1, let privateKey = generatedKey else {
            throw P12GeneratorError.keyGenerationFailed
        }
        defer { EVP_PKEY_free(privateKey) }

        guard let certificate = X509_new() else {
            throw P12GeneratorError.certificateCreationFailed
        }
        defer { X509_free(certificate) }

        X509_set_version(certificate, 2)
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), Int(Date().timeIntervalSince1970))
        X509_gmtime_adj(X509_getm_notBefore(certificate), 0)
        X509_gmtime_adj(X509_getm_notAfter(certificate), request.validityInDays * 24 * 60 * 60)

        guard X509_set_pubkey(certificate, privateKey) == 1 else {
            throw P12GeneratorError.certificateCreationFailed
        }

        guard let subjectName = X509_get_subject_name(certificate) else {
            throw P12GeneratorError.subjectNameFailed
        }

        let commonNameBytes = Array(request.commonName.utf8)
        let addedSubject = commonNameBytes.withUnsafeBufferPointer { buffer -> Int32 in
            X509_NAME_add_entry_by_txt(
                subjectName,
                "CN",
                multiByteStringAscii,
                buffer.baseAddress,
                Int32(buffer.count),
                -1,
                0
            )
        }
        guard addedSubject == 1 else {
            throw P12GeneratorError.subjectNameFailed
        }

        guard X509_set_issuer_name(certificate, subjectName) == 1 else {
            throw P12GeneratorError.subjectNameFailed
        }

        guard X509_sign(certificate, privateKey, EVP_sha256()) > 0 else {
            throw P12GeneratorError.signingFailed
        }

        let container = request.password.withCString { passwordPointer in
            "P12Maker".withCString { friendlyNamePointer in
                PKCS12_create(
                    passwordPointer,
                    friendlyNamePointer,
                    privateKey,
                    certificate,
                    nil,
                    aes256CbcNid,
                    aes256CbcNid,
                    2048,
                    1,
                    0
                )
            }
        }
        guard let container = container else {
            throw P12GeneratorError.packagingFailed
        }
        defer { PKCS12_free(container) }

        let length = i2d_PKCS12(container, nil)
        guard length > 0 else {
            throw P12GeneratorError.encodingFailed
        }

        var data = Data(count: Int(length))
        data.withUnsafeMutableBytes { rawBuffer in
            var cursor = rawBuffer.bindMemory(to: UInt8.self).baseAddress
            _ = i2d_PKCS12(container, &cursor)
        }
        return data
    }
}
