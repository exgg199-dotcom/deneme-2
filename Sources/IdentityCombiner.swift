import Foundation
import OpenSSL

enum IdentityCombinerError: Error, LocalizedError {
    case certificateInvalid
    case privateKeyInvalid
    case keyDoesNotMatchCertificate

    var errorDescription: String? {
        switch self {
        case .certificateInvalid:
            return "The certificate file could not be read. Provide an Apple issued .cer or a PEM certificate."
        case .privateKeyInvalid:
            return "The private key file could not be read. Provide the .key produced with the signing request."
        case .keyDoesNotMatchCertificate:
            return "The private key does not match this certificate."
        }
    }
}

struct IdentityCombiner {
    static func combine(
        certificateData: Data,
        privateKeyData: Data,
        password: String,
        friendlyName: String
    ) throws -> Data {
        guard let certificate = loadCertificate(from: certificateData) else {
            throw IdentityCombinerError.certificateInvalid
        }
        defer { X509_free(certificate) }

        guard let privateKey = loadPrivateKey(from: privateKeyData) else {
            throw IdentityCombinerError.privateKeyInvalid
        }
        defer { EVP_PKEY_free(privateKey) }

        guard X509_check_private_key(certificate, privateKey) == 1 else {
            throw IdentityCombinerError.keyDoesNotMatchCertificate
        }

        return try P12Generator.package(
            privateKey: privateKey,
            certificate: certificate,
            password: password,
            friendlyName: friendlyName
        )
    }

    private static func loadCertificate(from data: Data) -> OpaquePointer? {
        if let bio = makeReadableBIO(from: data) {
            defer { BIO_free(bio) }
            if let certificate = d2i_X509_bio(bio, nil) {
                return certificate
            }
        }
        if let bio = makeReadableBIO(from: data) {
            defer { BIO_free(bio) }
            if let certificate = PEM_read_bio_X509(bio, nil, nil, nil) {
                return certificate
            }
        }
        return nil
    }

    private static func loadPrivateKey(from data: Data) -> OpaquePointer? {
        if let bio = makeReadableBIO(from: data) {
            defer { BIO_free(bio) }
            if let privateKey = PEM_read_bio_PrivateKey(bio, nil, nil, nil) {
                return privateKey
            }
        }
        if let bio = makeReadableBIO(from: data) {
            defer { BIO_free(bio) }
            if let privateKey = d2i_PrivateKey_bio(bio, nil) {
                return privateKey
            }
        }
        return nil
    }

    private static func makeReadableBIO(from data: Data) -> OpaquePointer? {
        guard let memoryMethod = BIO_s_mem(), let bio = BIO_new(memoryMethod) else {
            return nil
        }
        let written = data.withUnsafeBytes { rawBuffer -> Int32 in
            BIO_write(bio, rawBuffer.baseAddress, Int32(data.count))
        }
        guard written == Int32(data.count) else {
            BIO_free(bio)
            return nil
        }
        return bio
    }
}
