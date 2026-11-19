import Foundation
import OpenSSL

enum CryptoKeyFactoryError: Error, LocalizedError {
    case generationFailed

    var errorDescription: String? {
        switch self {
        case .generationFailed:
            return "The private key could not be generated."
        }
    }
}

struct CryptoKeyFactory {
    private static let rsaIdentifier: Int32 = 6
    private static let operationKeygen: Int32 = 1 << 2
    private static let controlRsaKeygenBits: Int32 = 0x1000 + 3

    static func generatePrivateKey(sizeInBits: UInt32) throws -> OpaquePointer {
        guard let keyContext = EVP_PKEY_CTX_new_id(rsaIdentifier, nil) else {
            throw CryptoKeyFactoryError.generationFailed
        }
        defer { EVP_PKEY_CTX_free(keyContext) }

        guard EVP_PKEY_keygen_init(keyContext) == 1 else {
            throw CryptoKeyFactoryError.generationFailed
        }

        guard EVP_PKEY_CTX_ctrl(
            keyContext,
            rsaIdentifier,
            operationKeygen,
            controlRsaKeygenBits,
            Int32(sizeInBits),
            nil
        ) > 0 else {
            throw CryptoKeyFactoryError.generationFailed
        }

        var generatedKey: OpaquePointer?
        guard EVP_PKEY_keygen(keyContext, &generatedKey) == 1, let privateKey = generatedKey else {
            throw CryptoKeyFactoryError.generationFailed
        }
        return privateKey
    }
}
