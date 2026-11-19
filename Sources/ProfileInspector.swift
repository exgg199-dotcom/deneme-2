import Foundation
import OpenSSL

enum ProfileInspectorError: Error, LocalizedError {
    case notReadable
    case decodeFailed
    case contentMissing
    case propertyListInvalid

    var errorDescription: String? {
        switch self {
        case .notReadable:
            return "The provisioning profile could not be read."
        case .decodeFailed:
            return "The provisioning profile is not a valid signed container."
        case .contentMissing:
            return "The embedded property list could not be extracted."
        case .propertyListInvalid:
            return "The embedded property list could not be parsed."
        }
    }
}

struct ProfileSummary {
    var name: String
    var applicationIdentifier: String
    var teamIdentifier: String
    var teamName: String
    var creationDate: Date?
    var expirationDate: Date?
    var provisionedDeviceCount: Int?
    var certificateCount: Int

    var isExpired: Bool {
        guard let expirationDate = expirationDate else { return false }
        return expirationDate < Date()
    }
}

struct ProfileInspector {
    private static let pkcs7NoSignatures: Int32 = 0x4
    private static let pkcs7NoVerify: Int32 = 0x20

    static func summarize(profileData: Data) throws -> ProfileSummary {
        let propertyListData = try extractPropertyList(from: profileData)

        guard let object = try? PropertyListSerialization.propertyList(
            from: propertyListData,
            options: [],
            format: nil
        ), let dictionary = object as? [String: Any] else {
            throw ProfileInspectorError.propertyListInvalid
        }

        let entitlements = dictionary["Entitlements"] as? [String: Any]
        let teamIdentifiers = dictionary["TeamIdentifier"] as? [String]
        let devices = dictionary["ProvisionedDevices"] as? [String]
        let certificates = dictionary["DeveloperCertificates"] as? [Any]

        return ProfileSummary(
            name: dictionary["Name"] as? String ?? "Unknown",
            applicationIdentifier: entitlements?["application-identifier"] as? String ?? "Unknown",
            teamIdentifier: teamIdentifiers?.first ?? "Unknown",
            teamName: dictionary["TeamName"] as? String ?? "Unknown",
            creationDate: dictionary["CreationDate"] as? Date,
            expirationDate: dictionary["ExpirationDate"] as? Date,
            provisionedDeviceCount: devices?.count,
            certificateCount: certificates?.count ?? 0
        )
    }

    private static func extractPropertyList(from data: Data) throws -> Data {
        guard let memoryMethod = BIO_s_mem(), let inputBio = BIO_new(memoryMethod) else {
            throw ProfileInspectorError.notReadable
        }
        defer { BIO_free(inputBio) }

        let written = data.withUnsafeBytes { rawBuffer -> Int32 in
            BIO_write(inputBio, rawBuffer.baseAddress, Int32(data.count))
        }
        guard written == Int32(data.count) else {
            throw ProfileInspectorError.notReadable
        }

        guard let container = d2i_PKCS7_bio(inputBio, nil) else {
            throw ProfileInspectorError.decodeFailed
        }
        defer { PKCS7_free(container) }

        guard let outputMethod = BIO_s_mem(), let outputBio = BIO_new(outputMethod) else {
            throw ProfileInspectorError.contentMissing
        }
        defer { BIO_free(outputBio) }

        guard PKCS7_verify(
            container,
            nil,
            nil,
            nil,
            outputBio,
            pkcs7NoSignatures | pkcs7NoVerify
        ) == 1 else {
            throw ProfileInspectorError.contentMissing
        }

        var result = Data()
        let chunkSize = 4096
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer -> Int32 in
                BIO_read(outputBio, rawBuffer.baseAddress, Int32(chunkSize))
            }
            if bytesRead <= 0 {
                break
            }
            result.append(contentsOf: buffer[0..<Int(bytesRead)])
        }

        guard !result.isEmpty else {
            throw ProfileInspectorError.contentMissing
        }
        return result
    }
}
