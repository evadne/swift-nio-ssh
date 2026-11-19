//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

/// A public key of a kind that NIOSSH does not know: a P256 key under a made-up name.
struct TestCustomPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "test-p256@example.com"

    var key: P256.Signing.PublicKey

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.key.x963Representation)
    }
}

/// The private half of ``TestCustomPublicKey``, which signs under a name that is not the name of its key format.
struct TestCustomPrivateKey: NIOSSHPrivateKeyProtocol {
    static let signatureAlgorithm = "test-p256-sha256@example.com"

    var key = P256.Signing.PrivateKey()

    var signatureAlgorithm: String { Self.signatureAlgorithm }

    var publicKey: any NIOSSHPublicKeyProtocol {
        TestCustomPublicKey(key: self.key.publicKey)
    }

    func signature<D: DataProtocol>(for data: D) throws -> ByteBuffer {
        var buffer = ByteBuffer()
        buffer.writeSSHString(try self.key.signature(for: data).rawRepresentation)
        return buffer
    }
}

final class CustomKeyTests: XCTestCase {
    private struct SigningError: Error {}

    /// A key that uses the default signature algorithm and that cannot sign.
    private struct UnusableCustomPrivateKey: NIOSSHPrivateKeyProtocol {
        var publicKey: any NIOSSHPublicKeyProtocol {
            TestCustomPublicKey(key: P256.Signing.PrivateKey().publicKey)
        }

        func signature<D: DataProtocol>(for data: D) throws -> ByteBuffer {
            throw SigningError()
        }
    }

    private func makeRequest(
        _ privateKey: NIOSSHPrivateKey,
        sessionID: ByteBuffer
    ) throws -> SSHMessage.UserAuthRequestMessage {
        try SSHMessage.UserAuthRequestMessage(
            request: .init(username: "foo", serviceName: "", offer: .privateKey(.init(privateKey: privateKey))),
            sessionID: sessionID
        )
    }

    func testCustomPublicKeyIsWrittenWithItsPrefix() throws {
        let customKey = TestCustomPrivateKey()
        let publicKey = NIOSSHPublicKey(custom: TestCustomPublicKey(key: customKey.key.publicKey))

        var buffer = ByteBuffer()
        buffer.writeSSHHostKey(publicKey)

        XCTAssertEqual(buffer.readSSHStringAsString(), "test-p256@example.com")
        XCTAssertEqual(
            buffer.readSSHString().map { Array($0.readableBytesView) },
            Array(customKey.key.publicKey.x963Representation)
        )
        XCTAssertEqual(buffer.readableBytes, 0)

        XCTAssertTrue(String(openSSHPublicKey: publicKey).hasPrefix("test-p256@example.com "))
    }

    func testCustomPublicKeysCompareByPrefixAndBytes() throws {
        let first = TestCustomPrivateKey()
        let second = TestCustomPrivateKey()

        let firstKey = NIOSSHPublicKey(custom: TestCustomPublicKey(key: first.key.publicKey))
        let firstKeyAgain = NIOSSHPrivateKey(custom: first).publicKey
        let secondKey = NIOSSHPrivateKey(custom: second).publicKey

        XCTAssertEqual(firstKey, firstKeyAgain)
        XCTAssertEqual(firstKey.hashValue, firstKeyAgain.hashValue)
        XCTAssertNotEqual(firstKey, secondKey)

        // A custom key is never a built-in key, even where the key material is the same.
        XCTAssertNotEqual(firstKey, NIOSSHPrivateKey(p256Key: first.key).publicKey)
        XCTAssertEqual(Set([firstKey, firstKeyAgain, secondKey]).count, 2)
    }

    func testUserAuthRequestIsSignedUnderTheSignatureAlgorithm() throws {
        let customKey = TestCustomPrivateKey()
        let sessionID = ByteBuffer(repeating: 0xAB, count: 32)
        let request = try self.makeRequest(NIOSSHPrivateKey(custom: customKey), sessionID: sessionID)

        var message = ByteBuffer()
        message.writeSSHMessage(.userAuthRequest(request))

        XCTAssertEqual(message.readInteger(as: UInt8.self), SSHMessage.UserAuthRequestMessage.id)
        XCTAssertEqual(message.readSSHStringAsString(), "foo")
        XCTAssertEqual(message.readSSHStringAsString(), "ssh-connection")
        XCTAssertEqual(message.readSSHStringAsString(), "publickey")
        XCTAssertEqual(message.readSSHBoolean(), true)
        // The algorithm is the one the key signs with, not the name of its key format.
        XCTAssertEqual(message.readSSHStringAsString(), "test-p256-sha256@example.com")

        var keyBytes = try XCTUnwrap(message.readSSHString())
        let wholeKey = keyBytes
        XCTAssertEqual(keyBytes.readSSHStringAsString(), "test-p256@example.com")
        XCTAssertEqual(
            keyBytes.readSSHString().map { Array($0.readableBytesView) },
            Array(customKey.key.publicKey.x963Representation)
        )
        XCTAssertEqual(keyBytes.readableBytes, 0)

        var signatureBytes = try XCTUnwrap(message.readSSHString())
        XCTAssertEqual(signatureBytes.readSSHStringAsString(), "test-p256-sha256@example.com")
        let rawSignature = try XCTUnwrap(signatureBytes.readSSHString())
        XCTAssertEqual(signatureBytes.readableBytes, 0)
        XCTAssertEqual(message.readableBytes, 0)

        // The signature must be over the data that RFC 4252 § 7 specifies, which names the same algorithm.
        var signed = ByteBuffer()
        signed.writeSSHString(sessionID.readableBytesView)
        signed.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        signed.writeSSHString("foo".utf8)
        signed.writeSSHString("ssh-connection".utf8)
        signed.writeSSHString("publickey".utf8)
        signed.writeSSHBoolean(true)
        signed.writeSSHString("test-p256-sha256@example.com".utf8)
        signed.writeSSHString(wholeKey.readableBytesView)

        let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature.readableBytesView)
        XCTAssertTrue(customKey.key.publicKey.isValidSignature(signature, for: signed.readableBytesView))
    }

    func testSignatureAlgorithmDefaultsToTheKeyPrefix() throws {
        let privateKey = NIOSSHPrivateKey(custom: UnusableCustomPrivateKey())
        XCTAssertEqual(privateKey.customSignatureAlgorithm, "test-p256@example.com")
        XCTAssertEqual(privateKey.hostKeyAlgorithms, ["test-p256@example.com"])
    }

    func testBuiltInKeysHaveNoCustomSignatureAlgorithm() throws {
        XCTAssertNil(NIOSSHPrivateKey(ed25519Key: .init()).customSignatureAlgorithm)
        XCTAssertNil(NIOSSHPrivateKey(p256Key: .init()).customSignatureAlgorithm)
        XCTAssertNil(NIOSSHPrivateKey(p384Key: .init()).customSignatureAlgorithm)
        XCTAssertNil(NIOSSHPrivateKey(p521Key: .init()).customSignatureAlgorithm)
    }

    func testErrorsFromTheSignerAreThrown() throws {
        let privateKey = NIOSSHPrivateKey(custom: UnusableCustomPrivateKey())
        XCTAssertThrowsError(try self.makeRequest(privateKey, sessionID: ByteBuffer(repeating: 0, count: 32))) {
            error in
            XCTAssertTrue(error is SigningError)
        }
    }

    func testCustomPublicKeysVerifyNothing() throws {
        let customKey = TestCustomPrivateKey()
        let privateKey = NIOSSHPrivateKey(custom: customKey)
        let payload = UserAuthSignablePayload(
            sessionIdentifier: ByteBuffer(repeating: 0xAB, count: 32),
            userName: "foo",
            serviceName: "ssh-connection",
            publicKey: privateKey.publicKey,
            signatureAlgorithm: privateKey.customSignatureAlgorithm
        )
        let signature = try privateKey.sign(payload)

        XCTAssertFalse(privateKey.publicKey.isValidSignature(signature, for: payload))
        XCTAssertFalse(privateKey.publicKey.isValidSignature(signature, for: payload.bytes))
        XCTAssertFalse(privateKey.publicKey.isValidSignature(signature, for: SHA256.hash(data: [1, 2, 3])))
    }

    func testServersTreatCustomKeysAsUnknown() throws {
        let request = try self.makeRequest(
            NIOSSHPrivateKey(custom: TestCustomPrivateKey()),
            sessionID: ByteBuffer(repeating: 0xAB, count: 32)
        )

        var message = ByteBuffer()
        message.writeSSHMessage(.userAuthRequest(request))

        guard case .some(.userAuthRequest(let parsed)) = try message.readSSHMessage() else {
            return XCTFail("Expected a user auth request")
        }
        XCTAssertEqual(parsed.username, "foo")
        XCTAssertEqual(parsed.method, .publicKey(.unknown))
        XCTAssertEqual(message.readableBytes, 0)
    }

    func testCertificatesMayNotUseCustomKeys() throws {
        let customKey = NIOSSHPrivateKey(custom: TestCustomPrivateKey())
        let builtInKey = NIOSSHPrivateKey(p256Key: .init())
        let signature = try builtInKey.sign(digest: SHA256.hash(data: [1, 2, 3, 4]))

        func makeCertificate(key: NIOSSHPublicKey, signatureKey: NIOSSHPublicKey) throws -> NIOSSHCertifiedPublicKey {
            try NIOSSHCertifiedPublicKey(
                nonce: ByteBuffer(repeating: 0x21, count: 32),
                serial: 7,
                type: .user,
                key: key,
                keyID: "test",
                validPrincipals: [],
                validAfter: 0,
                validBefore: .max,
                criticalOptions: [:],
                extensions: [:],
                signatureKey: signatureKey,
                signature: signature
            )
        }

        XCTAssertNoThrow(try makeCertificate(key: builtInKey.publicKey, signatureKey: builtInKey.publicKey))
        XCTAssertThrowsError(try makeCertificate(key: customKey.publicKey, signatureKey: builtInKey.publicKey)) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidCertificate)
        }
        XCTAssertThrowsError(try makeCertificate(key: builtInKey.publicKey, signatureKey: customKey.publicKey)) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidCertificate)
        }
    }
}
