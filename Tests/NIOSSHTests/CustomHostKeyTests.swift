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
import NIOEmbedded
import XCTest

@testable import NIOSSH

extension TestCustomPublicKey: NIOSSHVerifyingPublicKeyProtocol {
    private struct InvalidKey: Error {}

    // One key format, two algorithms, as an RSA key has.
    static let signatureAlgorithms = [TestCustomPrivateKey.sha512Algorithm, TestCustomPrivateKey.sha256Algorithm]

    static func read(from buffer: inout ByteBuffer) throws -> TestCustomPublicKey {
        guard let keyBytes = buffer.readSSHString() else {
            throw InvalidKey()
        }
        return TestCustomPublicKey(key: try P256.Signing.PublicKey(x963Representation: keyBytes.readableBytesView))
    }

    func isValidSignature<D: DataProtocol>(_ signature: ByteBuffer, algorithm: String, for data: D) -> Bool {
        var signature = signature
        guard let rawSignature = signature.readSSHString(), signature.readableBytes == 0,
            let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature.readableBytesView)
        else {
            return false
        }

        switch algorithm {
        case TestCustomPrivateKey.sha512Algorithm:
            return self.key.isValidSignature(ecdsaSignature, for: SHA512.hash(data: data))
        case TestCustomPrivateKey.sha256Algorithm:
            return self.key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
        default:
            XCTFail("Asked to verify with \(algorithm), which this type does not list")
            return false
        }
    }
}

final class CustomHostKeyTests: XCTestCase {
    private final class RecordingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var hostKeys: [NIOSSHPublicKey] = []

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            self.hostKeys.append(hostKey)
            validationCompletePromise.succeed(())
        }
    }

    private static let builtInAlgorithms: [Substring] = [
        "ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521",
    ]

    private static let customAlgorithms: [Substring] = [
        "test-p256-sha512@example.com", "test-p256-sha256@example.com",
    ]

    private func makeClient(
        delegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate(),
        _ configure: (inout SSHClientConfiguration) -> Void = { $0.customHostKeyTypes = [TestCustomPublicKey.self] }
    ) -> SSHKeyExchangeStateMachine {
        var configuration = SSHClientConfiguration(
            userAuthDelegate: ExplodingAuthDelegate(),
            serverAuthDelegate: delegate
        )
        configure(&configuration)

        return SSHKeyExchangeStateMachine(
            allocator: ByteBufferAllocator(),
            loop: EmbeddedEventLoop(),
            role: .client(configuration),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
    }

    /// Runs the client up to the point where it awaits the server's reply.
    private func keyExchangeInit(
        _ client: inout SSHKeyExchangeStateMachine,
        server: ScriptedKeyExchangeServer
    ) throws -> (
        clientMessage: SSHMessage.KeyExchangeMessage, serverMessage: SSHMessage.KeyExchangeMessage,
        keyExchangeInit: SSHMessage.KeyExchangeECDHInitMessage
    ) {
        let clientMessage = client.createKeyExchangeMessage()
        client.send(keyExchange: clientMessage)

        let serverMessage = server.keyExchangeMessage()
        guard let response = try client.handle(keyExchange: serverMessage), response.count == 1,
            case .some(.keyExchangeInit(let keyExchangeInit)) = response.first
        else {
            XCTFail("Expected a single key exchange init message")
            throw NIOSSHError.keyExchangeNegotiationFailure
        }
        client.send(keyExchangeInit: keyExchangeInit)

        return (clientMessage, serverMessage, keyExchangeInit)
    }

    /// Runs a key exchange against a scripted server that presents `hostKey` and signs with `signingKey`.
    private func runKeyExchange(
        offering hostKeyAlgorithms: [Substring],
        presenting hostKey: NIOSSHPublicKey,
        signingWith signingKey: NIOSSHPrivateKey,
        delegate: RecordingHostKeysDelegate
    ) throws -> Substring? {
        var client = self.makeClient(delegate: delegate)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: hostKeyAlgorithms)

        let exchange = try self.keyExchangeInit(&client, server: server)
        let negotiated = client._testOnly_negotiatedHostKeyAlgorithm

        let reply = try server.reply(
            clientMessage: exchange.clientMessage,
            serverMessage: exchange.serverMessage,
            keyExchangeInit: exchange.keyExchangeInit,
            presenting: hostKey,
            sign: { try signingKey.sign(digest: $0) }
        )

        // The reply crosses the network, so the client must also be able to read it.
        var bytes = ByteBuffer()
        bytes.writeSSHMessage(.keyExchangeReply(reply))
        guard
            case .some(.keyExchangeReply(let parsedReply)) = try bytes.readSSHMessage(
                customHostKeyTypes: [TestCustomPublicKey.self]
            )
        else {
            XCTFail("Expected a key exchange reply")
            throw NIOSSHError.keyExchangeNegotiationFailure
        }
        XCTAssertEqual(parsedReply, reply)
        XCTAssertEqual(bytes.readableBytes, 0)

        _ = try client.handle(keyExchangeReply: parsedReply)
        return negotiated
    }

    func testCustomHostKeyAlgorithmsAreNotOfferedByDefault() throws {
        let client = self.makeClient { _ in }
        XCTAssertEqual(client.createKeyExchangeMessage().serverHostKeyAlgorithms, Self.builtInAlgorithms)
    }

    func testCustomHostKeyAlgorithmsAreOfferedAfterTheBuiltInOnes() throws {
        let client = self.makeClient()
        XCTAssertEqual(
            client.createKeyExchangeMessage().serverHostKeyAlgorithms,
            Self.builtInAlgorithms + Self.customAlgorithms
        )
    }

    func testCustomHostKeyAlgorithmsAreOfferedAfterHostCertificateAlgorithms() throws {
        let client = self.makeClient {
            $0.advertiseHostCertificateAlgorithms = true
            $0.customHostKeyTypes = [TestCustomPublicKey.self]
        }
        let algorithms = client.createKeyExchangeMessage().serverHostKeyAlgorithms
        XCTAssertEqual(algorithms.count, 10)
        XCTAssertEqual(Array(algorithms.suffix(6)), Self.builtInAlgorithms + Self.customAlgorithms)
    }

    func testKeyExchangeWithCustomHostKey() throws {
        for algorithm in [TestCustomPrivateKey.sha512Algorithm, TestCustomPrivateKey.sha256Algorithm] {
            let delegate = RecordingHostKeysDelegate()
            let hostKey = NIOSSHPrivateKey(custom: TestCustomPrivateKey(signatureAlgorithm: algorithm))

            let negotiated = try self.runKeyExchange(
                offering: [Substring(algorithm)],
                presenting: hostKey.publicKey,
                signingWith: hostKey,
                delegate: delegate
            )

            XCTAssertEqual(negotiated, Substring(algorithm))
            XCTAssertEqual(delegate.hostKeys, [hostKey.publicKey])
        }
    }

    func testBuiltInHostKeyIsPreferredToCustomHostKey() throws {
        let delegate = RecordingHostKeysDelegate()
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

        let negotiated = try self.runKeyExchange(
            offering: ["test-p256-sha512@example.com", "ssh-ed25519"],
            presenting: hostKey.publicKey,
            signingWith: hostKey,
            delegate: delegate
        )

        XCTAssertEqual(negotiated, "ssh-ed25519")
        XCTAssertEqual(delegate.hostKeys, [hostKey.publicKey])
    }

    func testSignatureWithAnotherAlgorithmThanNegotiatedIsRejected() throws {
        // The server negotiates SHA-512 and then signs, correctly, with SHA-256. That is a downgrade.
        let delegate = RecordingHostKeysDelegate()
        let key = P256.Signing.PrivateKey()
        let hostKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(key: key, signatureAlgorithm: TestCustomPrivateKey.sha512Algorithm)
        )
        let signingKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(key: key, signatureAlgorithm: TestCustomPrivateKey.sha256Algorithm)
        )

        XCTAssertThrowsError(
            try self.runKeyExchange(
                offering: ["test-p256-sha512@example.com"],
                presenting: hostKey.publicKey,
                signingWith: signingKey,
                delegate: delegate
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidExchangeHashSignature)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }

    func testCustomHostKeyThatDidNotSignIsRejected() throws {
        let delegate = RecordingHostKeysDelegate()
        let hostKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(signatureAlgorithm: TestCustomPrivateKey.sha512Algorithm)
        )
        let otherKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(signatureAlgorithm: TestCustomPrivateKey.sha512Algorithm)
        )

        XCTAssertThrowsError(
            try self.runKeyExchange(
                offering: ["test-p256-sha512@example.com"],
                presenting: hostKey.publicKey,
                signingWith: otherKey,
                delegate: delegate
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidExchangeHashSignature)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }

    func testBuiltInHostKeyIsRejectedWhenACustomAlgorithmWasNegotiated() throws {
        let delegate = RecordingHostKeysDelegate()
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

        XCTAssertThrowsError(
            try self.runKeyExchange(
                offering: ["test-p256-sha512@example.com"],
                presenting: hostKey.publicKey,
                signingWith: hostKey,
                delegate: delegate
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }

    func testCustomHostKeyIsRejectedWhenABuiltInAlgorithmWasNegotiated() throws {
        let delegate = RecordingHostKeysDelegate()
        let hostKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(signatureAlgorithm: TestCustomPrivateKey.sha512Algorithm)
        )

        XCTAssertThrowsError(
            try self.runKeyExchange(
                offering: ["ssh-ed25519"],
                presenting: hostKey.publicKey,
                signingWith: hostKey,
                delegate: delegate
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }

    func testCustomHostKeyIsUnknownWithoutItsType() throws {
        let hostKey = NIOSSHPrivateKey(custom: TestCustomPrivateKey()).publicKey

        var bytes = ByteBuffer()
        bytes.writeSSHHostKey(hostKey)

        var unknown = bytes
        XCTAssertThrowsError(try unknown.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownPublicKey)
        }

        var known = bytes
        XCTAssertEqual(try known.readSSHHostKey(customKeyTypes: [TestCustomPublicKey.self]), hostKey)
        XCTAssertEqual(known.readableBytes, 0)
    }

    func testCustomHostKeyWithTrailingBytesIsRejected() throws {
        var bytes = ByteBuffer()
        bytes.writeSSHHostKey(NIOSSHPrivateKey(custom: TestCustomPrivateKey()).publicKey)
        bytes.writeInteger(UInt8(0))

        XCTAssertThrowsError(try bytes.readSSHHostKey(customKeyTypes: [TestCustomPublicKey.self])) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testCustomTypesDoNotTakeOverBuiltInKeyFormats() throws {
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey

        var bytes = ByteBuffer()
        bytes.writeSSHHostKey(hostKey)
        XCTAssertEqual(try bytes.readSSHHostKey(customKeyTypes: [TestCustomPublicKey.self]), hostKey)
    }

    func testCustomSignatureIsUnknownWithoutItsAlgorithm() throws {
        let signature = try NIOSSHPrivateKey(custom: TestCustomPrivateKey()).sign(digest: SHA256.hash(data: [1, 2, 3]))

        var bytes = ByteBuffer()
        bytes.writeSSHSignature(signature)

        var unknown = bytes
        XCTAssertThrowsError(try unknown.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownSignature)
        }

        var otherAlgorithm = bytes
        XCTAssertThrowsError(try otherAlgorithm.readSSHSignature(customAlgorithms: ["test-p256-sha512@example.com"])) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .unknownSignature)
        }

        var known = bytes
        XCTAssertEqual(
            try known.readSSHSignature(customAlgorithms: TestCustomPublicKey.signatureAlgorithms),
            signature
        )
        XCTAssertEqual(known.readableBytes, 0)
    }

    func testPublicKeysThatCannotVerifyVerifyNothing() throws {
        struct SigningOnlyPublicKey: NIOSSHPublicKeyProtocol {
            static let publicKeyPrefix = "test-signing-only@example.com"

            func write(to buffer: inout ByteBuffer) -> Int {
                buffer.writeSSHString("key".utf8)
            }
        }

        let digest = SHA256.hash(data: [1, 2, 3])
        let signature = try NIOSSHPrivateKey(custom: TestCustomPrivateKey()).sign(digest: digest)
        XCTAssertFalse(NIOSSHPublicKey(custom: SigningOnlyPublicKey()).isValidSignature(signature, for: digest))
    }

    func testEndToEndWithCustomHostKey() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }

        let delegate = RecordingHostKeysDelegate()
        let hostKey = NIOSSHPrivateKey(
            custom: TestCustomPrivateKey(signatureAlgorithm: TestCustomPrivateKey.sha512Algorithm)
        )

        var harness = TestHarness()
        harness.clientServerAuthDelegate = delegate
        harness.serverHostKeys = [hostKey]
        harness.configureClient = { $0.customHostKeyTypes = [TestCustomPublicKey.self] }

        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertEqual(delegate.hostKeys, [hostKey.publicKey])
        XCTAssertTrue(userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
    }

    func testEndToEndWithCustomHostKeyAndNoTypeForIt() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }

        var harness = TestHarness()
        harness.serverHostKeys = [NIOSSHPrivateKey(custom: TestCustomPrivateKey())]

        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertThrowsError(try channel.interactInMemory()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyExchangeNegotiationFailure)
        }
    }
}
