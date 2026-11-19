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

/// A stand-in for the server side of a `curve25519-sha256` key exchange.
///
/// ``NIOSSH`` servers present their plain host keys only. These tests need a server that presents something else,
/// so this type computes the exchange hash and signs it itself.
struct ScriptedKeyExchangeServer {
    var version: String = Constants.version

    var hostKeyAlgorithms: [Substring]

    func keyExchangeMessage() -> SSHMessage.KeyExchangeMessage {
        .init(
            cookie: ByteBuffer(repeating: 0x5A, count: 16),
            keyExchangeAlgorithms: ["curve25519-sha256"],
            serverHostKeyAlgorithms: self.hostKeyAlgorithms,
            encryptionAlgorithmsClientToServer: ["aes256-gcm@openssh.com"],
            encryptionAlgorithmsServerToClient: ["aes256-gcm@openssh.com"],
            macAlgorithmsClientToServer: ["hmac-sha2-256"],
            macAlgorithmsServerToClient: ["hmac-sha2-256"],
            compressionAlgorithmsClientToServer: ["none"],
            compressionAlgorithmsServerToClient: ["none"],
            languagesClientToServer: [],
            languagesServerToClient: [],
            firstKexPacketFollows: false
        )
    }

    /// Completes the exchange, presenting `hostKey` and signing the exchange hash with `sign`.
    func reply(
        clientVersion: String = Constants.version,
        clientMessage: SSHMessage.KeyExchangeMessage,
        serverMessage: SSHMessage.KeyExchangeMessage,
        keyExchangeInit: SSHMessage.KeyExchangeECDHInitMessage,
        presenting hostKey: NIOSSHPublicKey,
        sign: (SHA256.Digest) throws -> NIOSSHSignature
    ) throws -> SSHMessage.KeyExchangeECDHReplyMessage {
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let clientKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: keyExchangeInit.publicKey.readableBytesView
        )
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: clientKey)

        var exchangeBytes = ByteBuffer()
        exchangeBytes.writeSSHString(clientVersion.utf8)
        exchangeBytes.writeSSHString(self.version.utf8)
        exchangeBytes.writeCompositeSSHString { $0.writeSSHMessage(.keyExchange(clientMessage)) }
        exchangeBytes.writeCompositeSSHString { $0.writeSSHMessage(.keyExchange(serverMessage)) }
        exchangeBytes.writeCompositeSSHString { $0.writeSSHHostKey(hostKey) }
        exchangeBytes.writeSSHString(keyExchangeInit.publicKey.readableBytesView)
        exchangeBytes.writeSSHString(ephemeralKey.publicKey.rawRepresentation)
        sharedSecret.withUnsafeBytes { secretBytes in
            _ = exchangeBytes.writePositiveMPInt(secretBytes)
        }

        let exchangeHash = SHA256.hash(data: exchangeBytes.readableBytesView)

        return .init(
            hostKey: hostKey,
            publicKey: ByteBuffer(bytes: ephemeralKey.publicKey.rawRepresentation),
            signature: try sign(exchangeHash)
        )
    }
}

final class HostCertificateKeyExchangeTests: XCTestCase {
    private final class RecordingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var hostKeys: [NIOSSHPublicKey] = []

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            self.hostKeys.append(hostKey)
            validationCompletePromise.succeed(())
        }
    }

    private static let plainAlgorithms: [Substring] = [
        "ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521",
    ]

    private static let certificateAlgorithms: [Substring] = [
        "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    ]

    private func makeClient(
        advertiseHostCertificateAlgorithms: Bool?,
        delegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate()
    ) -> SSHKeyExchangeStateMachine {
        var configuration = SSHClientConfiguration(
            userAuthDelegate: ExplodingAuthDelegate(),
            serverAuthDelegate: delegate
        )
        if let advertiseHostCertificateAlgorithms = advertiseHostCertificateAlgorithms {
            configuration.advertiseHostCertificateAlgorithms = advertiseHostCertificateAlgorithms
        }

        return SSHKeyExchangeStateMachine(
            allocator: ByteBufferAllocator(),
            loop: EmbeddedEventLoop(),
            role: .client(configuration),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
    }

    /// A host certificate for `hostKey`. The certificate authority's signature is over other data: ``NIOSSH``
    /// does not validate certificates during key exchange, so these tests must pass regardless.
    private func makeHostCertificate(for hostKey: NIOSSHPrivateKey) throws -> NIOSSHPublicKey {
        let authority = NIOSSHPrivateKey(p256Key: .init())
        let certificate = try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0x21, count: 32),
            serial: 7,
            type: .host,
            key: hostKey.publicKey,
            keyID: "test host",
            validPrincipals: ["host.example.com"],
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: authority.publicKey,
            signature: authority.sign(digest: SHA256.hash(data: [1, 2, 3, 4]))
        )
        return NIOSSHPublicKey(certificate)
    }

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

    func testHostCertificateAlgorithmsAreNotOfferedByDefault() throws {
        let client = self.makeClient(advertiseHostCertificateAlgorithms: nil)
        XCTAssertEqual(client.createKeyExchangeMessage().serverHostKeyAlgorithms, Self.plainAlgorithms)
    }

    func testHostCertificateAlgorithmsAreNotOfferedWhenDisabled() throws {
        let client = self.makeClient(advertiseHostCertificateAlgorithms: false)
        XCTAssertEqual(client.createKeyExchangeMessage().serverHostKeyAlgorithms, Self.plainAlgorithms)
    }

    func testHostCertificateAlgorithmsAreOfferedFirstWhenEnabled() throws {
        let client = self.makeClient(advertiseHostCertificateAlgorithms: true)
        XCTAssertEqual(
            client.createKeyExchangeMessage().serverHostKeyAlgorithms,
            Self.certificateAlgorithms + Self.plainAlgorithms
        )
    }

    func testServersNeverOfferHostCertificateAlgorithms() throws {
        let server = SSHKeyExchangeStateMachine(
            allocator: ByteBufferAllocator(),
            loop: EmbeddedEventLoop(),
            role: .server(
                .init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
            ),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        XCTAssertEqual(server.createKeyExchangeMessage().serverHostKeyAlgorithms, ["ssh-ed25519"])
    }

    func testHostCertificateIsNegotiatedAndGivenToTheDelegate() throws {
        let delegate = RecordingHostKeysDelegate()
        var client = self.makeClient(advertiseHostCertificateAlgorithms: true, delegate: delegate)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: ["ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519"])
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let certificate = try self.makeHostCertificate(for: hostKey)

        let exchange = try self.keyExchangeInit(&client, server: server)
        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, "ssh-ed25519-cert-v01@openssh.com")

        let reply = try server.reply(
            clientMessage: exchange.clientMessage,
            serverMessage: exchange.serverMessage,
            keyExchangeInit: exchange.keyExchangeInit,
            presenting: certificate,
            sign: { try hostKey.sign(digest: $0) }
        )
        XCTAssertNoThrow(try client.handle(keyExchangeReply: reply))

        // The delegate is given the certificate as the server presented it, not the plain key within it.
        XCTAssertEqual(delegate.hostKeys, [certificate])
        XCTAssertEqual(delegate.hostKeys.first.flatMap { NIOSSHCertifiedPublicKey($0) }?.key, hostKey.publicKey)
    }

    func testPlainHostKeyIsNegotiatedWhenTheServerHasNoCertificate() throws {
        let delegate = RecordingHostKeysDelegate()
        var client = self.makeClient(advertiseHostCertificateAlgorithms: true, delegate: delegate)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: ["ssh-ed25519"])
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

        let exchange = try self.keyExchangeInit(&client, server: server)
        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, "ssh-ed25519")

        let reply = try server.reply(
            clientMessage: exchange.clientMessage,
            serverMessage: exchange.serverMessage,
            keyExchangeInit: exchange.keyExchangeInit,
            presenting: hostKey.publicKey,
            sign: { try hostKey.sign(digest: $0) }
        )
        XCTAssertNoThrow(try client.handle(keyExchangeReply: reply))
        XCTAssertEqual(delegate.hostKeys, [hostKey.publicKey])
    }

    func testHostCertificateIsNotNegotiatedWhenNotOffered() throws {
        var client = self.makeClient(advertiseHostCertificateAlgorithms: false)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: ["ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519"])

        _ = try self.keyExchangeInit(&client, server: server)
        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, "ssh-ed25519")
    }

    func testPlainHostKeyIsRejectedWhenACertificateWasNegotiated() throws {
        let delegate = RecordingHostKeysDelegate()
        var client = self.makeClient(advertiseHostCertificateAlgorithms: true, delegate: delegate)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: ["ssh-ed25519-cert-v01@openssh.com"])
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())

        let exchange = try self.keyExchangeInit(&client, server: server)
        let reply = try server.reply(
            clientMessage: exchange.clientMessage,
            serverMessage: exchange.serverMessage,
            keyExchangeInit: exchange.keyExchangeInit,
            presenting: hostKey.publicKey,
            sign: { try hostKey.sign(digest: $0) }
        )

        XCTAssertThrowsError(try client.handle(keyExchangeReply: reply)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }

    func testHostCertificateIsRejectedWhenTheServerDoesNotHoldItsKey() throws {
        let delegate = RecordingHostKeysDelegate()
        var client = self.makeClient(advertiseHostCertificateAlgorithms: true, delegate: delegate)
        let server = ScriptedKeyExchangeServer(hostKeyAlgorithms: ["ssh-ed25519-cert-v01@openssh.com"])
        let certificate = try self.makeHostCertificate(for: NIOSSHPrivateKey(ed25519Key: .init()))
        let otherKey = NIOSSHPrivateKey(ed25519Key: .init())

        let exchange = try self.keyExchangeInit(&client, server: server)
        let reply = try server.reply(
            clientMessage: exchange.clientMessage,
            serverMessage: exchange.serverMessage,
            keyExchangeInit: exchange.keyExchangeInit,
            presenting: certificate,
            sign: { try otherKey.sign(digest: $0) }
        )

        XCTAssertThrowsError(try client.handle(keyExchangeReply: reply)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidExchangeHashSignature)
        }
        XCTAssertEqual(delegate.hostKeys, [])
    }
}
