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

import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class ExtensionNegotiationTests: XCTestCase {
    /// A delegate that takes its time over the host key, as a person reading a prompt does.
    private final class WaitingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var promise: EventLoopPromise<Void>?

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            self.promise = validationCompletePromise
        }
    }

    private static let extensionInfo = SSHMessage.extensionInfo(
        .init(
            extensions: [
                .init(name: "server-sig-algs", value: ByteBuffer(string: "ssh-ed25519,rsa-sha2-256,rsa-sha2-512")),
                .init(name: "publickey-hostbound@openssh.com", value: ByteBuffer(string: "0")),
            ]
        )
    )

    private func events(_ server: ScriptedServer) -> [NIOSSHExtensionInfoEvent] {
        server.userEvents.userEvents.compactMap { $0 as? NIOSSHExtensionInfoEvent }
    }

    func testExtensionNegotiationIsNotOfferedByDefault() throws {
        let server = try ScriptedServer()
        XCTAssertFalse(try server.exchangeVersions().keyExchangeAlgorithms.contains("ext-info-c"))
    }

    func testExtensionNegotiationIsOfferedInTheFirstKeyExchangeOnly() throws {
        let server = try ScriptedServer { $0.extensionNegotiation = true }
        let clientMessage = try server.exchangeVersions()
        XCTAssertEqual(clientMessage.keyExchangeAlgorithms.last, "ext-info-c")
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: clientMessage))
        XCTAssertNoThrow(try server.authenticate())

        XCTAssertNoThrow(try server.send(.keyExchange(server.keyExchange.keyExchangeMessage())))
        guard case .some(.keyExchange(let rekeyMessage)) = try server.clientMessages().first else {
            return XCTFail("Expected the client to answer with its own key exchange initialization")
        }
        XCTAssertFalse(rekeyMessage.keyExchangeAlgorithms.contains("ext-info-c"))
    }

    func testExtensionNegotiationIsOfferedBeforeStrictKeyExchange() throws {
        let server = try ScriptedServer {
            $0.extensionNegotiation = true
            $0.strictKeyExchange = true
        }
        XCTAssertEqual(
            Array(try server.exchangeVersions().keyExchangeAlgorithms.suffix(2)),
            ["ext-info-c", "kex-strict-c-v00@openssh.com"]
        )
    }

    func testExtensionsAreReportedBeforeAuthenticationBegins() throws {
        let server = try ScriptedServer { $0.extensionNegotiation = true }
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.send(Self.extensionInfo))

        XCTAssertEqual(self.events(server).count, 1)
        XCTAssertEqual(
            self.events(server).first?.serverSignatureAlgorithms,
            ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"]
        )
        XCTAssertEqual(
            self.events(server).first?.extensions.map { $0.name },
            ["server-sig-algs", "publickey-hostbound@openssh.com"]
        )

        // The client has asked for the authentication service and no more: nothing was offered yet.
        XCTAssertEqual(try server.clientMessages().last, .serviceRequest(.init(service: "ssh-userauth")))

        // A server may send its extensions again just before it says that authentication succeeded.
        XCTAssertNoThrow(try server.send(.serviceAccept(.init(service: "ssh-userauth"))))
        XCTAssertNoThrow(try server.send(.extensionInfo(.init(extensions: []))))
        XCTAssertNoThrow(try server.send(.userAuthSuccess))
        XCTAssertEqual(self.events(server).count, 2)
        XCTAssertNil(self.events(server).last?.serverSignatureAlgorithms)
        XCTAssertTrue(server.userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
    }

    func testExtensionsAreReportedWhileTheHostKeyIsBeingValidated() throws {
        let delegate = WaitingHostKeysDelegate()
        let server = try ScriptedServer {
            $0.extensionNegotiation = true
            $0.serverAuthDelegate = delegate
        }
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.send(Self.extensionInfo))
        XCTAssertEqual(self.events(server).count, 1)

        // Nothing has been sent since the key exchange: the client is still waiting for its delegate.
        XCTAssertEqual(try server.clientMessages(), [])
        delegate.promise?.succeed(())
        XCTAssertEqual(try server.clientMessages(), [.newKeys, .serviceRequest(.init(service: "ssh-userauth"))])
        XCTAssertNoThrow(try server.authenticate())
    }

    func testExtensionInfoIsAnUnknownMessageUnlessOffered() throws {
        let server = try ScriptedServer()
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))

        XCTAssertThrowsError(try server.send(Self.extensionInfo)) { error in
            guard case .some(.unknownType(7)) = error as? SSHMessage.ParsingError else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertEqual(self.events(server), [])
    }

    func testExtensionInfoIsRejectedOnceAuthenticated() throws {
        let server = try ScriptedServer { $0.extensionNegotiation = true }
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.authenticate())

        XCTAssertThrowsError(try server.send(Self.extensionInfo)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertEqual(self.events(server), [])
    }

    func testExtensionInfoIsRejectedDuringKeyExchange() throws {
        let server = try ScriptedServer { $0.extensionNegotiation = true }
        let clientMessage = try server.exchangeVersions()

        XCTAssertThrowsError(try server.exchangeKeys(clientMessage: clientMessage, beforeNewKeys: [Self.extensionInfo]))
        XCTAssertEqual(self.events(server), [])
    }

    func testExtensionInfoRoundTrips() throws {
        var buffer = ByteBuffer()
        buffer.writeSSHMessage(Self.extensionInfo)
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 7)

        var expected = buffer
        XCTAssertEqual(try expected.readSSHMessage(expectingExtensionInfo: true), Self.extensionInfo)
        XCTAssertEqual(expected.readableBytes, 0)

        var unexpected = buffer
        XCTAssertThrowsError(try unexpected.readSSHMessage())
    }

    func testExtensionCountIsCheckedBeforeItIsUsed() throws {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(7))
        buffer.writeInteger(UInt32.max)
        buffer.writeSSHString("server-sig-algs".utf8)
        buffer.writeSSHString("ssh-ed25519".utf8)

        XCTAssertThrowsError(try buffer.readSSHMessage(expectingExtensionInfo: true)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testServerSignatureAlgorithmsAreNilWhenTheServerDoesNotSay() throws {
        let event = NIOSSHExtensionInfoEvent(extensions: [
            .init(name: "ping@openssh.com", value: ByteBuffer(string: "0"))
        ])
        XCTAssertNil(event.serverSignatureAlgorithms)
        XCTAssertEqual(NIOSSHExtensionInfoEvent(extensions: []).serverSignatureAlgorithms, nil)
    }
}
