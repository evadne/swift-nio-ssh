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

final class SessionIdentifierTests: XCTestCase {
    private final class WaitingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var promise: EventLoopPromise<Void>?

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            self.promise = validationCompletePromise
        }
    }

    /// Accepts every host key, and records what `onHostKey` returns each time it is asked about one.
    private final class RecordingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var recorded: [ByteBuffer?] = []

        var onHostKey: () -> ByteBuffer? = { nil }

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            self.recorded.append(self.onHostKey())
            validationCompletePromise.succeed(())
        }
    }

    private final class RejectingHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        struct Rejected: Error {}

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            validationCompletePromise.fail(Rejected())
        }
    }

    /// Offers a password, and records what `onOffer` returns each time it is asked for an offer.
    private final class RecordingPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
        var recorded: [ByteBuffer?] = []

        var onOffer: () -> ByteBuffer? = { nil }

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            self.recorded.append(self.onOffer())
            nextChallengePromise.succeed(
                .init(username: "foo", serviceName: "ssh-connection", offer: .password(.init(password: "bar")))
            )
        }
    }

    /// Connects a client and a server, and authenticates the client.
    private func connect(_ channel: BackToBackEmbeddedChannel, harness: TestHarness = TestHarness()) throws {
        try channel.configureWithHarness(harness)
        XCTAssertNil(channel.clientSSHHandler?.sessionIdentifier)
        XCTAssertNil(channel.serverSSHHandler?.sessionIdentifier)

        try channel.activate()
        try channel.interactInMemory()
    }

    func testThereIsNoSessionIdentifierBeforeTheConnectionBegins() throws {
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: ByteBufferAllocator(),
            inboundChildChannelInitializer: nil
        )
        XCTAssertNil(handler.sessionIdentifier)
    }

    func testClientAndServerHaveTheSameSessionIdentifier() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }
        XCTAssertNoThrow(try self.connect(channel))

        let sessionIdentifier = try XCTUnwrap(channel.clientSSHHandler?.sessionIdentifier)
        XCTAssertEqual(channel.serverSSHHandler?.sessionIdentifier, sessionIdentifier)
        XCTAssertGreaterThanOrEqual(sessionIdentifier.readableBytes, 32)
    }

    func testSessionIdentifiersDifferBetweenConnections() throws {
        var sessionIdentifiers: Set<ByteBuffer> = []

        for _ in 0..<4 {
            let channel = BackToBackEmbeddedChannel()
            defer {
                XCTAssertNoThrow(try channel.finish())
            }
            XCTAssertNoThrow(try self.connect(channel))
            sessionIdentifiers.insert(try XCTUnwrap(channel.clientSSHHandler?.sessionIdentifier))
        }

        XCTAssertEqual(sessionIdentifiers.count, 4)
    }

    func testSessionIdentifierIsTheExchangeHashOfTheFirstKeyExchange() throws {
        let server = try ScriptedServer()
        XCTAssertNil(server.clientHandler.sessionIdentifier)
        let clientMessage = try server.exchangeVersions()
        XCTAssertNil(server.clientHandler.sessionIdentifier)

        XCTAssertNoThrow(
            try server.exchangeKeys(
                clientMessage: clientMessage,
                whileExchanging: {
                    XCTAssertNil(server.clientHandler.sessionIdentifier)
                },
                afterReply: {
                    // The client has verified the exchange hash and has sent its new keys message. The server
                    // has not sent its own, so the exchange has not completed.
                    XCTAssertEqual(try server.clientMessages().first, .newKeys)
                    XCTAssertNil(server.clientHandler.sessionIdentifier)
                }
            )
        )

        // The server computed the exchange hash itself, from what crossed the network.
        XCTAssertEqual(server.exchangeHashes.count, 1)
        XCTAssertEqual(server.exchangeHashes.first?.readableBytes, 32)
        XCTAssertEqual(server.clientHandler.sessionIdentifier, server.exchangeHashes.first)
    }

    func testThereIsNoSessionIdentifierUntilTheClientHasSentItsNewKeys() throws {
        let delegate = WaitingHostKeysDelegate()
        let server = try ScriptedServer { $0.serverAuthDelegate = delegate }
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))

        // The server has sent its new keys message. The client has not: it is still asking about the host key.
        XCTAssertEqual(try server.clientMessages(), [])
        XCTAssertEqual(server.exchangeHashes.count, 1)
        XCTAssertNil(server.clientHandler.sessionIdentifier)

        try XCTUnwrap(delegate.promise).succeed(())
        XCTAssertEqual(try server.clientMessages().first, .newKeys)
        XCTAssertEqual(server.clientHandler.sessionIdentifier, server.exchangeHashes.first)
    }

    func testThereIsNoSessionIdentifierWhenTheHostKeyIsRejected() throws {
        let server = try ScriptedServer { $0.serverAuthDelegate = RejectingHostKeysDelegate() }

        XCTAssertThrowsError(try server.exchangeKeys(clientMessage: try server.exchangeVersions())) { error in
            XCTAssertTrue(error is RejectingHostKeysDelegate.Rejected)
        }
        XCTAssertEqual(server.exchangeHashes.count, 1)
        XCTAssertNil(server.clientHandler.sessionIdentifier)
    }

    func testThereIsASessionIdentifierBeforeUserAuthentication() throws {
        let delegate = RecordingPasswordDelegate()
        let server = try ScriptedServer { $0.userAuthDelegate = delegate }
        delegate.onOffer = { server.clientHandler.sessionIdentifier }

        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertEqual(delegate.recorded, [])

        // The delegate is asked for its first offer when the server accepts the service request.
        XCTAssertNoThrow(try server.authenticate())
        XCTAssertEqual(server.exchangeHashes.count, 1)
        XCTAssertEqual(delegate.recorded, [server.exchangeHashes.first])
        XCTAssertEqual(server.clientHandler.sessionIdentifier, server.exchangeHashes.first)
    }

    func testSessionIdentifierDoesNotChangeWhenTheServerExchangesKeysAgain() throws {
        // The delegate is asked about the host key in every exchange, in the middle of it.
        let delegate = RecordingHostKeysDelegate()
        let server = try ScriptedServer { $0.serverAuthDelegate = delegate }
        delegate.onHostKey = { server.clientHandler.sessionIdentifier }
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.authenticate())
        let sessionIdentifier = try XCTUnwrap(server.clientHandler.sessionIdentifier)
        XCTAssertEqual(server.exchangeHashes, [sessionIdentifier])

        for _ in 0..<2 {
            // It is the same at every step of the exchange.
            XCTAssertNoThrow(
                try server.exchangeKeys(
                    whileExchanging: {
                        XCTAssertEqual(server.clientHandler.sessionIdentifier, sessionIdentifier)
                    },
                    afterReply: {
                        XCTAssertEqual(server.clientHandler.sessionIdentifier, sessionIdentifier)
                    }
                )
            )
            XCTAssertEqual(server.clientHandler.sessionIdentifier, sessionIdentifier)
            XCTAssertEqual(try server.clientMessages(), [.newKeys])
            XCTAssertEqual(server.clientHandler.sessionIdentifier, sessionIdentifier)
        }

        // Each exchange had an exchange hash of its own, and the session identifier is still the first of them.
        XCTAssertEqual(server.exchangeHashes.count, 3)
        XCTAssertEqual(Set(server.exchangeHashes).count, 3)
        XCTAssertEqual(server.exchangeHashes.first, sessionIdentifier)
        XCTAssertEqual(delegate.recorded, [nil, sessionIdentifier, sessionIdentifier])
    }

    func testSessionIdentifierDoesNotChangeWhenEitherPeerExchangesKeysAgain() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }
        XCTAssertNoThrow(try self.connect(channel))
        let sessionIdentifier = try XCTUnwrap(channel.clientSSHHandler?.sessionIdentifier)

        XCTAssertNoThrow(try channel.clientSSHHandler?._rekey())
        XCTAssertEqual(channel.clientSSHHandler?.sessionIdentifier, sessionIdentifier)
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.clientSSHHandler?.sessionIdentifier, sessionIdentifier)
        XCTAssertEqual(channel.serverSSHHandler?.sessionIdentifier, sessionIdentifier)

        XCTAssertNoThrow(try channel.serverSSHHandler?._rekey())
        XCTAssertEqual(channel.serverSSHHandler?.sessionIdentifier, sessionIdentifier)
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.clientSSHHandler?.sessionIdentifier, sessionIdentifier)
        XCTAssertEqual(channel.serverSSHHandler?.sessionIdentifier, sessionIdentifier)

        // The connection still works under the keys of the last exchange, which each peer derived from the
        // session identifier.
        _ = try channel.createNewChannel()
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    func testSessionIdentifierOutlivesTheConnection() throws {
        let channel = BackToBackEmbeddedChannel()
        XCTAssertNoThrow(try self.connect(channel))
        let clientHandler = try XCTUnwrap(channel.clientSSHHandler)
        let serverHandler = try XCTUnwrap(channel.serverSSHHandler)
        let sessionIdentifier = try XCTUnwrap(clientHandler.sessionIdentifier)

        XCTAssertNoThrow(try serverHandler._disconnect())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertFalse(channel.client.isActive)

        XCTAssertEqual(clientHandler.sessionIdentifier, sessionIdentifier)
        XCTAssertEqual(serverHandler.sessionIdentifier, sessionIdentifier)
    }
}
