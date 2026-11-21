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

final class SendDisconnectTests: XCTestCase {
    private func disconnectEvents(_ userEvents: UserEventExpecter) -> [NIOSSHDisconnectEvent] {
        userEvents.userEvents.compactMap { $0 as? NIOSSHDisconnectEvent }
    }

    func testAClientsDisconnectReachesTheServerWithItsReason() throws {
        let channel = BackToBackEmbeddedChannel()
        let serverEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try channel.server.pipeline.syncOperations.addHandler(serverEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        let promise = channel.client.eventLoop.makePromise(of: Void.self)
        channel.clientSSHHandler?.sendDisconnect(
            reasonCode: 11,
            description: "disconnected by user",
            languageTag: "en",
            promise: promise
        )
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
        XCTAssertEqual(
            self.disconnectEvents(serverEvents),
            [.init(reasonCode: 11, description: "disconnected by user", languageTag: "en")]
        )
        XCTAssertFalse(channel.server.isActive)
    }

    func testTheDisconnectIsFlushedAndTheChannelIsLeftOpen() throws {
        let channel = BackToBackEmbeddedChannel()
        XCTAssertNoThrow(try channel.configureWithHarness(.scriptable()))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        // Nothing but the handler flushes: an embedded channel gives up only what was flushed.
        channel.clientSSHHandler?.sendDisconnect(reasonCode: 11, description: "disconnected by user")

        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [.disconnect(.init(reason: 11, description: "disconnected by user", tag: ""))]
        )
        XCTAssertTrue(channel.client.isActive)
    }

    func testNothingIsSentAfterADisconnect() throws {
        let channel = BackToBackEmbeddedChannel()
        XCTAssertNoThrow(try channel.configureWithHarness(.scriptable()))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        channel.clientSSHHandler?.sendDisconnect(reasonCode: 11, description: "")
        let second = channel.client.eventLoop.makePromise(of: Void.self)
        channel.clientSSHHandler?.sendDisconnect(reasonCode: 2, description: "", promise: second)
        let request = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        channel.clientSSHHandler?.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true, promise: request)

        XCTAssertThrowsError(try second.futureResult.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [.disconnect(.init(reason: 11, description: "", tag: ""))]
        )

        // The request was held and never sent, and fails once the handler is removed.
        channel.client.close(promise: nil)
        channel.run()
        XCTAssertThrowsError(try request.futureResult.wait()) { error in
            XCTAssertEqual(error as? ChannelError, .eof)
        }
    }

    func testWhatThePeerSendsAfterADisconnectIsDiscarded() throws {
        let channel = BackToBackEmbeddedChannel()
        let clientEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(.scriptable()))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(clientEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        channel.clientSSHHandler?.sendDisconnect(reasonCode: 11, description: "")
        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(.disconnect(.init(reason: 2, description: "Goodbye", tag: "")))
        )

        // The peer's own disconnect is not read, so it is neither reported nor acted on.
        XCTAssertEqual(self.disconnectEvents(clientEvents), [])
        XCTAssertTrue(channel.client.isActive)
    }

    func testADisconnectCanBeSentBeforeThePeerHasSentItsVersion() throws {
        let server = try ScriptedServer()
        let promise = server.channel.eventLoop.makePromise(of: Void.self)

        // The client has sent its version and has heard nothing.
        server.clientHandler.sendDisconnect(reasonCode: 11, description: "disconnected by user", promise: promise)

        XCTAssertNoThrow(try promise.futureResult.wait())
        XCTAssertEqual(
            try server.clientMessages(),
            [.disconnect(.init(reason: 11, description: "disconnected by user", tag: ""))]
        )
    }

    func testADisconnectFailsWhereTheChannelIsNotActive() throws {
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
        )
        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))

        let promise = channel.eventLoop.makePromise(of: Void.self)
        handler.sendDisconnect(reasonCode: 11, description: "", promise: promise)
        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        }

        // Nothing was changed by it: once active, the client says who it is first, as ever.
        XCTAssertNoThrow(try channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait())
        let version = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
        XCTAssertTrue(version.readableBytesView.starts(with: "SSH-2.0-".utf8))
    }
}
