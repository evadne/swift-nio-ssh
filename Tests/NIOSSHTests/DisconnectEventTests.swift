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

final class DisconnectEventTests: XCTestCase {
    private func disconnectEvents(_ userEvents: UserEventExpecter) -> [NIOSSHDisconnectEvent] {
        userEvents.userEvents.compactMap { $0 as? NIOSSHDisconnectEvent }
    }

    func testDisconnectFromAnAuthenticatedPeerIsReported() throws {
        let channel = BackToBackEmbeddedChannel()
        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(.scriptable()))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertEqual(self.disconnectEvents(userEvents), [])
        XCTAssertTrue(channel.client.isActive)

        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(
                .disconnect(.init(reason: 11, description: "Shutting down", tag: "en"))
            )
        )

        XCTAssertEqual(
            self.disconnectEvents(userEvents),
            [.init(reasonCode: 11, description: "Shutting down", languageTag: "en")]
        )
        XCTAssertFalse(channel.client.isActive)
    }

    func testDisconnectDuringKeyExchangeIsReported() throws {
        let channel = EmbeddedChannel()
        let userEvents = UserEventExpecter()
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
        )
        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandlers([handler, userEvents]))
        XCTAssertNoThrow(try channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait())

        // The peer says who it is and then, before any key has been exchanged, that it is leaving.
        var bytes = ByteBuffer(string: "SSH-2.0-Test_1.0\r\n")
        var packet = ByteBuffer.plaintextSSHPacket(
            .disconnect(.init(reason: 2, description: "Too many authentication failures", tag: ""))
        )
        bytes.writeBuffer(&packet)
        XCTAssertNoThrow(try channel.writeInbound(bytes))

        XCTAssertEqual(
            self.disconnectEvents(userEvents),
            [.init(reasonCode: 2, description: "Too many authentication failures", languageTag: "")]
        )
        XCTAssertFalse(channel.isActive)
    }

    func testDisconnectFromAServerHandlerIsReported() throws {
        let channel = BackToBackEmbeddedChannel()
        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertNoThrow(try channel.serverSSHHandler?._disconnect())
        XCTAssertNoThrow(try channel.interactInMemory())

        XCTAssertEqual(self.disconnectEvents(userEvents), [.init(reasonCode: 0, description: "", languageTag: "")])
        XCTAssertFalse(channel.client.isActive)
    }

    func testNoEventWhenTheConnectionIsMerelyClosed() throws {
        let channel = BackToBackEmbeddedChannel()
        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        channel.client.pipeline.fireChannelInactive()
        channel.client.close(promise: nil)
        channel.run()

        XCTAssertEqual(self.disconnectEvents(userEvents), [])
    }
}
