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

final class GlobalRequestTests: XCTestCase {
    /// A client that has authenticated with a real server, whose part the test plays from here on.
    private func makeAuthenticatedChannel() throws -> BackToBackEmbeddedChannel {
        let channel = BackToBackEmbeddedChannel()
        try channel.configureWithHarness(.scriptable())
        try channel.activate()
        try channel.interactInMemory()
        return channel
    }

    func testRequestsAreWrittenWithTheirNameAndData() throws {
        let channel = try self.makeAuthenticatedChannel()
        let handler = try XCTUnwrap(channel.clientSSHHandler)

        handler.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true)
        handler.sendGlobalRequest(name: "example@example.com", wantReply: false, data: ByteBuffer(bytes: [1, 2, 3]))

        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [
                .globalRequest(.init(wantReply: true, type: .unknown("keepalive@openssh.com", ByteBuffer()))),
                .globalRequest(
                    .init(wantReply: false, type: .unknown("example@example.com", ByteBuffer(bytes: [1, 2, 3])))
                ),
            ]
        )
    }

    func testRepliesAreMatchedToRequestsInOrder() throws {
        let channel = try self.makeAuthenticatedChannel()
        let handler = try XCTUnwrap(channel.clientSSHHandler)

        let first = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        let unanswered = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        let second = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        let third = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        handler.sendGlobalRequest(name: "first@example.com", wantReply: true, promise: first)
        handler.sendGlobalRequest(name: "unanswered@example.com", wantReply: false, promise: unanswered)
        handler.sendGlobalRequest(name: "second@example.com", wantReply: true, promise: second)
        handler.sendGlobalRequest(name: "third@example.com", wantReply: true, promise: third)
        XCTAssertEqual(try channel.messagesForScriptedServer().count, 4)

        // A request that wants no reply is complete once it is written.
        XCTAssertNil(try unanswered.futureResult.wait())

        XCTAssertNoThrow(try channel.sendFromScriptedServer(.requestSuccess(.init(buffer: ByteBuffer(bytes: [42])))))
        XCTAssertNoThrow(try channel.sendFromScriptedServer(.requestFailure))
        XCTAssertNoThrow(try channel.sendFromScriptedServer(.requestSuccess(.init(buffer: ByteBuffer()))))

        XCTAssertEqual(try first.futureResult.wait(), ByteBuffer(bytes: [42]))
        XCTAssertThrowsError(try second.futureResult.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
        XCTAssertEqual(try third.futureResult.wait(), ByteBuffer())
    }

    func testRequestsSentBeforeAuthenticationAreHeld() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }
        XCTAssertNoThrow(try channel.configureWithHarness(TestHarness()))

        // A server of ours refuses a request it does not know, which is a reply all the same.
        let reply = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        channel.clientSSHHandler?.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true, promise: reply)

        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertThrowsError(try reply.futureResult.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
    }

    func testOutstandingRequestsFailWhenTheConnectionEnds() throws {
        let channel = try self.makeAuthenticatedChannel()
        let handler = try XCTUnwrap(channel.clientSSHHandler)

        let reply = channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        handler.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true, promise: reply)
        XCTAssertEqual(try channel.messagesForScriptedServer().count, 1)

        let result = NIOLoopBoundBox<Result<ByteBuffer?, Error>?>(nil, eventLoop: channel.client.eventLoop)
        reply.futureResult.whenComplete { result.value = $0 }

        channel.client.close(promise: nil)
        channel.run()

        // The peer never replied, and the error must not say that it did.
        guard case .some(.failure(let error)) = result.value else {
            return XCTFail("Expected the request to have failed, got \(String(describing: result.value))")
        }
        XCTAssertNotEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
    }
}
