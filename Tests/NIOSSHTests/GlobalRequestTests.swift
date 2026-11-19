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
    /// A delegate that records the requests ``NIOSSH`` does not know, and answers them as it is told to.
    private final class RecordingGlobalRequestDelegate: GlobalRequestDelegate {
        struct Refused: Error {}

        struct Request: Equatable {
            var name: String
            var data: ByteBuffer
            var wantReply: Bool
        }

        var requests: [Request] = []

        var answer: Result<ByteBuffer?, Error> = .failure(Refused())

        func unknownGlobalRequest(
            name: String,
            data: ByteBuffer,
            wantReply: Bool,
            handler: NIOSSHHandler,
            promise: EventLoopPromise<ByteBuffer?>
        ) {
            self.requests.append(.init(name: name, data: data, wantReply: wantReply))
            promise.completeWith(self.answer)
        }
    }

    /// A client that has authenticated with a real server, whose part the test plays from here on.
    private func makeAuthenticatedChannel(
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) throws -> BackToBackEmbeddedChannel {
        let channel = BackToBackEmbeddedChannel()
        var harness = TestHarness.scriptable()
        harness.clientGlobalRequestDelegate = globalRequestDelegate
        try channel.configureWithHarness(harness)
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

    func testUnknownRequestsAreRefusedByDefault() throws {
        let channel = try self.makeAuthenticatedChannel()

        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(
                .globalRequest(.init(wantReply: true, type: .unknown("keepalive@openssh.com", ByteBuffer())))
            )
        )
        XCTAssertEqual(try channel.messagesForScriptedServer(), [.requestFailure])

        // A request that wants no reply gets none.
        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(
                .globalRequest(.init(wantReply: false, type: .unknown("hostkeys-00@openssh.com", ByteBuffer())))
            )
        )
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])
    }

    func testUnknownRequestsAreGivenToTheDelegate() throws {
        let delegate = RecordingGlobalRequestDelegate()
        let channel = try self.makeAuthenticatedChannel(globalRequestDelegate: delegate)
        let hostKeys = ByteBuffer(bytes: [0, 0, 0, 3, 1, 2, 3])

        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(
                .globalRequest(.init(wantReply: false, type: .unknown("hostkeys-00@openssh.com", hostKeys)))
            )
        )
        XCTAssertEqual(delegate.requests, [.init(name: "hostkeys-00@openssh.com", data: hostKeys, wantReply: false)])

        // The delegate refused, but the peer did not want to know.
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])
    }

    func testTheDelegateAnswersUnknownRequests() throws {
        let delegate = RecordingGlobalRequestDelegate()
        let channel = try self.makeAuthenticatedChannel(globalRequestDelegate: delegate)
        let request = SSHMessage.globalRequest(
            .init(wantReply: true, type: .unknown("example@example.com", ByteBuffer()))
        )

        delegate.answer = .success(ByteBuffer(bytes: [42]))
        XCTAssertNoThrow(try channel.sendFromScriptedServer(request))
        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [.requestSuccess(.init(buffer: ByteBuffer(bytes: [42])))]
        )

        delegate.answer = .success(nil)
        XCTAssertNoThrow(try channel.sendFromScriptedServer(request))
        XCTAssertEqual(try channel.messagesForScriptedServer(), [.requestSuccess(.init(buffer: ByteBuffer()))])

        delegate.answer = .failure(RecordingGlobalRequestDelegate.Refused())
        XCTAssertNoThrow(try channel.sendFromScriptedServer(request))
        XCTAssertEqual(try channel.messagesForScriptedServer(), [.requestFailure])

        XCTAssertEqual(delegate.requests.count, 3)
        XCTAssertEqual(delegate.requests.map { $0.wantReply }, [true, true, true])
    }

    func testRequestsThatAreKnownAreNotGivenToTheDelegateAsUnknown() throws {
        let delegate = RecordingGlobalRequestDelegate()
        let channel = try self.makeAuthenticatedChannel(globalRequestDelegate: delegate)

        XCTAssertNoThrow(
            try channel.sendFromScriptedServer(
                .globalRequest(.init(wantReply: true, type: .tcpipForward("localhost", 22)))
            )
        )
        XCTAssertEqual(try channel.messagesForScriptedServer(), [.requestFailure])
        XCTAssertEqual(delegate.requests, [])
    }
}
