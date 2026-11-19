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

    /// A delegate that keeps the promises of the requests it is given, for the test to complete.
    private final class HoldingGlobalRequestDelegate: GlobalRequestDelegate {
        var promises: [EventLoopPromise<ByteBuffer?>] = []

        var forwardingPromises: [EventLoopPromise<GlobalRequest.TCPForwardingResponse>] = []

        func tcpForwardingRequest(
            _ request: GlobalRequest.TCPForwardingRequest,
            handler: NIOSSHHandler,
            promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
        ) {
            self.forwardingPromises.append(promise)
        }

        func unknownGlobalRequest(
            name: String,
            data: ByteBuffer,
            wantReply: Bool,
            handler: NIOSSHHandler,
            promise: EventLoopPromise<ByteBuffer?>
        ) {
            self.promises.append(promise)
        }
    }

    /// A delegate that accepts every host key, at once or when the test completes the promise.
    private final class HoldableHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
        var hold = false

        var promises: [EventLoopPromise<Void>] = []

        func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
            if self.hold {
                self.promises.append(validationCompletePromise)
            } else {
                validationCompletePromise.succeed(())
            }
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

    /// A client that has authenticated with a server the test plays from the first byte, and which can therefore
    /// exchange keys again.
    private func makeAuthenticatedScriptedServer(
        _ configure: (inout SSHClientConfiguration) -> Void = { _ in }
    ) throws -> ScriptedServer {
        let server = try ScriptedServer(configure)
        try server.exchangeKeys(clientMessage: try server.exchangeVersions())
        try server.authenticate()
        return server
    }

    private static let keepalive = SSHMessage.GlobalRequestMessage(
        wantReply: true,
        type: .unknown("keepalive@openssh.com", ByteBuffer())
    )

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

    func testTheDelegateMayAnswerUnknownRequestsInAnyOrder() throws {
        let delegate = HoldingGlobalRequestDelegate()
        let channel = try self.makeAuthenticatedChannel(globalRequestDelegate: delegate)

        // Three requests. The second does not want a reply.
        for (name, wantReply) in [
            ("first@example.com", true), ("second@example.com", false), ("third@example.com", true),
        ] {
            XCTAssertNoThrow(
                try channel.sendFromScriptedServer(
                    .globalRequest(.init(wantReply: wantReply, type: .unknown(name, ByteBuffer())))
                )
            )
        }
        guard delegate.promises.count == 3 else {
            return XCTFail("Expected three requests, got \(delegate.promises.count)")
        }
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])

        // The delegate answers the last request first. Its reply waits for the reply to the first.
        delegate.promises[2].succeed(ByteBuffer(bytes: [3]))
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])

        // The second request has no reply, and holds nothing back.
        delegate.promises[1].succeed(nil)
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])

        // Once the first is answered, both replies are sent, in the order of the requests.
        delegate.promises[0].fail(RecordingGlobalRequestDelegate.Refused())
        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [.requestFailure, .requestSuccess(.init(buffer: ByteBuffer(bytes: [3])))]
        )
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

    func testRepliesCompletedDuringARekeyAreSentAfterIt() throws {
        let delegate = HoldingGlobalRequestDelegate()
        let server = try self.makeAuthenticatedScriptedServer { $0.globalRequestDelegate = delegate }

        // Two requests that want a reply. The delegate answers neither yet.
        XCTAssertNoThrow(
            try server.send(.globalRequest(.init(wantReply: true, type: .tcpipForward("localhost", 0))))
        )
        XCTAssertNoThrow(try server.send(.globalRequest(Self.keepalive)))
        guard delegate.forwardingPromises.count == 1, delegate.promises.count == 1 else {
            return XCTFail("Expected one request of each kind")
        }
        XCTAssertEqual(try server.clientMessages(), [])

        // The server exchanges keys again, and the delegate answers while it does, the later request first. The
        // client has sent its key exchange initialization and may send no reply before its new keys message
        // (RFC 4253 § 7.1).
        XCTAssertNoThrow(
            try server.exchangeKeys(whileExchanging: {
                delegate.promises[0].succeed(ByteBuffer(bytes: [42]))
                delegate.forwardingPromises[0].succeed(.init(boundPort: 2222))
                try server.channel.throwIfErrorCaught()
                XCTAssertEqual(try server.clientMessages(), [])
            })
        )

        // The replies follow the new keys message, in the order of the requests.
        XCTAssertEqual(
            try server.clientMessages(),
            [
                .newKeys,
                .requestSuccess(.init(buffer: ByteBuffer(integer: UInt32(2222)))),
                .requestSuccess(.init(buffer: ByteBuffer(bytes: [42]))),
            ]
        )
        XCTAssertNoThrow(try server.channel.throwIfErrorCaught())
    }

    func testRequestsReceivedBeforeOurNewKeysAreAnsweredAfterThem() throws {
        let hostKeys = HoldableHostKeysDelegate()
        let server = try self.makeAuthenticatedScriptedServer { $0.serverAuthDelegate = hostKeys }

        // The server exchanges keys again and sends its new keys message. The client has not sent its own: it is
        // still asking its delegate about the host key.
        hostKeys.hold = true
        XCTAssertNoThrow(try server.exchangeKeys())
        XCTAssertEqual(hostKeys.promises.count, 1)
        XCTAssertEqual(try server.clientMessages(), [])

        // The server may send what it likes after its new keys message, and an OpenSSH server that has no channel
        // open sends this request at its `ClientAliveInterval`. The client refuses it, which is a reply, but
        // cannot send it yet.
        XCTAssertNoThrow(try server.send(.globalRequest(Self.keepalive)))
        XCTAssertEqual(try server.clientMessages(), [])

        hostKeys.promises[0].succeed(())
        XCTAssertEqual(try server.clientMessages(), [.newKeys, .requestFailure])
        XCTAssertNoThrow(try server.channel.throwIfErrorCaught())
    }

    func testRequestsSentDuringARekeyAreSentAfterIt() throws {
        let server = try self.makeAuthenticatedScriptedServer()
        let handler = try server.channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
        let request = SSHMessage.globalRequest(Self.keepalive)

        let replyResult = NIOLoopBoundBox<Result<ByteBuffer?, Error>?>(nil, eventLoop: server.channel.eventLoop)
        let reply = server.channel.eventLoop.makePromise(of: ByteBuffer?.self)
        reply.futureResult.whenComplete { replyResult.value = $0 }
        XCTAssertNoThrow(
            try server.exchangeKeys(whileExchanging: {
                handler.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true, promise: reply)
                try server.channel.throwIfErrorCaught()
                XCTAssertEqual(try server.clientMessages(), [])
            })
        )
        XCTAssertEqual(try server.clientMessages(), [.newKeys, request])

        XCTAssertNoThrow(try server.send(.requestSuccess(.init(buffer: ByteBuffer()))))
        XCTAssertEqual(try XCTUnwrap(replyResult.value).get(), ByteBuffer())
    }

    func testRequestsSentBeforeOurNewKeysAreSentAfterThem() throws {
        let hostKeys = HoldableHostKeysDelegate()
        let server = try self.makeAuthenticatedScriptedServer { $0.serverAuthDelegate = hostKeys }
        let handler = try server.channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
        let request = SSHMessage.globalRequest(Self.keepalive)

        // The server has sent its new keys message, and the client is still asking its delegate about the host key.
        hostKeys.hold = true
        XCTAssertNoThrow(try server.exchangeKeys())
        XCTAssertEqual(hostKeys.promises.count, 1)

        let replyResult = NIOLoopBoundBox<Result<ByteBuffer?, Error>?>(nil, eventLoop: server.channel.eventLoop)
        let reply = server.channel.eventLoop.makePromise(of: ByteBuffer?.self)
        reply.futureResult.whenComplete { replyResult.value = $0 }
        handler.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: true, promise: reply)
        XCTAssertNoThrow(try server.channel.throwIfErrorCaught())
        XCTAssertEqual(try server.clientMessages(), [])

        // The key exchange ends when the client sends its new keys message, and the request must not wait for the
        // server to send something first: the server may have nothing to send.
        hostKeys.promises[0].succeed(())
        XCTAssertEqual(try server.clientMessages(), [.newKeys, request])

        XCTAssertNoThrow(try server.send(.requestSuccess(.init(buffer: ByteBuffer()))))
        XCTAssertEqual(try XCTUnwrap(replyResult.value).get(), ByteBuffer())
    }
}
