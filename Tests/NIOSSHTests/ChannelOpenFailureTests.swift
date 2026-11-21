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

final class ChannelOpenFailureTests: XCTestCase {
    private var channel: BackToBackEmbeddedChannel!

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
    }

    /// What the client's child channel was failed with, and what its pipeline was told of it.
    private struct Refusal {
        var promised: Error?
        var caught: [Error]
    }

    /// Has the client ask for a session, and the server refuse it with `encodedRefusal`, the encoding of an
    /// `SSH_MSG_CHANNEL_OPEN_FAILURE` that `encodedRefusal` writes for the channel that the client named.
    private func refuseChannel(encodedRefusal: (_ recipientChannel: UInt32) -> ByteBuffer) throws -> Refusal {
        // The peers protect nothing, so that this test can play the server once the client has authenticated.
        try self.channel.configureWithHarness(.scriptable())
        try self.channel.activate()
        try self.channel.interactInMemory()

        let errorLogger = ErrorLoggingHandler()
        let childResult = NIOLoopBoundBox<Result<Channel, Error>?>(nil, eventLoop: self.channel.client.eventLoop)
        let childPromise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        childPromise.futureResult.whenComplete { childResult.value = $0 }
        self.channel.clientSSHHandler?.createChannel(childPromise, channelType: .session) { channel, _ in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(errorLogger)
            }
        }

        guard case .some(.channelOpen(let request)) = try self.channel.messagesForScriptedServer().first else {
            XCTFail("Expected the client to request a channel")
            return Refusal(promised: nil, caught: [])
        }

        try self.channel.client.writeInbound(
            ByteBuffer.plaintextSSHPacket(encodedMessage: encodedRefusal(request.senderChannel))
        )
        self.channel.run()

        guard case .failure(let error) = childResult.value else {
            XCTFail("Expected the channel to fail, got \(String(describing: childResult.value))")
            return Refusal(promised: nil, caught: errorLogger.errors)
        }
        return Refusal(promised: error, caught: errorLogger.errors)
    }

    /// Has the client ask for a session, and the server refuse it with `reasonCode` and `description`.
    private func refuseChannel(reasonCode: UInt32, description: String, language: String = "") throws -> Refusal {
        try self.refuseChannel { recipientChannel in
            var buffer = ByteBuffer()
            buffer.writeSSHMessage(
                .channelOpenFailure(
                    .init(
                        recipientChannel: recipientChannel,
                        reasonCode: reasonCode,
                        description: description,
                        language: language
                    )
                )
            )
            return buffer
        }
    }

    private func assertRefused(
        _ refusal: Refusal,
        with expected: NIOSSHChannelOpenFailure,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let promised = refusal.promised as? NIOSSHError
        XCTAssertEqual(promised?.type, .channelSetupRejected, file: file, line: line)
        XCTAssertEqual(promised?.channelOpenFailure, expected, file: file, line: line)

        XCTAssertEqual(refusal.caught.count, 1, file: file, line: line)
        let caught = refusal.caught.first as? NIOSSHError
        XCTAssertEqual(caught?.type, .channelSetupRejected, file: file, line: line)
        XCTAssertEqual(caught?.channelOpenFailure, expected, file: file, line: line)
    }

    func testTheReasonForAdministrativeProhibitionIsGiven() throws {
        let refusal = try self.refuseChannel(reasonCode: 1, description: "open failed", language: "en")
        self.assertRefused(refusal, with: .init(reasonCode: 1, description: "open failed"))
    }

    func testTheReasonForAFailedConnectionIsGiven() throws {
        let refusal = try self.refuseChannel(reasonCode: 2, description: "Connection refused")
        self.assertRefused(refusal, with: .init(reasonCode: 2, description: "Connection refused"))
    }

    func testTheReasonForAnUnknownChannelTypeIsGiven() throws {
        let refusal = try self.refuseChannel(reasonCode: 3, description: "unknown channel type")
        self.assertRefused(refusal, with: .init(reasonCode: 3, description: "unknown channel type"))
    }

    func testTheReasonForAResourceShortageIsGiven() throws {
        let refusal = try self.refuseChannel(reasonCode: 4, description: "resource shortage")
        self.assertRefused(refusal, with: .init(reasonCode: 4, description: "resource shortage"))
    }

    func testAReasonCodeThatRFC4254DoesNotDefineIsGivenAsSent() throws {
        let refusal = try self.refuseChannel(reasonCode: 0xFE00_0001, description: "private")
        self.assertRefused(refusal, with: .init(reasonCode: 0xFE00_0001, description: "private"))
    }

    func testAnEmptyDescriptionIsGivenAsEmpty() throws {
        let refusal = try self.refuseChannel(reasonCode: 2, description: "")
        self.assertRefused(refusal, with: .init(reasonCode: 2, description: ""))
    }

    func testALongDescriptionIsGivenWhole() throws {
        // As long as a packet of the default maximum size leaves room for, with the rest of the message.
        let description = String(repeating: "connect failed: ", count: 8000)
        XCTAssertEqual(description.utf8.count, 128_000)
        let refusal = try self.refuseChannel(reasonCode: 2, description: description)
        self.assertRefused(refusal, with: .init(reasonCode: 2, description: description))
    }

    func testADescriptionThatIsNotUTF8IsGivenWithReplacementCharacters() throws {
        let refusal = try self.refuseChannel { recipientChannel in
            var buffer = ByteBuffer()
            buffer.writeInteger(SSHMessage.ChannelOpenFailureMessage.id)
            buffer.writeInteger(recipientChannel)
            buffer.writeInteger(UInt32(2))
            // "no", a lone continuation byte, a truncated two-byte sequence, an overlong encoding of "/", "pe".
            let description: [UInt8] = [0x6E, 0x6F, 0x80, 0xC3, 0x20, 0xC0, 0xAF, 0x70, 0x65]
            buffer.writeInteger(UInt32(description.count))
            buffer.writeBytes(description)
            buffer.writeInteger(UInt32(0))
            return buffer
        }
        self.assertRefused(
            refusal,
            with: .init(reasonCode: 2, description: "no\u{FFFD}\u{FFFD} \u{FFFD}\u{FFFD}pe")
        )
    }

    func testTheErrorIsOtherwiseAsItWas() throws {
        let refusal = try self.refuseChannel(reasonCode: 1, description: "open failed")
        XCTAssertEqual(
            refusal.promised.map { String(describing: $0) },
            "NIOSSHError.channelSetupRejected: Reason: 1 open failed"
        )
        XCTAssertEqual(
            refusal.caught.first.map { String(describing: $0) },
            "NIOSSHError.channelSetupRejected: Reason: 1 open failed"
        )
    }

    func testAnErrorOfAnyOtherTypeGivesNoReason() {
        XCTAssertNil(NIOSSHError.tcpShutdown.channelOpenFailure)
        XCTAssertNil(NIOSSHError.creatingChannelAfterClosure.channelOpenFailure)
        XCTAssertNil(NIOSSHError.protocolViolation(protocolName: "channel", violation: "test").channelOpenFailure)
        XCTAssertNil(NIOSSHError.invalidSSHMessage(reason: "test").channelOpenFailure)
    }

    /// Connects a client to a server whose initializer of a channel that the client asks for fails with `error`, has
    /// the client ask for a session, and gives what the client's channel was failed with.
    private func refuseChannelFromTheServersInitializer(failingWith error: Error) throws -> Error? {
        let harness = TestHarness()
        let clientHandler = NIOSSHHandler(
            role: .client(
                .init(
                    userAuthDelegate: harness.clientAuthDelegate,
                    serverAuthDelegate: harness.clientServerAuthDelegate
                )
            ),
            allocator: self.channel.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(
            role: .server(
                .init(hostKeys: harness.serverHostKeys, userAuthDelegate: harness.serverAuthDelegate)
            ),
            allocator: self.channel.server.allocator
        ) { channel, _ in
            channel.eventLoop.makeFailedFuture(error)
        }
        try self.channel.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.channel.server.pipeline.syncOperations.addHandler(serverHandler)
        try self.channel.activate()
        try self.channel.interactInMemory()

        let childResult = NIOLoopBoundBox<Result<Channel, Error>?>(nil, eventLoop: self.channel.client.eventLoop)
        let childPromise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        childPromise.futureResult.whenComplete { childResult.value = $0 }
        clientHandler.createChannel(childPromise, channelType: .session, nil)
        try self.channel.interactInMemory()

        guard case .failure(let error) = childResult.value else {
            XCTFail("Expected the channel to fail, got \(String(describing: childResult.value))")
            return nil
        }
        return error
    }

    func testAnInitializerThatFailsWithAReasonRefusesTheChannelWithIt() throws {
        for reason: NIOSSHChannelOpenFailure in [
            .init(reasonCode: 1, description: "administratively prohibited"),
            .init(reasonCode: 2, description: "connect failed"),
            .init(reasonCode: 3, description: "unknown channel type"),
            .init(reasonCode: 4, description: "resource shortage"),
            .init(reasonCode: 1, description: ""),
        ] {
            // A connection for each reason, the one that `tearDown` finishes last.
            try self.channel.finish()
            self.channel = BackToBackEmbeddedChannel()
            let error = try self.refuseChannelFromTheServersInitializer(failingWith: reason)
            XCTAssertEqual((error as? NIOSSHError)?.type, .channelSetupRejected)
            XCTAssertEqual((error as? NIOSSHError)?.channelOpenFailure, reason)
        }
    }

    func testAnInitializerThatFailsWithAnyOtherErrorRefusesTheChannelAsBefore() throws {
        struct OtherError: Error {}
        let error = try self.refuseChannelFromTheServersInitializer(failingWith: OtherError())
        XCTAssertEqual((error as? NIOSSHError)?.type, .channelSetupRejected)
        XCTAssertEqual((error as? NIOSSHError)?.channelOpenFailure, .init(reasonCode: 2, description: ""))
        XCTAssertEqual(error.map { String(describing: $0) }, "NIOSSHError.channelSetupRejected: Reason: 2 ")
    }
}
