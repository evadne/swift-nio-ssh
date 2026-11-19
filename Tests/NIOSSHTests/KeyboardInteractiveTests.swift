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

/// A delegate that makes the offers it is given, in order, and answers challenges as it is told to.
final class ScriptedClientAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    enum Answer {
        case respond([String])
        case fail
        case wait
    }

    struct NoAnswer: Error {}

    var offers: [NIOSSHUserAuthenticationOffer.Offer]

    var answer: Answer = .wait

    private(set) var availableMethods: [NIOSSHAvailableUserAuthenticationMethods] = []

    private(set) var challenges: [NIOSSHKeyboardInteractiveChallenge] = []

    private(set) var pendingOffer: EventLoopPromise<NIOSSHUserAuthenticationOffer?>?

    private(set) var pendingResponse: EventLoopPromise<[String]>?

    init(offers: [NIOSSHUserAuthenticationOffer.Offer]) {
        self.offers = offers
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.availableMethods.append(availableMethods)
        if self.offers.isEmpty {
            // Nothing to offer yet: the test will make an offer by hand.
            self.pendingOffer = nextChallengePromise
        } else {
            nextChallengePromise.succeed(.init(username: "foo", serviceName: "", offer: self.offers.removeFirst()))
        }
    }

    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        self.challenges.append(challenge)
        switch self.answer {
        case .respond(let responses):
            responsePromise.succeed(responses)
        case .fail:
            responsePromise.fail(NoAnswer())
        case .wait:
            self.pendingResponse = responsePromise
        }
    }

    func offer(_ offer: NIOSSHUserAuthenticationOffer.Offer) {
        let promise = self.pendingOffer
        self.pendingOffer = nil
        promise?.succeed(.init(username: "foo", serviceName: "", offer: offer))
    }
}

final class KeyboardInteractiveTests: XCTestCase {
    private static let passwordChallenge = SSHMessage.UserAuthInfoRequestMessage(
        name: "",
        instruction: "",
        prompts: [.init(prompt: "Password: ", echo: false)]
    )

    private static let twoPromptChallenge = SSHMessage.UserAuthInfoRequestMessage(
        name: "Second factor",
        instruction: "Enter both codes",
        prompts: [.init(prompt: "Code: ", echo: true), .init(prompt: "PIN: ", echo: false)]
    )

    /// A client state machine that has sent a request for `offer` and awaits the server.
    private func makeStateMachine(
        offering offer: NIOSSHUserAuthenticationOffer.Offer,
        delegate: ScriptedClientAuthDelegate
    ) throws -> UserAuthenticationStateMachine {
        delegate.offers.append(offer)

        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: EmbeddedEventLoop(),
            sessionID: ByteBuffer(repeating: 0xAB, count: 32)
        )
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))
        let request = try XCTUnwrap(try stateMachine.receiveServiceAccept(.init(service: "ssh-userauth"))?.wait())
        stateMachine.sendUserAuthRequest(request)
        return stateMachine
    }

    private func assertProtocolViolation(
        _ body: @autoclosure () throws -> Any?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation, file: file, line: line)
        }
    }

    // MARK: Messages

    func testKeyboardInteractiveRequestRoundTrips() throws {
        let message = SSHMessage.userAuthRequest(
            .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive(submethods: "pam,otp"))
        )

        var buffer = ByteBuffer()
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testKeyboardInteractiveRequestWireFormat() throws {
        var buffer = ByteBuffer()
        buffer.writeSSHMessage(
            .userAuthRequest(
                .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive(submethods: ""))
            )
        )

        XCTAssertEqual(buffer.readInteger(as: UInt8.self), 50)
        XCTAssertEqual(buffer.readSSHStringAsString(), "foo")
        XCTAssertEqual(buffer.readSSHStringAsString(), "ssh-connection")
        XCTAssertEqual(buffer.readSSHStringAsString(), "keyboard-interactive")
        XCTAssertEqual(buffer.readSSHStringAsString(), "")
        XCTAssertEqual(buffer.readSSHStringAsString(), "")
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testInfoRequestRoundTripsOnlyWhenExpected() throws {
        let message = SSHMessage.userAuthInfoRequest(Self.twoPromptChallenge)

        var buffer = ByteBuffer()
        buffer.writeSSHMessage(message)
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 60)

        var expected = buffer
        XCTAssertEqual(try expected.readSSHMessage(expectingUserAuthInfoRequest: true), message)
        XCTAssertEqual(expected.readableBytes, 0)

        // Without being told otherwise, message 60 is SSH_MSG_USERAUTH_PK_OK, which this is not.
        var unexpected = buffer
        XCTAssertThrowsError(try unexpected.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testPublicKeyOKIsNotReadAsAnInfoRequestByDefault() throws {
        let message = SSHMessage.userAuthPKOK(.init(key: NIOSSHPrivateKey(ed25519Key: .init()).publicKey))

        var buffer = ByteBuffer()
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testInfoResponseRoundTrips() throws {
        let message = SSHMessage.userAuthInfoResponse(.init(responses: ["123456", "", "hunter2"]))

        var buffer = ByteBuffer()
        buffer.writeSSHMessage(message)
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 61)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testInfoRequestPromptCountIsBounded() throws {
        func challenge(promptCount: Int) -> ByteBuffer {
            var buffer = ByteBuffer()
            buffer.writeSSHMessage(
                .userAuthInfoRequest(
                    .init(
                        name: "",
                        instruction: "",
                        prompts: Array(repeating: .init(prompt: "?", echo: true), count: promptCount)
                    )
                )
            )
            return buffer
        }

        var acceptable = challenge(promptCount: 256)
        guard
            case .some(.userAuthInfoRequest(let message)) = try acceptable.readSSHMessage(
                expectingUserAuthInfoRequest: true
            )
        else {
            return XCTFail("Expected an info request")
        }
        XCTAssertEqual(message.prompts.count, 256)

        var excessive = challenge(promptCount: 257)
        XCTAssertThrowsError(try excessive.readSSHMessage(expectingUserAuthInfoRequest: true)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testInfoRequestPromptCountIsCheckedBeforeItIsUsed() throws {
        // A message that claims far more prompts than it could hold must be rejected for its count alone.
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(60))
        buffer.writeSSHString("".utf8)
        buffer.writeSSHString("".utf8)
        buffer.writeSSHString("".utf8)
        buffer.writeInteger(UInt32.max)

        XCTAssertThrowsError(try buffer.readSSHMessage(expectingUserAuthInfoRequest: true)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testAvailableMethodsIncludeKeyboardInteractiveOnlyWhenTheServerNamesIt() throws {
        let named = NIOSSHAvailableUserAuthenticationMethods(
            SSHMessage.UserAuthFailureMessage(
                authentications: ["publickey", "keyboard-interactive"],
                partialSuccess: false
            )
        )
        XCTAssertEqual(named, [.publicKey, .keyboardInteractive])
        XCTAssertEqual(named.strings, ["publickey", "keyboard-interactive"])
        XCTAssertFalse(NIOSSHAvailableUserAuthenticationMethods.all.contains(.keyboardInteractive))
    }

    // MARK: The state machine

    func testMessage60IsAnInfoRequestOnlyDuringAKeyboardInteractiveAttempt() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)
        XCTAssertTrue(stateMachine.expectingUserAuthInfoRequest)

        // The attempt fails, and the delegate offers a password instead.
        delegate.offers.append(.password(.init(password: "bar")))
        let next = try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))
        XCTAssertFalse(stateMachine.expectingUserAuthInfoRequest)

        stateMachine.sendUserAuthRequest(try XCTUnwrap(next?.wait()))
        XCTAssertFalse(stateMachine.expectingUserAuthInfoRequest)
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge))
        XCTAssertEqual(delegate.challenges, [])
    }

    func testChallengesAreAnsweredInTurn() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

        delegate.answer = .respond(["hunter2"])
        let first = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge)?.wait())
        XCTAssertEqual(first, .init(responses: ["hunter2"]))
        stateMachine.sendUserAuthInfoResponse(first)
        XCTAssertTrue(stateMachine.expectingUserAuthInfoRequest)

        delegate.answer = .respond(["123456", "0000"])
        let second = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(Self.twoPromptChallenge)?.wait())
        XCTAssertEqual(second, .init(responses: ["123456", "0000"]))
        stateMachine.sendUserAuthInfoResponse(second)

        XCTAssertEqual(delegate.challenges, [.init(Self.passwordChallenge), .init(Self.twoPromptChallenge)])
        XCTAssertEqual(delegate.challenges.last?.name, "Second factor")
        XCTAssertEqual(delegate.challenges.last?.instruction, "Enter both codes")
        XCTAssertEqual(delegate.challenges.last?.prompts.map { $0.echo }, [true, false])

        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
        XCTAssertFalse(stateMachine.expectingUserAuthInfoRequest)
    }

    func testChallengeWithNoPromptsIsAnsweredWithNoResponses() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

        delegate.answer = .respond([])
        let response = try stateMachine.receiveUserAuthInfoRequest(.init(name: "Notice", instruction: "", prompts: []))
        XCTAssertEqual(try response?.wait(), .init(responses: []))
    }

    func testTheNumberOfResponsesMustBeTheNumberOfPrompts() throws {
        for responses in [[], ["one"], ["one", "two", "three"]] {
            let delegate = ScriptedClientAuthDelegate(offers: [])
            var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

            delegate.answer = .respond(responses)
            let response = try stateMachine.receiveUserAuthInfoRequest(Self.twoPromptChallenge)
            XCTAssertThrowsError(try response?.wait()) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidKeyboardInteractiveResponse)
            }
        }
    }

    func testASecondChallengeBeforeTheFirstIsAnsweredIsRejected() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

        XCTAssertNotNil(try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge))
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoRequest(Self.twoPromptChallenge))

        // The delegate was asked once only.
        XCTAssertEqual(delegate.challenges, [.init(Self.passwordChallenge)])
    }

    func testAnAnswerIsNotSentOnceTheServerHasGivenTheOutcome() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

        // The delegate is still thinking when the server gives up on the attempt.
        let response = try XCTUnwrap(try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge))
        _ = try stateMachine.receiveUserAuthFailure(.init(authentications: ["password"], partialSuccess: false))
        XCTAssertFalse(stateMachine.expectingUserAuthInfoRequest)

        delegate.pendingResponse?.succeed(["hunter2"])
        XCTAssertNil(try response.wait())
    }

    func testAnErrorFromTheDelegateIsReported() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        var stateMachine = try self.makeStateMachine(offering: .keyboardInteractive(.init()), delegate: delegate)

        delegate.answer = .fail
        let response = try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge)
        XCTAssertThrowsError(try response?.wait()) { error in
            XCTAssertTrue(error is ScriptedClientAuthDelegate.NoAnswer)
        }
    }

    func testDelegatesThatDoNotImplementChallengesFailThem() throws {
        let loop = EmbeddedEventLoop()
        let promise = loop.makePromise(of: [String].self)
        InfinitePasswordDelegate().respondToKeyboardInteractiveChallenge(
            .init(Self.passwordChallenge),
            responsePromise: promise
        )
        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unsupportedUserAuthenticationMethod)
        }
    }

    func testServersNeverReceiveChallenges() throws {
        var stateMachine = UserAuthenticationStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0)
                )
            ),
            loop: EmbeddedEventLoop(),
            sessionID: ByteBuffer(repeating: 0xAB, count: 32)
        )
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoRequest(Self.passwordChallenge))
        XCTAssertFalse(stateMachine.expectingUserAuthInfoRequest)
    }

    // MARK: Through the handler

    func testServersRefuseKeyboardInteractiveRequests() throws {
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }

        let delegate = ScriptedClientAuthDelegate(offers: [
            .keyboardInteractive(.init()), .password(.init(password: "bar")),
        ])
        var harness = TestHarness()
        harness.clientAuthDelegate = delegate

        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())

        // We assume the usual methods at first. The server then tells us which it takes, and that is not this one.
        XCTAssertEqual(delegate.availableMethods, [.all, .all])
        XCTAssertEqual(delegate.challenges, [])
        XCTAssertTrue(userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
    }

    /// Brings a client to the point where a real server has refused keyboard-interactive authentication and
    /// the client's delegate has been asked what to offer next. From there the test plays the server.
    private func makeChannelAwaitingAnOffer(
        delegate: ScriptedClientAuthDelegate
    ) throws -> (BackToBackEmbeddedChannel, UserEventExpecter) {
        let channel = BackToBackEmbeddedChannel()
        delegate.offers = [.keyboardInteractive(.init())]

        var harness = TestHarness.scriptable()
        harness.clientAuthDelegate = delegate

        let userEvents = UserEventExpecter()
        try channel.configureWithHarness(harness)
        try channel.client.pipeline.syncOperations.addHandler(userEvents)
        try channel.activate()
        try channel.interactInMemory()

        XCTAssertNotNil(delegate.pendingOffer)
        return (channel, userEvents)
    }

    func testKeyboardInteractiveAuthenticationThroughTheHandler() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        let (channel, userEvents) = try self.makeChannelAwaitingAnOffer(delegate: delegate)

        delegate.offer(.keyboardInteractive(.init(submethods: "pam")))
        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [
                .userAuthRequest(
                    .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive(submethods: "pam"))
                )
            ]
        )

        // The first challenge is answered at once, the second after a while.
        delegate.answer = .respond(["hunter2"])
        XCTAssertNoThrow(try channel.sendFromScriptedServer(.userAuthInfoRequest(Self.passwordChallenge)))
        XCTAssertEqual(try channel.messagesForScriptedServer(), [.userAuthInfoResponse(.init(responses: ["hunter2"]))])

        delegate.answer = .wait
        XCTAssertNoThrow(try channel.sendFromScriptedServer(.userAuthInfoRequest(Self.twoPromptChallenge)))
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])
        delegate.pendingResponse?.succeed(["123456", "0000"])
        XCTAssertEqual(
            try channel.messagesForScriptedServer(),
            [.userAuthInfoResponse(.init(responses: ["123456", "0000"]))]
        )

        XCTAssertEqual(delegate.challenges, [.init(Self.passwordChallenge), .init(Self.twoPromptChallenge)])
        XCTAssertFalse(userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })

        XCTAssertNoThrow(try channel.sendFromScriptedServer(.userAuthSuccess))
        XCTAssertTrue(userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })

        // Once authentication is over, message 60 is not a challenge any more.
        XCTAssertThrowsError(try channel.sendFromScriptedServer(.userAuthInfoRequest(Self.passwordChallenge))) {
            error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
        XCTAssertEqual(delegate.challenges.count, 2)
    }

    func testAWrongNumberOfResponsesSendsNothing() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        let (channel, _) = try self.makeChannelAwaitingAnOffer(delegate: delegate)

        delegate.offer(.keyboardInteractive(.init()))
        XCTAssertEqual(try channel.messagesForScriptedServer().count, 1)

        delegate.answer = .respond(["only one"])
        XCTAssertThrowsError(try channel.sendFromScriptedServer(.userAuthInfoRequest(Self.twoPromptChallenge))) {
            error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidKeyboardInteractiveResponse)
        }
        XCTAssertEqual(try channel.messagesForScriptedServer(), [])
    }

    func testAChallengeForAnotherMethodIsAnError() throws {
        let delegate = ScriptedClientAuthDelegate(offers: [])
        let (channel, _) = try self.makeChannelAwaitingAnOffer(delegate: delegate)

        delegate.offer(.password(.init(password: "bar")))
        XCTAssertEqual(try channel.messagesForScriptedServer().count, 1)

        // After a password request, message 60 is not a challenge, and this one is not anything else either.
        XCTAssertThrowsError(try channel.sendFromScriptedServer(.userAuthInfoRequest(Self.passwordChallenge))) {
            error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
        XCTAssertEqual(delegate.challenges, [])
    }
}
