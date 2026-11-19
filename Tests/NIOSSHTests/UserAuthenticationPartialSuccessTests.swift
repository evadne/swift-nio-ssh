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

final class UserAuthenticationPartialSuccessTests: XCTestCase {
    /// A delegate that offers a password every time, and records what it is told.
    private final class RecordingDelegate: NIOSSHClientUserAuthenticationDelegate {
        var calls: [(methods: NIOSSHAvailableUserAuthenticationMethods, partialSuccess: Bool)] = []

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            XCTFail("The method that carries partial success must be called in place of this one")
            nextChallengePromise.succeed(nil)
        }

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            partialSuccess: Bool,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            self.calls.append((availableMethods, partialSuccess))
            nextChallengePromise.succeed(
                .init(username: "foo", serviceName: "", offer: .password(.init(password: "bar")))
            )
        }
    }

    /// A delegate written before partial success was reported.
    private final class OlderDelegate: NIOSSHClientUserAuthenticationDelegate {
        var calls: [NIOSSHAvailableUserAuthenticationMethods] = []

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            self.calls.append(availableMethods)
            nextChallengePromise.succeed(
                .init(username: "foo", serviceName: "", offer: .password(.init(password: "bar")))
            )
        }
    }

    private func makeStateMachine(
        delegate: NIOSSHClientUserAuthenticationDelegate
    ) throws -> UserAuthenticationStateMachine {
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

    func testDelegateIsToldOfPartialSuccess() throws {
        let delegate = RecordingDelegate()
        var stateMachine = try self.makeStateMachine(delegate: delegate)

        // Nothing has been offered yet, so nothing has succeeded.
        XCTAssertEqual(delegate.calls.count, 1)
        XCTAssertEqual(delegate.calls.last?.methods, .all)
        XCTAssertEqual(delegate.calls.last?.partialSuccess, false)

        // The server takes the password and wants a public key as well.
        let second = try stateMachine.receiveUserAuthFailure(
            .init(authentications: ["publickey"], partialSuccess: true)
        )
        XCTAssertEqual(delegate.calls.count, 2)
        XCTAssertEqual(delegate.calls.last?.methods, .publicKey)
        XCTAssertEqual(delegate.calls.last?.partialSuccess, true)

        // The server rejects what was offered next. That is a failure and nothing else.
        stateMachine.sendUserAuthRequest(try XCTUnwrap(second?.wait()))
        _ = try stateMachine.receiveUserAuthFailure(.init(authentications: ["publickey"], partialSuccess: false))
        XCTAssertEqual(delegate.calls.count, 3)
        XCTAssertEqual(delegate.calls.last?.methods, .publicKey)
        XCTAssertEqual(delegate.calls.last?.partialSuccess, false)
    }

    func testOlderDelegatesAreCalledAsBefore() throws {
        let delegate = OlderDelegate()
        var stateMachine = try self.makeStateMachine(delegate: delegate)

        _ = try stateMachine.receiveUserAuthFailure(.init(authentications: ["publickey"], partialSuccess: true))
        XCTAssertEqual(delegate.calls, [.all, .publicKey])
    }
}
