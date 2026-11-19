//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method, and can say whether
    /// the server accepted the last one.
    ///
    /// A server that requires several authentication methods answers an offer it accepts with a list of the
    /// methods that it still requires, and marks that answer as a partial success (RFC 4252 § 5.1). An offer it
    /// rejects is answered with a list of methods too, so only the mark tells the two apart.
    ///
    /// This is called in place of ``nextAuthenticationType(availableMethods:nextChallengePromise:)``. The default
    /// implementation calls that method and discards `partialSuccess`.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - partialSuccess: Whether the server accepted the last offer and requires more. This is `false` when
    ///         no offer has been made yet.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        partialSuccess: Bool,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when the server issues a challenge during keyboard-interactive authentication (RFC 4256).
    ///
    /// This is only called after the delegate has offered
    /// ``NIOSSHUserAuthenticationOffer/Offer-swift.enum/keyboardInteractive(_:)``. The server may issue several
    /// challenges for one offer, so this may be called several times before the offer is accepted or rejected. It
    /// is never called while an earlier challenge is unanswered.
    ///
    /// The delegate must succeed `responsePromise` with exactly one response for each of the challenge's
    /// prompts, in order: for a challenge with no prompts, an empty array. Any other number of responses is an
    /// error and nothing is sent to the server. If the delegate fails `responsePromise` nothing is sent to the
    /// server either, and the error is reported on the channel.
    ///
    /// The default implementation fails `responsePromise`.
    ///
    /// - parameters:
    ///     - challenge: The challenge issued by the server.
    ///     - responsePromise: An `EventLoopPromise` to be fulfilled with one response for each prompt.
    func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        partialSuccess: Bool,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
    }

    public func respondToKeyboardInteractiveChallenge(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<[String]>
    ) {
        responsePromise.fail(NIOSSHError.unsupportedUserAuthenticationMethod)
    }
}
