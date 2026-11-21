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

/// The reason for which the opening of a channel was refused, as `SSH_MSG_CHANNEL_OPEN_FAILURE` carries it
/// (RFC 4254 § 5.1).
///
/// A channel whose opening is refused fails with a ``NIOSSHError`` of the type
/// ``NIOSSHError/ErrorType/channelSetupRejected``, and its ``NIOSSHError/channelOpenFailure`` is the reason given.
///
/// Where the peer refused the channel, all of the reason is chosen by the peer: do not trust it, and filter
/// ``description`` of control characters before displaying it.
public struct NIOSSHChannelOpenFailure: Hashable, Sendable {
    /// The reason for the refusal, as an `SSH_OPEN` reason code (RFC 4254 § 5.1): `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`
    /// is 1, `SSH_OPEN_CONNECT_FAILED` 2, `SSH_OPEN_UNKNOWN_CHANNEL_TYPE` 3 and `SSH_OPEN_RESOURCE_SHORTAGE` 4. A
    /// peer may send any other value.
    public var reasonCode: UInt32

    /// A description of the reason, as worded by the peer. This may be empty. Bytes that are not UTF-8 are read
    /// as U+FFFD REPLACEMENT CHARACTER, as every string of the protocol is.
    public var description: String

    public init(reasonCode: UInt32, description: String) {
        self.reasonCode = reasonCode
        self.description = description
    }
}
