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

/// This event indicates that the remote peer has ended the connection by sending `SSH_MSG_DISCONNECT`.
///
/// The event is fired as a user inbound event on the channel just before ``NIOSSHHandler`` closes it. A
/// connection that is closed without this event having been fired was not ended by the peer in the terms of the
/// protocol: it was lost, or it was closed locally.
///
/// All of this event is chosen by the peer, and it may arrive before the peer has been authenticated: do not
/// trust it, and filter ``description`` of control characters before displaying it.
public struct NIOSSHDisconnectEvent: Hashable, Sendable {
    /// The reason for the disconnection, as an `SSH_DISCONNECT` reason code (RFC 4253 § 11.1).
    public var reasonCode: UInt32

    /// A description of the reason, as worded by the peer. This may be empty.
    public var description: String

    /// The tag identifying the language used for ``description``, following RFC 3066. This is usually empty.
    public var languageTag: String

    public init(reasonCode: UInt32, description: String, languageTag: String) {
        self.reasonCode = reasonCode
        self.description = description
        self.languageTag = languageTag
    }
}

extension NIOSSHDisconnectEvent {
    internal init(_ message: SSHMessage.DisconnectMessage) {
        self.reasonCode = message.reason
        self.description = message.description
        self.languageTag = message.tag
    }
}
