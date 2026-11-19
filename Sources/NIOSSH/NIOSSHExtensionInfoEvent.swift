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

/// This event indicates that the server has told us which protocol extensions it supports (RFC 8308).
///
/// The event is fired as a user inbound event on the channel of a client whose configuration enables
/// ``SSHClientConfiguration/extensionNegotiation``, if the server supports extension negotiation. It is fired
/// after keys have been exchanged and before the client's first authentication offer is asked for. A server may
/// send its extensions a second time, just before user authentication succeeds, in which case the event is
/// fired again and replaces the first.
public struct NIOSSHExtensionInfoEvent: Hashable, Sendable {
    /// A single extension.
    public struct Extension: Hashable, Sendable {
        /// The name of the extension, such as `server-sig-algs`.
        public var name: String

        /// The value of the extension, in a format that is specific to it.
        public var value: ByteBuffer

        public init(name: String, value: ByteBuffer) {
            self.name = name
            self.value = value
        }
    }

    /// The extensions, in the order in which the server listed them.
    public var extensions: [Extension]

    public init(extensions: [Extension]) {
        self.extensions = extensions
    }

    /// The public key algorithms that the server accepts for user authentication, if it said: the value of the
    /// `server-sig-algs` extension (RFC 8308 § 3.1).
    public var serverSignatureAlgorithms: [String]? {
        guard let value = self.extensions.first(where: { $0.name == "server-sig-algs" })?.value else {
            return nil
        }
        return String(buffer: value).split(separator: ",").map { String($0) }
    }
}

extension NIOSSHExtensionInfoEvent {
    internal init(_ message: SSHMessage.ExtensionInfoMessage) {
        self.extensions = message.extensions
    }
}
