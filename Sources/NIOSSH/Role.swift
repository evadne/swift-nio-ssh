//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// The role of a given party in an SSH connection.
public enum SSHConnectionRole {
    /// This entity is an SSH client.
    case client(SSHClientConfiguration)

    /// This entity is an SSH server.
    case server(SSHServerConfiguration)

    internal var isClient: Bool {
        switch self {
        case .client:
            return true
        case .server:
            return false
        }
    }

    internal var isServer: Bool {
        switch self {
        case .client:
            return false
        case .server:
            return true
        }
    }

    internal var transportProtectionSchemes: [NIOSSHTransportProtection.Type] {
        switch self {
        case .client(let configuration):
            return configuration.transportProtectionSchemes
        case .server(let configuration):
            return configuration.transportProtectionSchemes
        }
    }

    /// The identification string that this peer sends, without its line ending. This is also part of what the
    /// key exchange signs, so it must be the same wherever it is used.
    internal var version: String {
        switch self {
        case .client(let configuration):
            return "SSH-2.0-" + configuration.softwareVersion
        case .server:
            return Constants.version
        }
    }

    /// Whether the peer may send `SSH_MSG_EXT_INFO`: it may if we are a client that offered extension
    /// negotiation.
    internal var extensionNegotiation: Bool {
        switch self {
        case .client(let configuration):
            return configuration.extensionNegotiation
        case .server:
            return false
        }
    }

    /// The types of host key of a custom kind that the peer may present. Only clients are presented with host keys.
    internal var customHostKeyTypes: [any NIOSSHVerifyingPublicKeyProtocol.Type] {
        switch self {
        case .client(let configuration):
            return configuration.customHostKeyTypes
        case .server:
            return []
        }
    }

    /// The maximum size of a channel data payload this peer advertises it is willing to receive,
    /// and against which inbound encrypted packets are bounded.
    internal var maximumPacketSize: UInt32 {
        switch self {
        case .client(let configuration):
            return UInt32(truncatingIfNeeded: configuration.maximumPacketSize)
        case .server(let configuration):
            return UInt32(truncatingIfNeeded: configuration.maximumPacketSize)
        }
    }
}

@available(*, unavailable)
extension SSHConnectionRole: Sendable {}
