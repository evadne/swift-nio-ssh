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

/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// The maximum size, in bytes, of a channel data payload this peer is willing to receive (the
    /// "maximum packet size" of an SSH channel, RFC 4254 §5.1). It is advertised to the remote peer
    /// when opening channels and bounds inbound encrypted packets. Defaults to `1 << 17` (128 KiB).
    ///
    /// The per-channel receive window we advertise is a fixed multiple of this value (64x), so raising
    /// this value raises the window proportionally. The window is stored as an `Int32`, meaning
    /// values above ~33 MiB (`Int32.max / 64`) saturate the window.
    ///
    /// - Precondition: Must be at least 32768 bytes, the uncompressed payload size
    ///   RFC 4253 §6.1 requires every implementation to support.
    /// - Precondition: The packet size must leave 1024 bytes for headers and framing.
    public var maximumPacketSize: Int = Constants.defaultMaximumChannelPacketSize {
        didSet {
            precondition(
                self.maximumPacketSize >= Constants.minimumChannelPacketSize,
                "maximumPacketSize must be at least \(Constants.minimumChannelPacketSize) bytes (RFC 4253 §6.1)"
            )
            precondition(
                self.maximumPacketSize <= Constants.maximumChannelPacketSize,
                "maximumPacketSize must leave room for SSH framing and padding (RFC 4253 §6)."
            )
        }
    }

    /// The software version that this client names in its identification string, which is the first thing it
    /// sends to a server: `SSH-2.0-` followed by this value (RFC 4253 § 4.2). Defaults to `SwiftNIOSSH_1.0`.
    ///
    /// Servers log this string, and some change their behavior according to it.
    ///
    /// - Precondition: Must be between 1 and 64 printable US-ASCII characters, none of which is a space or a
    ///   minus sign.
    public var softwareVersion: String = Constants.softwareVersion {
        didSet {
            precondition(
                Self.isValidSoftwareVersion(self.softwareVersion),
                "softwareVersion must be 1 to 64 printable US-ASCII characters without spaces or minus signs"
            )
        }
    }

    /// Whether `softwareVersion` may be used in an identification string. RFC 4253 § 4.2 allows printable
    /// US-ASCII characters other than whitespace and the minus sign, and limits the whole string to 255 bytes.
    internal static func isValidSoftwareVersion(_ softwareVersion: String) -> Bool {
        let bytes = softwareVersion.utf8
        return (1...64).contains(bytes.count)
            && bytes.allSatisfy { $0 > UInt8(ascii: " ") && $0 < 0x7F && $0 != UInt8(ascii: "-") }
    }

    /// Whether this client offers OpenSSH's strict key exchange extension (`kex-strict-c-v00@openssh.com`), the
    /// countermeasure to the Terrapin attack (CVE-2023-48795). Defaults to `false`.
    ///
    /// Strict key exchange is used only when the server offers it too. The client then requires the server's
    /// first packet to be its key exchange initialization, accepts no message during the first key exchange
    /// that is not part of it, and sets its packet sequence numbers back to zero whenever new keys are taken
    /// into use. Without it, a party on the network path can remove packets from the start of the encrypted
    /// stream of some transport protection schemes without being detected.
    public var strictKeyExchange: Bool = false

    /// Whether this client offers the OpenSSH host certificate algorithms (`*-cert-v01@openssh.com`) ahead of
    /// the plain host key algorithms. Defaults to `false`.
    ///
    /// When this is `true` a server that holds a host certificate presents it instead of its plain host key.
    /// The certificate is passed to
    /// ``NIOSSHClientServerAuthenticationDelegate/validateHostKey(hostKey:validationCompletePromise:)`` as a
    /// ``NIOSSHPublicKey`` that wraps a ``NIOSSHCertifiedPublicKey``, which can be unwrapped with
    /// ``NIOSSHCertifiedPublicKey/init(_:)``.
    ///
    /// ``NIOSSH`` proves only that the server holds the private key that the certificate certifies. It does
    /// **not** validate the certificate: the delegate is responsible for checking the certificate authority, the
    /// principals, the validity window and the critical options before it trusts the certificate.
    public var advertiseHostCertificateAlgorithms: Bool = false

    /// The types of host key that this client accepts in addition to the Ed25519 and ECDSA keys that ``NIOSSH``
    /// has built in. Defaults to none.
    ///
    /// The client proposes the ``NIOSSHVerifyingPublicKeyProtocol/signatureAlgorithms`` of each type as host key
    /// algorithms, after the built-in ones and in the order given here. A server that has a host key of a built-in
    /// kind therefore still presents that. A host key of one of these types is passed to
    /// ``NIOSSHClientServerAuthenticationDelegate/validateHostKey(hostKey:validationCompletePromise:)`` like any
    /// other, once the type has verified the server's signature.
    ///
    /// - Precondition: No two types may share a key format or an algorithm, and none may use the name of a
    ///   built-in key format or algorithm.
    /// - Precondition: No type may list the algorithm `ssh-rsa`, which signs with SHA-1.
    public var customHostKeyTypes: [any NIOSSHVerifyingPublicKeyProtocol.Type] = [] {
        didSet {
            self.customHostKeyTypes.validateAsHostKeyTypes()
        }
    }

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            userAuthDelegate: userAuthDelegate,
            serverAuthDelegate: serverAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            transportProtectionSchemes: Constants.bundledTransportProtectionSchemes
        )
    }

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.userAuthDelegate = userAuthDelegate
        self.serverAuthDelegate = serverAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.transportProtectionSchemes = transportProtectionSchemes
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHClientConfiguration: Sendable {}
