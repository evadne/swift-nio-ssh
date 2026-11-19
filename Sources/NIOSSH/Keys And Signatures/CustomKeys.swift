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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A public key of a kind that ``NIOSSH`` does not have built in.
///
/// ``NIOSSH`` has built-in support for Ed25519 and ECDSA keys. A type that conforms to this protocol describes
/// the public half of a key of any other kind, such as RSA, well enough for ``NIOSSH`` to send it to a peer. It
/// can be wrapped in a ``NIOSSHPublicKey`` using ``NIOSSHPublicKey/init(custom:)``.
///
/// Two keys of a custom kind are equal when they have the same ``publicKeyPrefix`` and write the same bytes. A
/// key of a custom kind is never equal to a key of a built-in kind.
public protocol NIOSSHPublicKeyProtocol: Sendable {
    /// The name of the key format, such as `ssh-rsa`. This is the string that begins the encoding of the key.
    static var publicKeyPrefix: String { get }

    /// Writes the key in its format-specific encoding: the bytes that follow the name of the key format in the
    /// encoding of a public key (RFC 4253 § 6.6).
    ///
    /// - returns: The number of bytes written.
    func write(to buffer: inout ByteBuffer) -> Int
}

/// A public key of a kind that ``NIOSSH`` does not have built in, which can be read from the network and can
/// verify signatures.
///
/// A client accepts host keys of the types listed in ``SSHClientConfiguration/customHostKeyTypes``. This is how a
/// client can connect to a server whose only host key is, for example, an RSA key.
///
/// - Important: Implementations decide whether a host has proven that it holds its key, so they must be written
///     with care. ``isValidSignature(_:algorithm:for:)`` must verify `signature` with the algorithm it is given
///     and no other.
public protocol NIOSSHVerifyingPublicKeyProtocol: NIOSSHPublicKeyProtocol, _NIOSSHSendableMetatype {
    /// The names of the public key algorithms that keys of this type can verify signatures of, in order of
    /// preference. For an `ssh-rsa` key these are `rsa-sha2-512` and `rsa-sha2-256` (RFC 8332).
    ///
    /// These are the names a client proposes as host key algorithms. A signature is only ever verified when it
    /// was made with the algorithm that was negotiated.
    ///
    /// - Important: The algorithm `ssh-rsa`, which signs with SHA-1, must not be listed. ``NIOSSH`` does not
    ///     accept signatures made with it.
    static var signatureAlgorithms: [String] { get }

    /// Reads a key from its format-specific encoding: the bytes that
    /// ``NIOSSHPublicKeyProtocol/write(to:)`` writes.
    ///
    /// - parameters:
    ///     - buffer: The bytes that follow the name of the key format. All of them must be read.
    /// - throws: If `buffer` does not hold a valid key.
    static func read(from buffer: inout ByteBuffer) throws -> Self

    /// Verifies that `signature` was made over `data` by the holder of the private half of this key.
    ///
    /// - parameters:
    ///     - signature: The signature blob: the bytes that follow the name of the algorithm in the encoding of a
    ///         signature (RFC 4253 § 6.6).
    ///     - algorithm: The algorithm that the signature was made with. This is always one of
    ///         ``signatureAlgorithms``.
    ///     - data: The data that was signed. It has not been hashed.
    func isValidSignature<D: DataProtocol>(_ signature: ByteBuffer, algorithm: String, for data: D) -> Bool
}

/// A private key of a kind that ``NIOSSH`` does not have built in.
///
/// A type that conforms to this protocol signs on behalf of a ``NIOSSHPrivateKey`` created with
/// ``NIOSSHPrivateKey/init(custom:)``. It does not need to hold any key material itself: the private key may be
/// kept by the operating system, in a secure element, or by some other party, so long as it can be asked to sign.
///
/// - Important: ``signature(for:)`` is called synchronously on the event loop of the connection. Implementations
///     should not block.
public protocol NIOSSHPrivateKeyProtocol: Sendable {
    /// The public half of this key.
    var publicKey: any NIOSSHPublicKeyProtocol { get }

    /// The name of the public key algorithm that this key signs with, such as `rsa-sha2-512`.
    ///
    /// This is the name sent to the peer alongside the key, and it is part of the data that is signed. It is
    /// distinct from ``NIOSSHPublicKeyProtocol/publicKeyPrefix`` because one key format may be used with several
    /// algorithms: an `ssh-rsa` key signs as `rsa-sha2-256` or `rsa-sha2-512` (RFC 8332). The default
    /// implementation returns the public key's ``NIOSSHPublicKeyProtocol/publicKeyPrefix``.
    var signatureAlgorithm: String { get }

    /// Signs `data` with the algorithm named by ``signatureAlgorithm``.
    ///
    /// - parameters:
    ///     - data: The data to sign. It has not been hashed.
    /// - returns: The signature blob: the bytes that follow the name of the algorithm in the encoding of a
    ///     signature (RFC 4253 § 6.6). For `rsa-sha2-256` and `rsa-sha2-512` that is the signature as an SSH
    ///     string.
    func signature<D: DataProtocol>(for data: D) throws -> ByteBuffer
}

extension NIOSSHPrivateKeyProtocol {
    public var signatureAlgorithm: String {
        type(of: self.publicKey).publicKeyPrefix
    }
}

extension NIOSSHPublicKeyProtocol {
    /// The encoding of this key without the name of its format, used to compare and to hash keys.
    internal var writtenBytes: ByteBuffer {
        var buffer = ByteBuffer()
        _ = self.write(to: &buffer)
        return buffer
    }
}

extension NIOSSHPublicKeyProtocol {
    /// Verifies a signature made with `algorithm`, if this key is of a type that can verify and `algorithm` is
    /// one that the type verifies.
    internal func isValidCustomSignature<D: DataProtocol>(
        _ signature: ByteBuffer,
        algorithm: String,
        for data: D
    ) -> Bool {
        guard let key = self as? any NIOSSHVerifyingPublicKeyProtocol,
            type(of: key).signatureAlgorithms.contains(algorithm)
        else {
            return false
        }
        return key.isValidSignature(signature, algorithm: algorithm, for: data)
    }
}

extension Array where Element == any NIOSSHVerifyingPublicKeyProtocol.Type {
    /// The names of every algorithm that keys of these types verify signatures of, in order of preference.
    internal var signatureAlgorithms: [String] {
        self.flatMap { $0.signatureAlgorithms }
    }

    /// Whether these types may be accepted by a client as host key types alongside the built-in ones.
    internal func validateAsHostKeyTypes() {
        var prefixes = Set(NIOSSHPublicKey.knownAlgorithms.map { String($0) })
        var algorithms = Set(SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms.map { String($0) })
        algorithms.formUnion(SSHKeyExchangeStateMachine.supportedServerHostCertificateAlgorithms.map { String($0) })
        // RSA with SHA-1 (RFC 4253 § 6.6). The format of an RSA key is also called "ssh-rsa", and that is fine.
        algorithms.insert("ssh-rsa")

        for type in self {
            precondition(
                prefixes.insert(type.publicKeyPrefix).inserted,
                "customHostKeyTypes may not hold two types for the key format \(type.publicKeyPrefix), or a type for a built-in one"
            )
            precondition(
                !algorithms.contains(type.publicKeyPrefix) || type.publicKeyPrefix == "ssh-rsa",
                "customHostKeyTypes may not hold a type for the key format \(type.publicKeyPrefix)"
            )
            for algorithm in type.signatureAlgorithms {
                precondition(
                    algorithms.insert(algorithm).inserted,
                    "customHostKeyTypes may not list the algorithm \(algorithm): it is built in, listed twice, or not accepted"
                )
            }
        }
    }
}
