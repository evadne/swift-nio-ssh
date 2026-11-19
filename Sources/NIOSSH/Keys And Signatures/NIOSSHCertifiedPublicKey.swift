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

import Crypto
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Bionic)
import Bionic
#endif

/// A ``NIOSSHCertifiedPublicKey`` is an SSH public key combined with an SSH certificate.
///
/// SSH has a non-standard interface for using a very basic form of certificate-based authentication.
/// This is largely defined by OpenSSH, with the specification written down in [`PROTOCOL.certkeys`](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD) in the
/// OpenSSH repository.
///
/// These certificates are much simpler than X.509 certificates. They are less extensible and carry less
/// information. They cannot be "chained" in the same way as X.509 certificates (that is, the chain length is
/// essentially always 2, leaf + certificate authority). They are very specifically tied to the SSH protocol
/// and solve its specific problems.
///
/// Certificates are most often deployed in larger businesses where managing access control is important. In
/// particular, because the key certification can be done by a "certificate authority", it is possible to
/// tie certificate issuance into access control measures of various kinds. This is highly useful in large
/// enterprises.
///
/// In the SSH protocol itself, certificates fit into a slightly strange space. They are essentially a (weird)
/// key type on the wire, with more information available to them. To mirror this use-case, a ``NIOSSHCertifiedPublicKey``
/// is never directly passed to or from any of the interfaces in SwiftNIO SSH. Instead, it has an optional constructor
/// from ``NIOSSHPublicKey`` and ``NIOSSHPublicKey`` has a non-failing constructor from this key type. This allows users
/// to check at runtime whether a given ``NIOSSHPublicKey`` is _actually_ a ``NIOSSHCertifiedPublicKey``, and allows
/// users that have a ``NIOSSHCertifiedPublicKey`` to use it as though it were a ``NIOSSHPublicKey``.
///
/// A certificate authority may sign with a key of a kind that SwiftNIO SSH does not know, such as an RSA key, or with
/// an algorithm that it does not know. Such a certificate can still be read from the network: the key it certifies is
/// usable, so a peer that presents the certificate can prove that it holds that key. Its ``signatureKey`` and
/// ``signature`` can only be compared and written, and
/// ``validate(principal:type:allowedAuthoritySigningKeys:acceptableCriticalOptions:)`` always refuses it, as
/// SwiftNIO SSH cannot verify the signature. A user that wants to trust such a certificate has to verify it itself,
/// from its bytes.
///
/// A certificate that was read from the network, or from an OpenSSH public key string, and has not been changed
/// since is written out as the bytes it was read from. Those are the bytes that the peer signs when it proves that
/// it holds the key, and the bytes that the certificate authority signed. They are not always the bytes that
/// SwiftNIO SSH would write from the fields: a key ID need not be UTF-8, for example. Changing any property makes
/// SwiftNIO SSH write the certificate from its fields instead.
public struct NIOSSHCertifiedPublicKey {
    /// A CA-provided random bitstring of arbitrary length (typically 16 or 32 bytes). This defends against
    /// hash-collision attacks.
    public var nonce: ByteBuffer {
        get {
            self.backing.nonce
        }
        set {
            self.ensureUniqueStorage()
            self.backing.nonce = newValue
        }
    }

    /// An optional certificate serial number set by the CA to refer to certificates from that CA. CAs are not
    /// required to number their certificates, and may set this field to zero if they wish.
    public var serial: UInt64 {
        get {
            self.backing.serial
        }
        set {
            self.ensureUniqueStorage()
            self.backing.serial = newValue
        }
    }

    /// The type of this certificate: what kind of role it authorises.
    public var type: CertificateType {
        get {
            self.backing.type
        }
        set {
            self.ensureUniqueStorage()
            self.backing.type = newValue
        }
    }

    /// The base public key associated with this certified public key.
    public var key: NIOSSHPublicKey {
        get {
            self.backing.key
        }
        set {
            self.ensureUniqueStorage()
            self.backing.key = newValue
        }
    }

    /// A free-form text field filled in by the CA at the time of signing. Usually used to identify the identity
    /// principal.
    public var keyID: String {
        get {
            self.backing.keyID
        }
        set {
            self.ensureUniqueStorage()
            self.backing.keyID = newValue
        }
    }

    /// The principals for which this certified key is valid. For keys where ``NIOSSHCertifiedPublicKey/type``
    /// is ``NIOSSHCertifiedPublicKey/CertificateType/host``, these will be hostnames. For keys where
    /// ``NIOSSHCertifiedPublicKey/type`` is ``NIOSSHCertifiedPublicKey/CertificateType/user``, these will be
    /// usernames.
    ///
    /// If this is empty, the certificate is valid for _any_ principal of the given type.
    public var validPrincipals: [String] {
        get {
            self.backing.validPrincipals
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validPrincipals = newValue
        }
    }

    /// The earliest instant for which this certificate is valid. The resolution of this field is in seconds since 1970-01-01
    /// 00:00:00.
    public var validAfter: UInt64 {
        get {
            self.backing.validAfter
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validAfter = newValue
        }
    }

    /// The second after the latest instant for which this certificate is valid. The resolution of this field is in
    /// seconds since 1970-01-01 00:00:00.
    public var validBefore: UInt64 {
        get {
            self.backing.validBefore
        }
        set {
            self.ensureUniqueStorage()
            self.backing.validBefore = newValue
        }
    }

    /// Critical options are extensions that indicate restrictions on the default permissions of a certificate. These
    /// are most commonly used for certificates of ``NIOSSHCertifiedPublicKey/CertificateType/user`` type.
    ///
    /// These options are critical in the sense that critical options not recognised by an implementation must lead to the
    /// certificate being not trusted. SwiftNIO does not police these options itself, and relies on users to do so. The
    /// certificate validation APIs provide hooks to allow implementations to identify which options they are willing to
    /// police.
    ///
    /// The two critical options defined in the specification are only usable for
    /// ``NIOSSHCertifiedPublicKey/CertificateType/user`` certificates, and are:
    ///
    /// - `force-command`: Specifies a command that will be executed whenever this certificate is used for auth, replacing
    ///     anything the user selected.
    /// - `source-address`: A comma-separated list of valid source addresses for connections using this certificate. These will
    ///     be represented in CIDR format.
    public var criticalOptions: [String: String] {
        get {
            self.backing.criticalOptions
        }
        set {
            self.ensureUniqueStorage()
            self.backing.criticalOptions = newValue
        }
    }

    /// Extensions usually enable features that would otherwise be disabled for a given user. These are not critical: if they
    /// are not understood it is acceptable to ignore them. SwiftNIO does not act on any extensions: it is up to users to do so.
    public var extensions: [String: String] {
        get {
            self.backing.extensions
        }
        set {
            self.ensureUniqueStorage()
            self.backing.extensions = newValue
        }
    }

    /// The public key corresponding to the private key used to sign this ``NIOSSHCertifiedPublicKey``.
    ///
    /// For a certificate that was read from the network this may be a key of a kind that SwiftNIO SSH does not know.
    /// Such a key can be compared and written, and it verifies nothing. It is never a certificate: a certificate
    /// that names another certificate as the key that signed it is not read.
    public var signatureKey: NIOSSHPublicKey {
        get {
            self.backing.signatureKey
        }
        set {
            self.ensureUniqueStorage()
            self.backing.signatureKey = newValue
        }
    }

    /// The signature over this certificate.
    ///
    /// For a certificate that was read from the network this may be a signature made with an algorithm that
    /// SwiftNIO SSH does not know. Such a signature can be compared and written, and no key finds it valid.
    public var signature: NIOSSHSignature {
        get {
            self.backing.signature
        }
        set {
            self.ensureUniqueStorage()
            self.backing.signature = newValue
        }
    }

    /// The class-based backing storage.
    private var backing: Backing

    public init(
        nonce: ByteBuffer,
        serial: UInt64,
        type: CertificateType,
        key: NIOSSHPublicKey,
        keyID: String,
        validPrincipals: [String],
        validAfter: UInt64,
        validBefore: UInt64,
        criticalOptions: [String: String],
        extensions: [String: String],
        signatureKey: NIOSSHPublicKey,
        signature: NIOSSHSignature
    ) throws {
        self.backing = try Backing(
            nonce: nonce,
            serial: serial,
            type: type,
            key: key,
            keyID: keyID,
            validPrincipals: validPrincipals,
            validAfter: validAfter,
            validBefore: validBefore,
            criticalOptions: criticalOptions,
            extensions: extensions,
            signatureKey: signatureKey,
            signature: signature
        )
    }

    /// Attempt to unwrap a ``NIOSSHPublicKey`` that may contain a ``NIOSSHCertifiedPublicKey``.
    ///
    /// Not all public keys are certified, so this method will fail if the key is not.
    public init?(_ key: NIOSSHPublicKey) {
        guard case .certified(let base) = key.backingKey else {
            return nil
        }

        self = base
    }
}

// `NIOSSHCertifiedPublicKey` implements copy on write (CoW) and is therefore `Sendable`
extension NIOSSHCertifiedPublicKey: @unchecked Sendable {}

extension NIOSSHCertifiedPublicKey {
    /// Validates that a given certified public key is valid for usage.
    ///
    /// This function validates the following criteria:
    ///
    /// 1. Is the certificate attesting to an acceptable principal?
    /// 2. Is the certificate of the appropriate type?
    /// 3. Is the certificate within its valid duration?
    /// 4. Is the certificate signed by one of the `allowedAuthoritySigningKeys`?
    /// 5. Is the certificate attesting to any critical option that is not supported by this implementation?
    ///
    /// If all of the above tests pass, this function will return the values of the acceptable critical options.
    /// These values will not have been validated: validating them is the responsibility of the caller of this
    /// function, and failure to do so may lead to critical security flaws.
    ///
    /// If any of the above tests fail, this function will throw an error. It also throws an error for any
    /// certificate that was signed by a key of a kind, or with an algorithm, that SwiftNIO SSH does not know: the
    /// signature over such a certificate cannot be verified here, so the certificate is never valid here.
    ///
    /// - parameters:
    ///     - principal: The principal that this certificate must be attesting to. Either the
    ///         username the user asked for, or the hostname to which we connected.
    ///     - type: The type of certificate this must be.
    ///     - allowedAuthoritySigningKeys: The signing keys of the certificate authorities trusted by this
    ///         implementation.
    ///     - acceptableCriticalOptions: The critical options understood by this implementation that will be validated
    ///         separately from this function.
    /// - returns: The values of the supported critical options.
    /// - throws: If the certifiate fails to validate.
    public func validate(
        principal: String,
        type: CertificateType,
        allowedAuthoritySigningKeys: [NIOSSHPublicKey],
        acceptableCriticalOptions: [String] = []
    ) throws -> [String: String] {
        // Before we do any computation on values in this certificate, we first need to do the cryptographic
        // validation, to avoid the cryptographic doom principle. First, check if the signing key is in our allowed
        // set: second, validate the signature.
        //
        // A certificate that we read from the network may have been signed by a key of a kind, or with an
        // algorithm, that we do not know. We cannot verify that signature, so we refuse the certificate whatever
        // the caller allows. The signature check below would refuse it as well: we check first to say why.
        if case .unknown = self.signatureKey.backingKey {
            throw NIOSSHError.invalidCertificate(
                diagnostics: "Certificate was signed by a key of an unknown kind and cannot be verified"
            )
        }
        if case .unknown = self.signature.backingSignature {
            throw NIOSSHError.invalidCertificate(
                diagnostics: "Certificate was signed with an unknown algorithm and cannot be verified"
            )
        }

        guard allowedAuthoritySigningKeys.contains(self.signatureKey) else {
            throw NIOSSHError.invalidCertificate(
                diagnostics: "Certificate was not signed by one of the allowed principals"
            )
        }

        guard self.signatureKey.isValidSignature(self.signature, for: self.signableBytes) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Signature is not valid for this certificate")
        }

        guard self.type == type else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is of unexpected type")
        }

        // There's a special case: no principals means valid for any principal
        guard self.validPrincipals.count == 0 || self.validPrincipals.contains(principal) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is not valid for this principal")
        }

        // Check that "now" falls within the validity window [validAfter, validBefore]. The
        // bounds are UInt64 seconds-since-epoch: ssh-keygen writes validBefore == UInt64.max
        // for a certificate that never expires and validAfter == 0 for one valid "from the
        // beginning". The comparison is done in integer seconds (see isValid(nowSeconds:))
        // rather than via DispatchWallTime: converting UInt64.max to time_t (Int64) overflows
        // and traps the process — a crash on ordinary forever-certificates and a client-side
        // denial of service when validating a hostile host certificate — while libdispatch's
        // internal "now" sentinel additionally misreads the epoch (0) as the current instant.
        guard self.isValid(nowSeconds: UInt64(max(0, time(nil)))) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate is no longer valid")
        }

        for criticalOption in self.criticalOptions.keys {
            guard acceptableCriticalOptions.contains(criticalOption) else {
                throw NIOSSHError.invalidCertificate(diagnostics: "Unsupported critical option present")
            }
        }

        return self.criticalOptions
    }

    internal var signableBytes: ByteBuffer {
        var bytes = ByteBufferAllocator().buffer(capacity: 2048)
        bytes.writeSignableBytes(self)
        return bytes
    }

    static let p256KeyPrefix = "ecdsa-sha2-nistp256-cert-v01@openssh.com".utf8

    static let p384KeyPrefix = "ecdsa-sha2-nistp384-cert-v01@openssh.com".utf8

    static let p521KeyPrefix = "ecdsa-sha2-nistp521-cert-v01@openssh.com".utf8

    static let ed25519KeyPrefix = "ssh-ed25519-cert-v01@openssh.com".utf8

    internal var keyPrefix: String.UTF8View {
        switch self.key.backingKey {
        case .ed25519:
            return Self.ed25519KeyPrefix
        case .ecdsaP256:
            return Self.p256KeyPrefix
        case .ecdsaP384:
            return Self.p384KeyPrefix
        case .ecdsaP521:
            return Self.p521KeyPrefix
        case .custom:
            preconditionFailure("base key cannot be of a custom kind")
        case .unknown:
            preconditionFailure("base key cannot be of an unknown kind")
        case .certified:
            preconditionFailure("base key cannot be certified")
        }
    }

    internal func isValidSignature<DigestBytes: Digest>(_ signature: NIOSSHSignature, for digest: DigestBytes) -> Bool {
        self.key.isValidSignature(signature, for: digest)
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for bytes: ByteBuffer) -> Bool {
        self.key.isValidSignature(signature, for: bytes)
    }

    internal func isValidSignature(_ signature: NIOSSHSignature, for payload: UserAuthSignablePayload) -> Bool {
        self.key.isValidSignature(signature, for: payload)
    }

    internal static func baseKeyPrefixForKeyPrefix<Bytes: Collection>(_ prefix: Bytes) throws -> String.UTF8View
    where Bytes.Element == UInt8 {
        if prefix.elementsEqual(Self.ed25519KeyPrefix) {
            return NIOSSHPublicKey.ed25519PublicKeyPrefix
        } else if prefix.elementsEqual(Self.p256KeyPrefix) {
            return NIOSSHPublicKey.ecdsaP256PublicKeyPrefix
        } else if prefix.elementsEqual(Self.p384KeyPrefix) {
            return NIOSSHPublicKey.ecdsaP384PublicKeyPrefix
        } else if prefix.elementsEqual(Self.p521KeyPrefix) {
            return NIOSSHPublicKey.ecdsaP521PublicKeyPrefix
        } else {
            throw NIOSSHError.unknownPublicKey(algorithm: String(decoding: prefix, as: UTF8.self))
        }
    }

    /// How the name of every certificate format that OpenSSH defines ends.
    static let certificateKeyPrefixSuffix = "-cert-v01@openssh.com".utf8

    /// Whether `prefix` is the name of a certificate format: of one that we read, or of any other that is named as
    /// OpenSSH names them, which is a certificate for a key of a kind that we do not know.
    internal static func isCertificateKeyPrefix<Bytes: BidirectionalCollection>(_ prefix: Bytes) -> Bool
    where Bytes.Element == UInt8 {
        // We read a certificate exactly when its format has a base key format, so this is what has to be asked of
        // the formats that we know. It stays right when a format is added there.
        if (try? Self.baseKeyPrefixForKeyPrefix(prefix)) != nil {
            return true
        }

        return prefix.suffix(Self.certificateKeyPrefixSuffix.count).elementsEqual(Self.certificateKeyPrefixSuffix)
    }
}

extension NIOSSHCertifiedPublicKey: Hashable {}

extension NIOSSHCertifiedPublicKey: CustomDebugStringConvertible {
    public var debugDescription: String {
        // Slightly hacky multiline string to try to keep things
        // clear.
        "NIOSSHCertifiedPublicKey(nonce: \(self.nonce), serial: \(self.serial), type: \(self.type), "
            + "key: \(self.key), keyID: \(self.keyID), validPrincipals: \(self.validPrincipals), "
            + "validAfter: \(self.validAfter), validBefore: \(self.validBefore), "
            + "criticalOptions: \(self.criticalOptions), extensions: \(self.extensions), "
            + "signatureKey: \(self.signatureKey), signature: \(self.signature))"
    }
}

extension NIOSSHCertifiedPublicKey {
    /// A ``NIOSSHCertifiedPublicKey/CertificateType`` defines the type of a given certificate.
    ///
    /// In SSH there are essentially two types in standard use: ``NIOSSHCertifiedPublicKey/CertificateType/user``
    /// and ``NIOSSHCertifiedPublicKey/CertificateType/host``. Certificates of type
    /// ``NIOSSHCertifiedPublicKey/CertificateType/user`` identify a user, while certificates of
    /// type ``NIOSSHCertifiedPublicKey/CertificateType/host`` identify a host.
    ///
    /// For extensibility purposes this is not defined as an enumeration, but instead as a `RawRepresentable` type
    /// wrapping the base type.
    public struct CertificateType: RawRepresentable, Sendable {
        public var rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        /// A certificate valid for identifying a user.
        public static let user = CertificateType(rawValue: 1)

        /// A certificate valid for identifying a host.
        public static let host = CertificateType(rawValue: 2)
    }
}

extension NIOSSHCertifiedPublicKey.CertificateType: Hashable {}

extension NIOSSHCertifiedPublicKey.CertificateType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .user:
            return "NIOSSHCertifiedPublicKey.CertificateType.user"
        case .host:
            return "NIOSSHCertifiedPublicKey.CertificateType.host"
        default:
            return "NIOSSHCertifiedPublicKey.CertificateType(rawValue: \(self.rawValue))"
        }
    }
}

extension NIOSSHCertifiedPublicKey {
    /// `NIOSSHCertifiedPublicKey` is a struct backed by a class. We do this for a few reasons:
    ///
    /// 1. The object is otherwise very large, 153 bytes! This is a lot of copying to do if it's passed
    ///     around: it'll inevitably get spilled to the stack each time.
    /// 2. The object contains 8 references, which is a lot. Each copy incurs 8 refcount operations, which is
    ///     way too high for copying this around by value.
    /// 3. This type would risk being self-referential. As this can be the backing type of a `NIOSSHPublicKey`,
    ///     but also _contains_ `NIOSSHPublicKey`s, at a certain point something must become an indirect type
    ///     in order to safely achieve that goal. Given that this type has decent performance reasons to want to
    ///     be heap-allocated, it may as well be this type that incurs that cost.
    ///
    /// By-and-large these objects aren't transient: they're created and used to verify a user or host, being passed through
    /// several methods including out through virtual method boundaries into user code. This more-than-justifies the allocation
    /// cost of creating them: heck, they need to allocate multiple times to be created for all their arrays and dictionaries.
    /// They are also very-rarely mutated: when they are, that mutation is done in the service of trying to actually build an
    /// SSH CA, and so the odds of them being uniquely owned are very high. Thus, the CoW costs are low.
    ///
    /// This all justifies moving this type into class-backed storage.
    fileprivate final class Backing {
        fileprivate var nonce: ByteBuffer
        fileprivate var serial: UInt64
        fileprivate var type: CertificateType
        fileprivate var key: NIOSSHPublicKey {
            willSet {
                if case .certified = newValue.backingKey {
                    preconditionFailure("Certificate may not use certified key as public key")
                }
            }
        }

        fileprivate var keyID: String
        fileprivate var validPrincipals: [String]
        fileprivate var validAfter: UInt64
        fileprivate var validBefore: UInt64
        fileprivate var criticalOptions: [String: String]
        fileprivate var extensions: [String: String]
        fileprivate var signatureKey: NIOSSHPublicKey {
            willSet {
                if case .certified = newValue.backingKey {
                    preconditionFailure("Certificate may not be signed by certified key")
                }
            }
        }

        fileprivate var signature: NIOSSHSignature

        /// The bytes this key was read from, after the name of the key format, if it was read and has not been
        /// changed since. A key that has these is written as them, and not from the fields above.
        fileprivate var encodedFields: ByteBuffer?

        fileprivate init(
            nonce: ByteBuffer,
            serial: UInt64,
            type: CertificateType,
            key: NIOSSHPublicKey,
            keyID: String,
            validPrincipals: [String],
            validAfter: UInt64,
            validBefore: UInt64,
            criticalOptions: [String: String],
            extensions: [String: String],
            signatureKey: NIOSSHPublicKey,
            signature: NIOSSHSignature
        ) throws {
            // These two contrains are _very important_: without them, a number of NIOSSHPublicKey operations become infinitely
            // recursive.
            if case .certified = key.backingKey {
                throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not use certified key as public key")
            }
            if case .certified = signatureKey.backingKey {
                throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not be signed by certified key")
            }

            // We can neither name the certificate type of a key of a custom kind nor verify a signature made by one.
            if case .custom = key.backingKey {
                throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not use custom key as public key")
            }
            if case .custom = signatureKey.backingKey {
                throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not be signed by custom key")
            }

            // Nor can we name the certificate type of a key of an unknown kind, or write the key without its name.
            // Such a key may have signed the certificate, though: that is the one place we read one.
            if case .unknown = key.backingKey {
                throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not use unknown key as public key")
            }

            self.nonce = nonce
            self.serial = serial
            self.type = type
            self.key = key
            self.keyID = keyID
            self.validPrincipals = validPrincipals
            self.validAfter = validAfter
            self.validBefore = validBefore
            self.criticalOptions = criticalOptions
            self.extensions = extensions
            self.signatureKey = signatureKey
            self.signature = signature
        }

        fileprivate init(copying original: Backing) {
            self.nonce = original.nonce
            self.serial = original.serial
            self.type = original.type
            self.key = original.key
            self.keyID = original.keyID
            self.validPrincipals = original.validPrincipals
            self.validAfter = original.validAfter
            self.validBefore = original.validBefore
            self.criticalOptions = original.criticalOptions
            self.extensions = original.extensions
            self.signatureKey = original.signatureKey
            self.signature = original.signature

            // We only copy in order to mutate, and what is mutated is no longer what was read.
            self.encodedFields = nil
        }
    }

    /// Guarantees that the storage for this key is unique. Must be called before mutating anything on `.backing`.
    ///
    /// As a mutation follows, this also forgets the bytes that this key was read from: they are about to stop
    /// describing it.
    mutating func ensureUniqueStorage() {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = Backing(copying: self.backing)
        }
        self.backing.encodedFields = nil
    }

    /// The bytes this key was read from, after the name of the key format, if it was read and has not been changed
    /// since.
    fileprivate var encodedFields: ByteBuffer? {
        self.backing.encodedFields
    }

    /// Records the bytes that this key was just read from. Nothing else may hold the key yet.
    fileprivate mutating func wasRead(from encodedFields: ByteBuffer) {
        self.backing.encodedFields = encodedFields
    }
}

extension NIOSSHCertifiedPublicKey.Backing: Hashable {
    // Keys are compared and hashed by their fields. The bytes that a key was read from say how it was encoded, not
    // what it is.
    static func == (lhs: NIOSSHCertifiedPublicKey.Backing, rhs: NIOSSHCertifiedPublicKey.Backing) -> Bool {
        (lhs.nonce == rhs.nonce && lhs.serial == rhs.serial && lhs.type == rhs.type && lhs.key == rhs.key
            && lhs.keyID == rhs.keyID && lhs.validPrincipals == rhs.validPrincipals && lhs.validAfter == rhs.validAfter
            && lhs.validBefore == rhs.validBefore && lhs.criticalOptions == rhs.criticalOptions
            && lhs.extensions == rhs.extensions && lhs.signatureKey == rhs.signatureKey
            && lhs.signature == rhs.signature)
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.nonce)
        hasher.combine(self.serial)
        hasher.combine(self.type)
        hasher.combine(self.key)
        hasher.combine(self.keyID)
        hasher.combine(self.validPrincipals)
        hasher.combine(self.validAfter)
        hasher.combine(self.validBefore)
        hasher.combine(self.criticalOptions)
        hasher.combine(self.extensions)
        hasher.combine(self.signatureKey)
        hasher.combine(self.signature)
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeCertifiedKey(_ key: NIOSSHCertifiedPublicKey) -> Int {
        // A key that we read, and that has not been changed since, is written as it was read. Its encoding is
        // signed over, by the peer that proves it holds the key and by the certificate authority, and we would not
        // always produce the same encoding from the fields: we do not keep the reserved field, and we hold the key
        // ID and the principals as strings, which they need not be.
        if var encodedFields = key.encodedFields {
            var written = self.writeSSHString(key.keyPrefix)
            written += self.writeBuffer(&encodedFields)
            return written
        }

        // A certified key is the signable bytes plus the signature.
        var written = 0
        written += self.writeSignableBytes(key)
        written += self.writeCompositeSSHString { buffer in
            buffer.writeSSHSignature(key.signature)
        }
        return written
    }

    @discardableResult
    fileprivate mutating func writeSignableBytes(_ key: NIOSSHCertifiedPublicKey) -> Int {
        var written = 0
        var nonceCopy = key.nonce
        written += self.writeSSHString(key.keyPrefix)
        written += self.writeSSHString(&nonceCopy)
        written += self.writePublicKeyWithoutPrefix(key.key)
        written += self.writeInteger(key.serial)
        written += self.writeInteger(key.type.rawValue)
        written += self.writeSSHString(key.keyID.utf8)
        written += self.writePrincipals(key.validPrincipals)
        written += self.writeInteger(key.validAfter)
        written += self.writeInteger(key.validBefore)
        written += self.writeMapStringString(key.criticalOptions)
        written += self.writeMapStringString(key.extensions)
        written += self.writeSSHString([])  // reserved
        written += self.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(key.signatureKey)
        }
        return written
    }

    mutating func readCertifiedKey() throws -> NIOSSHCertifiedPublicKey? {
        try self.rewindOnNilOrError { `self` in
            guard let keyPrefix = self.readSSHStringAsString() else {
                return nil
            }

            return try self.readCertifiedKeyWithoutKeyPrefix(keyPrefix.utf8)
        }
    }

    mutating func readCertifiedKeyWithoutKeyPrefix<Bytes: Collection>(
        _ keyPrefix: Bytes
    ) throws -> NIOSSHCertifiedPublicKey? where Bytes.Element == UInt8 {
        try self.rewindOnNilOrError { `self` in
            let innerKeyPrefix = try NIOSSHCertifiedPublicKey.baseKeyPrefixForKeyPrefix(keyPrefix)
            let unreadBytes = self

            guard
                let nonce = self.readSSHString(),
                let key = try self.readPublicKeyWithoutPrefixForIdentifier(innerKeyPrefix),
                let serial = self.readInteger(as: UInt64.self),
                let rawType = self.readInteger(as: UInt32.self),
                let keyID = self.readSSHStringAsString(),
                var rawPrincipals = self.readSSHString(),
                let validAfter = self.readInteger(as: UInt64.self),
                let validBefore = self.readInteger(as: UInt64.self),
                var rawCriticalOptions = self.readSSHString(),
                var rawExtensions = self.readSSHString(),
                let _ = self.readSSHString(),  // reserved
                var rawSignatureKey = self.readSSHString(),
                var rawSignature = self.readSSHString()
            else {
                return nil
            }

            guard
                let principals = rawPrincipals.readPrincipals(),
                let criticalOptions = try rawCriticalOptions.readMapStringToString(),
                let extensions = try rawExtensions.readMapStringToString(),
                let signatureKey = try rawSignatureKey.readCertificateSignatureKey(),
                let signature = try rawSignature.readCertificateSignature()
            else {
                throw NIOSSHError.invalidSSHMessage(reason: "invalid encoding of certified key")
            }

            var certifiedKey = try NIOSSHCertifiedPublicKey(
                nonce: nonce,
                serial: serial,
                type: NIOSSHCertifiedPublicKey.CertificateType(rawValue: rawType),
                key: key,
                keyID: keyID,
                validPrincipals: principals,
                validAfter: validAfter,
                validBefore: validBefore,
                criticalOptions: criticalOptions,
                extensions: extensions,
                signatureKey: signatureKey,
                signature: signature
            )

            // Everything we have just read is the encoding of the key, less the name of its format.
            let encodedFieldsLength = self.readerIndex - unreadBytes.readerIndex
            certifiedKey.wasRead(from: unreadBytes.getSlice(at: unreadBytes.readerIndex, length: encodedFieldsLength)!)
            return certifiedKey
        }
    }

    /// Reads the key that signed a certificate.
    ///
    /// A certificate authority may sign with a key of a kind that we do not know, such as an RSA key. That is no
    /// reason to fail to read the certificate: the key it certifies is the one we use, and whoever wants to trust
    /// the certificate may be able to verify it where we cannot. We keep such a signature key as its encoding.
    ///
    /// A certificate is signed by a plain key, and never by another certificate. We refuse a signature key that is
    /// a certificate by the name of its format, before we read anything else of it, whether or not we know the kind
    /// of key that it certifies.
    private mutating func readCertificateSignatureKey() throws -> NIOSSHPublicKey? {
        let encodedKey = self

        // The key begins with the name of its format.
        var prefixBytes = encodedKey
        guard let prefix = prefixBytes.readSSHString() else {
            return nil
        }

        // This check is _very important_. To read a certificate is to read the key that signed it, so if that key
        // could be a certificate we would read the key that signed that one in turn, and so on for as many
        // certificates as the peer chose to put inside one another: it could have us run out of stack. With this
        // check, reading a signature key never reads another certificate.
        guard !NIOSSHCertifiedPublicKey.isCertificateKeyPrefix(prefix.readableBytesView) else {
            throw NIOSSHError.invalidCertificate(diagnostics: "Certificate may not be signed by certified key")
        }

        do {
            return try self.readSSHHostKey()
        } catch let error as NIOSSHError where error.type == .unknownPublicKey {
            self.moveReaderIndex(to: self.writerIndex)
            return NIOSSHPublicKey(
                backingKey: .unknown(prefix: String(buffer: prefix), encodedKey: encodedKey)
            )
        }
    }

    /// Reads the signature over a certificate.
    ///
    /// As with the key that made it, we keep a signature made with an algorithm that we do not know as its
    /// encoding.
    private mutating func readCertificateSignature() throws -> NIOSSHSignature? {
        let encodedSignature = self

        do {
            return try self.readSSHSignature()
        } catch let error as NIOSSHError where error.type == .unknownSignature {
            self.moveReaderIndex(to: self.writerIndex)
            return NIOSSHSignature(backingSignature: .unknown(encodedSignature))
        }
    }

    @discardableResult
    private mutating func writePrincipals(_ principals: [String]) -> Int {
        self.writeCompositeSSHString { buffer in
            var written = 0
            for principal in principals {
                written += buffer.writeSSHString(principal.utf8)
            }
            return written
        }
    }

    @discardableResult
    private mutating func writeMapStringString(_ map: [String: String]) -> Int {
        self.writeCompositeSSHString { buffer in
            var written = 0

            // Weird note: for these structures, the map needs to be lexicographically ordered by key. For
            // that reason we actually manifest this into an array and sort: it's cheaper than all the hashing.
            let namesAndValues = Array(map).sorted(by: { $0.key < $1.key })
            for entry in namesAndValues {
                written += buffer.writeSSHString(entry.key.utf8)

                if entry.value.utf8.count > 0 {
                    written += buffer.writeCompositeSSHString { $0.writeSSHString(entry.value.utf8) }
                } else {
                    written += buffer.writeInteger(UInt32(0))  // Empty SSH string
                }
            }
            return written
        }
    }

    private mutating func readPrincipals() -> [String]? {
        var principals = [String]()
        principals.reserveCapacity(1)

        while self.readableBytes > 0 {
            guard let nextPrincipal = self.readSSHStringAsString() else {
                return nil
            }
            principals.append(nextPrincipal)
        }

        return principals
    }

    private mutating func readMapStringToString() throws -> [String: String]? {
        var map: [String: String] = [:]

        while self.readableBytes > 0 {
            guard let key = self.readSSHStringAsString(), var valueString = self.readSSHString() else {
                return nil
            }
            // There's a weirdness here: if the value is non-empty, it's got a string _inside_ it. If it's
            // empty, it doesn't.
            let value: String
            if valueString.readableBytes > 0 {
                guard let innerString = valueString.readSSHStringAsString() else {
                    throw NIOSSHError.invalidSSHMessage(reason: "Invalid encoding of certificate map")
                }
                value = innerString
            } else {
                value = ""
            }
            map[key] = value
        }

        return map
    }
}

extension NIOSSHCertifiedPublicKey {
    /// Whether `nowSeconds` (whole seconds since the Unix epoch) falls within this
    /// certificate's `[validAfter, validBefore]` validity window.
    ///
    /// The comparison is pure `UInt64` integer arithmetic on the raw certificate bounds, so it
    /// is safe across the entire representable range — including the two values `ssh-keygen`
    /// emits for open-ended windows: `validBefore == UInt64.max` ("never expires", so any real
    /// `now` is strictly before it) and `validAfter == 0` ("valid from the beginning", so any
    /// real `now` is at or after it). It never constructs a `DispatchWallTime`, avoiding the
    /// `UInt64 -> time_t` overflow trap on far-future bounds and libdispatch's "now" sentinel
    /// on the epoch.
    internal func isValid(nowSeconds: UInt64) -> Bool {
        self.validAfter <= nowSeconds && nowSeconds < self.validBefore
    }
}
