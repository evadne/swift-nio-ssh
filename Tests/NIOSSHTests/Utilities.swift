//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

func assertNoThrowWithValue<T>(
    _ body: @autoclosure () throws -> T,
    defaultValue: T? = nil,
    message: String? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("\(message.map { $0 + ": " } ?? "")unexpected error \(error) thrown", file: file, line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

// This algorithm is not secure, used only for testing purposes
struct InsecureEncryptionAlgorithm {
    static func encrypt(key: ByteBuffer, plaintext: ByteBuffer) -> ByteBuffer {
        var ciphertext = ByteBuffer()
        var plaintext = plaintext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self)
        else {
            preconditionFailure("check key size")
        }

        while var block = plaintext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self)
            else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            ciphertext.writeInteger(v0)
            ciphertext.writeInteger(v1)
            ciphertext.writeInteger(v2)
            ciphertext.writeInteger(v3)
        }
        return ciphertext
    }

    static func decrypt(key: ByteBuffer, ciphertext: ByteBuffer) -> ByteBuffer {
        var plaintext = ByteBuffer()
        var ciphertext = ciphertext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self)
        else {
            preconditionFailure("check key size")
        }

        while var block = ciphertext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self)
            else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            plaintext.writeInteger(v0)
            plaintext.writeInteger(v1)
            plaintext.writeInteger(v2)
            plaintext.writeInteger(v3)
        }

        return plaintext
    }
}

@available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
class TestTransportProtection: NIOSSHTransportProtection {
    enum TestError: Error {
        case doubleDecode
    }

    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        32
    }

    var lengthEncrypted: Bool {
        true
    }

    static var cipherName: String {
        "insecure-tiny-encription-cipher"
    }

    static var macName: String? {
        nil
    }

    static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }

    private var outboundEncryptionKey: ByteBuffer
    private var inboundEncryptionKey: ByteBuffer
    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey

    private var lastFirstBlock: ByteBufferView?

    required init(initialKeys: NIOSSHSessionKeys) {
        precondition(initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = initialKeys.outboundMACKey
        self.inboundMACKey = initialKeys.inboundMACKey
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        precondition(newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = newKeys.outboundMACKey
        self.inboundMACKey = newKeys.inboundMACKey
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        let index = source.readerIndex

        guard let ciphertextView = source.viewBytes(at: index, length: Self.cipherBlockSize),
            ciphertextView.count > 0, ciphertextView.count % Self.cipherBlockSize == 0
        else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        if self.lastFirstBlock == ciphertextView {
            throw TestError.doubleDecode
        }

        self.lastFirstBlock = ciphertextView

        let plaintext = InsecureEncryptionAlgorithm.decrypt(
            key: self.inboundEncryptionKey,
            ciphertext: ByteBuffer(bytes: ciphertextView)
        )

        source.setBytes(plaintext.readableBytesView, at: index)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        defer {
            self.lastFirstBlock = nil
        }

        guard var plaintext = source.readSlice(length: Self.cipherBlockSize) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        // First block is expected to be decoded by decodeFirstBlock
        if source.readableBytes > self.macBytes {
            guard let ciphertext = source.readSlice(length: source.readableBytes - 32),
                ciphertext.readableBytes > 0, ciphertext.readableBytes % Self.cipherBlockSize == 0
            else {
                // The only way this fails is if the payload doesn't match this encryption scheme.
                throw NIOSSHError.invalidEncryptedPacketLength
            }

            var tail = InsecureEncryptionAlgorithm.decrypt(key: self.inboundEncryptionKey, ciphertext: ciphertext)
            plaintext.writeBuffer(&tail)
        }

        guard let tagView = source.readSlice(length: 32)?.readableBytesView else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        guard
            HMAC<SHA256>.isValidAuthenticationCode(
                tagView,
                authenticating: plaintext.readableBytesView,
                using: self.inboundMACKey
            )
        else {
            preconditionFailure("authentication failure")
        }

        // First 4 bytes are length
        plaintext.moveReaderIndex(forwardBy: 4)
        let paddingLength = plaintext.readInteger(as: UInt8.self)!
        return plaintext.readSlice(length: plaintext.readableBytes - Int(paddingLength))!
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let packetLengthIndex = destination.readerIndex
        let encryptedBufferSize = destination.readableBytes

        let plaintextView = destination.viewBytes(at: packetLengthIndex, length: encryptedBufferSize)!
        let ciphertext = InsecureEncryptionAlgorithm.encrypt(
            key: self.outboundEncryptionKey,
            plaintext: ByteBuffer(bytes: plaintextView)
        )
        assert(ciphertext.readableBytes == encryptedBufferSize)

        var hmac = HMAC<SHA256>.init(key: self.outboundMACKey)
        hmac.update(data: plaintextView)

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the tag.
        destination.setBytes(ciphertext.readableBytesView, at: packetLengthIndex)
        let tagLength = destination.writeBytes(hmac.finalize())
        precondition(tagLength == self.macBytes, "Unexpected short tag")
    }
}

/// A transport protection scheme that protects nothing.
///
/// With this scheme negotiated, a test can play one side of a connection by hand after key exchange: it can
/// write packets for a ``NIOSSHHandler`` to read, and it can read the packets that the handler writes.
final class PlaintextTransportProtection: NIOSSHTransportProtection {
    /// The sequence numbers that instances of this scheme have been given for the packets they were asked to
    /// protect, in order. Tests that read this must reset it first.
    static let sequenceNumbers = NIOLockedValueBox<(inbound: [UInt32], outbound: [UInt32])>(([], []))

    static var cipherBlockSize: Int { 8 }

    static var cipherName: String { "plaintext@test.example.com" }

    static var macName: String? { nil }

    static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }

    var macBytes: Int { 0 }

    var lengthEncrypted: Bool { true }

    init(initialKeys: NIOSSHSessionKeys) {}

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {}

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {}

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        guard let content = source.readPlaintextPacketContent() else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        Self.sequenceNumbers.withLockedValue { $0.inbound.append(sequenceNumber) }
        return content
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        Self.sequenceNumbers.withLockedValue { $0.outbound.append(sequenceNumber) }
    }
}

extension ByteBuffer {
    /// Reads one packet that ``PlaintextTransportProtection`` or no protection at all was applied to, and returns
    /// its content.
    fileprivate mutating func readPlaintextPacketContent() -> ByteBuffer? {
        guard let length = self.readInteger(as: UInt32.self), var packet = self.readSlice(length: Int(length)),
            let paddingLength = packet.readInteger(as: UInt8.self)
        else {
            return nil
        }
        return packet.readSlice(length: packet.readableBytes - Int(paddingLength))
    }

    /// Reads every packet in this buffer as ``readPlaintextPacketContent()`` does, and parses the messages.
    mutating func readPlaintextSSHMessages(expectingUserAuthInfoRequest: Bool = false) throws -> [SSHMessage] {
        var messages: [SSHMessage] = []
        while var content = self.readPlaintextPacketContent() {
            guard let message = try content.readSSHMessage(expectingUserAuthInfoRequest: expectingUserAuthInfoRequest)
            else {
                throw NIOSSHError.invalidPacketFormat
            }
            messages.append(message)
        }
        return messages
    }

    /// A packet holding `message`, as ``PlaintextTransportProtection`` would send it.
    static func plaintextSSHPacket(_ message: SSHMessage) -> ByteBuffer {
        var buffer = ByteBuffer()
        buffer.writeSSHPacket(message: message, lengthEncrypted: true, blockSize: 8)
        return buffer
    }

    /// A packet holding the encoding of a message, as ``PlaintextTransportProtection`` would send it. This is for
    /// a message that ``NIOSSH`` would not write as it is given.
    static func plaintextSSHPacket(encodedMessage: ByteBuffer) -> ByteBuffer {
        // The packet is a multiple of eight bytes long, with at least four bytes of padding (RFC 4253 § 6).
        var paddingLength = 8 - ((5 + encodedMessage.readableBytes) % 8)
        if paddingLength < 4 {
            paddingLength += 8
        }

        var buffer = ByteBuffer()
        buffer.writeInteger(UInt32(1 + encodedMessage.readableBytes + paddingLength))
        buffer.writeInteger(UInt8(paddingLength))
        buffer.writeImmutableBuffer(encodedMessage)
        buffer.writeRepeatingByte(0, count: paddingLength)
        return buffer
    }
}

extension BackToBackEmbeddedChannel {
    /// Has the client read `message` as though the server had sent it. Both peers must have negotiated
    /// ``PlaintextTransportProtection``.
    func sendFromScriptedServer(_ message: SSHMessage) throws {
        try self.client.writeInbound(ByteBuffer.plaintextSSHPacket(message))
        self.run()
    }

    /// The messages the client has written and that have not been passed to the server, which never sees them.
    func messagesForScriptedServer(expectingUserAuthInfoRequest: Bool = false) throws -> [SSHMessage] {
        self.run()

        var messages: [SSHMessage] = []
        while var bytes = try self.client.readOutbound(as: ByteBuffer.self) {
            messages.append(
                contentsOf: try bytes.readPlaintextSSHMessages(
                    expectingUserAuthInfoRequest: expectingUserAuthInfoRequest
                )
            )
        }
        return messages
    }
}

extension TestHarness {
    /// A harness whose peers protect nothing, so that a test can play the server by hand once it has to.
    static func scriptable() -> TestHarness {
        var harness = TestHarness()
        harness.configureClient = { $0.transportProtectionSchemes = [PlaintextTransportProtection.self] }
        harness.configureServer = { $0.transportProtectionSchemes = [PlaintextTransportProtection.self] }
        return harness
    }
}

/// A server played by hand, from the first byte, against a client ``NIOSSHHandler``.
///
/// ``NIOSSH`` servers do not implement every extension that clients do. This type lets a test be the server for
/// those: it exchanges keys as a server would and protects nothing afterwards.
final class ScriptedServer {
    static let version = "SSH-2.0-Scripted_1.0"

    let channel = EmbeddedChannel()

    /// The client that this server talks to.
    let clientHandler: NIOSSHHandler

    let userEvents = UserEventExpecter()

    var hostKey = NIOSSHPrivateKey(ed25519Key: .init())

    /// The encoding of the host key to present, where that is not the public half of ``hostKey`` as ``NIOSSH``
    /// writes it: a certificate for it, say.
    var encodedHostKey: ByteBuffer?

    var keyExchange = ScriptedKeyExchangeServer(
        version: ScriptedServer.version,
        hostKeyAlgorithms: ["ssh-ed25519"],
        encryptionAlgorithms: [Substring(PlaintextTransportProtection.cipherName)]
    )

    /// The exchange hash of every key exchange so far, as this server computed it.
    private(set) var exchangeHashes: [ByteBuffer] = []

    private let clientVersion: String

    init(_ configure: (inout SSHClientConfiguration) -> Void = { _ in }) throws {
        var configuration = SSHClientConfiguration(
            userAuthDelegate: InfinitePasswordDelegate(),
            serverAuthDelegate: AcceptAllHostKeysDelegate()
        )
        configuration.transportProtectionSchemes = [PlaintextTransportProtection.self]
        configure(&configuration)
        self.clientVersion = "SSH-2.0-" + configuration.softwareVersion

        self.clientHandler = NIOSSHHandler(
            role: .client(configuration),
            allocator: self.channel.allocator,
            inboundChildChannelInitializer: nil
        )
        try self.channel.pipeline.syncOperations.addHandlers([self.clientHandler, self.userEvents])
        try self.channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    /// Sends `message` to the client.
    func send(_ message: SSHMessage) throws {
        try self.channel.writeInbound(ByteBuffer.plaintextSSHPacket(message))
    }

    /// The messages the client has sent since this was last called.
    func clientMessages() throws -> [SSHMessage] {
        self.channel.embeddedEventLoop.run()

        var messages: [SSHMessage] = []
        while var bytes = try self.channel.readOutbound(as: ByteBuffer.self) {
            if bytes.readableBytesView.starts(with: "SSH-".utf8) {
                // The client's identification string, which is not a message.
                bytes.moveReaderIndex(forwardBy: self.clientVersion.utf8.count + 2)
            }
            messages.append(contentsOf: try bytes.readPlaintextSSHMessages())
        }
        return messages
    }

    /// Sends the server's identification string and returns the client's key exchange initialization.
    func exchangeVersions() throws -> SSHMessage.KeyExchangeMessage {
        try self.channel.writeInbound(ByteBuffer(string: Self.version + "\r\n"))
        guard case .some(.keyExchange(let clientMessage)) = try self.clientMessages().first else {
            throw NIOSSHError.invalidPacketFormat
        }
        return clientMessage
    }

    /// Runs one key exchange to the point where both peers have taken the new keys into use.
    ///
    /// - parameters:
    ///     - clientMessage: The client's key exchange initialization, if it has sent it already. When rekeying
    ///         the client only sends it in answer to ours.
    ///     - beforeNewKeys: Messages to send between the server's reply and its new keys message.
    ///     - whileExchanging: Called once both peers have sent their key exchange initialization, before the
    ///         server replies.
    ///     - afterReply: Called once the server has replied, before it sends anything more.
    func exchangeKeys(
        clientMessage: SSHMessage.KeyExchangeMessage? = nil,
        beforeNewKeys: [SSHMessage] = [],
        whileExchanging: () throws -> Void = {},
        afterReply: () throws -> Void = {}
    ) throws {
        let serverMessage = self.keyExchange.keyExchangeMessage()
        try self.send(.keyExchange(serverMessage))

        var sent = try self.clientMessages()
        var clientMessage = clientMessage
        if clientMessage == nil, case .some(.keyExchange(let message)) = sent.first {
            clientMessage = message
            sent.removeFirst()
        }
        guard let clientMessage = clientMessage, case .some(.keyExchangeInit(let keyExchangeInit)) = sent.first else {
            throw NIOSSHError.invalidPacketFormat
        }

        try whileExchanging()

        let sign: (SHA256.Digest) throws -> NIOSSHSignature = { exchangeHash in
            self.exchangeHashes.append(ByteBuffer(bytes: exchangeHash))
            return try self.hostKey.sign(digest: exchangeHash)
        }

        if let encodedHostKey = self.encodedHostKey {
            let reply = try self.keyExchange.encodedReply(
                clientVersion: self.clientVersion,
                clientMessage: clientMessage,
                serverMessage: serverMessage,
                keyExchangeInit: keyExchangeInit,
                presenting: encodedHostKey,
                sign: sign
            )
            try self.channel.writeInbound(ByteBuffer.plaintextSSHPacket(encodedMessage: reply))
        } else {
            let reply = try self.keyExchange.reply(
                clientVersion: self.clientVersion,
                clientMessage: clientMessage,
                serverMessage: serverMessage,
                keyExchangeInit: keyExchangeInit,
                presenting: self.hostKey.publicKey,
                sign: sign
            )
            try self.send(.keyExchangeReply(reply))
        }
        try afterReply()

        for message in beforeNewKeys {
            try self.send(message)
        }
        try self.send(.newKeys)
    }

    /// Accepts the client's service request and its first authentication request.
    func authenticate() throws {
        try self.send(.serviceAccept(.init(service: "ssh-userauth")))
        try self.send(.userAuthSuccess)
        _ = try self.clientMessages()
    }
}
