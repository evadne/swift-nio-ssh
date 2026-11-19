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

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class SoftwareVersionTests: XCTestCase {
    /// The first bytes a client with this configuration sends.
    private func identification(_ configure: (inout SSHClientConfiguration) -> Void) throws -> String? {
        var configuration = SSHClientConfiguration(
            userAuthDelegate: ExplodingAuthDelegate(),
            serverAuthDelegate: AcceptAllHostKeysDelegate()
        )
        configure(&configuration)

        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(
            role: .client(configuration),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
        )
        try channel.pipeline.syncOperations.addHandler(handler)
        try channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait()

        return try channel.readOutbound(as: ByteBuffer.self).map { String(buffer: $0) }
    }

    func testDefaultIdentification() throws {
        XCTAssertEqual(try self.identification { _ in }, "SSH-2.0-SwiftNIOSSH_1.0\r\n")
    }

    func testConfiguredIdentification() throws {
        XCTAssertEqual(try self.identification { $0.softwareVersion = "Example_2.3" }, "SSH-2.0-Example_2.3\r\n")
    }

    func testServersSendTheDefaultIdentification() throws {
        let channel = EmbeddedChannel()
        let handler = NIOSSHHandler(
            role: .server(
                .init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
            ),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
        )
        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        XCTAssertNoThrow(try channel.connect(to: .init(unixDomainSocketPath: "/fake")).wait())
        XCTAssertEqual(
            try channel.readOutbound(as: ByteBuffer.self),
            ByteBuffer(string: "SSH-2.0-SwiftNIOSSH_1.0\r\n")
        )
    }

    func testKeyExchangeAgreesOnAConfiguredIdentification() throws {
        // Both identification strings are part of what the server signs. The server takes ours from the
        // network, so the handshake completes only if we signed the one we sent.
        let channel = BackToBackEmbeddedChannel()
        defer {
            XCTAssertNoThrow(try channel.finish())
        }

        var harness = TestHarness()
        harness.configureClient = { $0.softwareVersion = "Example_2.3" }

        let userEvents = UserEventExpecter()
        XCTAssertNoThrow(try channel.configureWithHarness(harness))
        XCTAssertNoThrow(try channel.client.pipeline.syncOperations.addHandler(userEvents))
        XCTAssertNoThrow(try channel.activate())
        XCTAssertNoThrow(try channel.interactInMemory())
        XCTAssertTrue(userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
    }

    func testSoftwareVersionValidation() {
        XCTAssertTrue(SSHClientConfiguration.isValidSoftwareVersion("SwiftNIOSSH_1.0"))
        XCTAssertTrue(SSHClientConfiguration.isValidSoftwareVersion("x"))
        XCTAssertTrue(SSHClientConfiguration.isValidSoftwareVersion(String(repeating: "x", count: 64)))

        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion(""))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion(String(repeating: "x", count: 65)))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion("with space"))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion("with-minus"))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion("line\r\nbreak"))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion("null\u{0}"))
        XCTAssertFalse(SSHClientConfiguration.isValidSoftwareVersion("caf\u{E9}"))
    }
}
