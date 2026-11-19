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
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class StrictKeyExchangeTests: XCTestCase {
    private static let serverMarker: Substring = "kex-strict-s-v00@openssh.com"

    private static let clientMarker: Substring = "kex-strict-c-v00@openssh.com"

    private let ignore = SSHMessage.ignore(.init(data: ByteBuffer(string: "ignore me")))

    override func setUp() {
        PlaintextTransportProtection.sequenceNumbers.withLockedValue { $0 = ([], []) }
    }

    private var sequenceNumbers: (inbound: [UInt32], outbound: [UInt32]) {
        PlaintextTransportProtection.sequenceNumbers.withLockedValue { $0 }
    }

    private func makeServer(clientOffers: Bool, serverOffers: Bool) throws -> ScriptedServer {
        let server = try ScriptedServer { $0.strictKeyExchange = clientOffers }
        if serverOffers {
            server.keyExchange.keyExchangeAlgorithms.append(Self.serverMarker)
        }
        return server
    }

    private func assertProtocolViolation(
        _ body: @autoclosure () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation, file: file, line: line)
        }
    }

    // MARK: Offering it

    func testStrictKeyExchangeIsNotOfferedByDefault() throws {
        let server = try ScriptedServer()
        let clientMessage = try server.exchangeVersions()
        XCTAssertFalse(clientMessage.keyExchangeAlgorithms.contains(Self.clientMarker))
        XCTAssertFalse(clientMessage.keyExchangeAlgorithms.contains(Self.serverMarker))
    }

    func testStrictKeyExchangeIsOfferedLastWhenEnabled() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: false)
        let clientMessage = try server.exchangeVersions()
        XCTAssertEqual(clientMessage.keyExchangeAlgorithms.last, Self.clientMarker)
        XCTAssertEqual(clientMessage.keyExchangeAlgorithms.filter { $0 == Self.clientMarker }.count, 1)
    }

    func testStrictKeyExchangeIsOfferedInTheFirstKeyExchangeOnly() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.authenticate())

        // The server asks for new keys. The client's answer must not carry the marker again.
        XCTAssertNoThrow(try server.send(.keyExchange(server.keyExchange.keyExchangeMessage())))
        guard case .some(.keyExchange(let rekeyMessage)) = try server.clientMessages().first else {
            return XCTFail("Expected the client to answer with its own key exchange initialization")
        }
        XCTAssertFalse(rekeyMessage.keyExchangeAlgorithms.contains(Self.clientMarker))
    }

    // MARK: Sequence numbers

    func testSequenceNumbersCarryOnWithoutStrictKeyExchange() throws {
        for (clientOffers, serverOffers) in [(false, false), (true, false), (false, true)] {
            PlaintextTransportProtection.sequenceNumbers.withLockedValue { $0 = ([], []) }

            let server = try self.makeServer(clientOffers: clientOffers, serverOffers: serverOffers)
            XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
            XCTAssertNoThrow(try server.authenticate())

            // Three packets went each way before the new keys: the count carries on from there.
            XCTAssertEqual(self.sequenceNumbers.inbound, [3, 4], "client \(clientOffers), server \(serverOffers)")
            XCTAssertEqual(self.sequenceNumbers.outbound, [3, 4], "client \(clientOffers), server \(serverOffers)")
        }
    }

    func testSequenceNumbersStartAgainUnderStrictKeyExchange() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.authenticate())

        XCTAssertEqual(self.sequenceNumbers.inbound, [0, 1])
        XCTAssertEqual(self.sequenceNumbers.outbound, [0, 1])
        XCTAssertTrue(server.userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
    }

    func testSequenceNumbersStartAgainAtEveryRekeyUnderStrictKeyExchange() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.authenticate())

        // The marker means nothing in a later key exchange, and the rule holds all the same.
        server.keyExchange.keyExchangeAlgorithms.removeAll { $0 == Self.serverMarker }
        XCTAssertNoThrow(try server.exchangeKeys())
        XCTAssertNoThrow(try server.send(self.ignore))
        XCTAssertNoThrow(try server.send(self.ignore))

        // Inbound: two packets under the first keys, four for the rekey, and then two from zero.
        XCTAssertEqual(self.sequenceNumbers.inbound, [0, 1, 2, 3, 4, 0, 1])
        // Outbound: two packets under the first keys, three for the rekey, and nothing since.
        XCTAssertEqual(self.sequenceNumbers.outbound, [0, 1, 2, 3, 4])

        // The client's own new keys message ended the rekey. What it sends next is numbered from zero.
        XCTAssertEqual(try server.clientMessages(), [.newKeys])
        let handler = try server.channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
        handler.sendGlobalRequest(name: "keepalive@openssh.com", wantReply: false)
        XCTAssertEqual(try server.clientMessages().count, 1)
        XCTAssertEqual(self.sequenceNumbers.outbound, [0, 1, 2, 3, 4, 0])
    }

    // MARK: The first key exchange

    func testOtherMessagesDuringTheFirstKeyExchangeAreRejectedUnderStrictKeyExchange() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        let clientMessage = try server.exchangeVersions()
        self.assertProtocolViolation(
            try server.exchangeKeys(clientMessage: clientMessage, beforeNewKeys: [self.ignore])
        )
        XCTAssertEqual(self.sequenceNumbers.inbound, [])
    }

    func testOtherMessagesDuringTheFirstKeyExchangeAreToleratedOtherwise() throws {
        for (clientOffers, serverOffers) in [(false, false), (true, false), (false, true)] {
            let server = try self.makeServer(clientOffers: clientOffers, serverOffers: serverOffers)
            let clientMessage = try server.exchangeVersions()
            XCTAssertNoThrow(try server.exchangeKeys(clientMessage: clientMessage, beforeNewKeys: [self.ignore]))
            XCTAssertNoThrow(try server.authenticate())
            XCTAssertTrue(server.userEvents.userEvents.contains { $0 is UserAuthSuccessEvent })
        }
    }

    func testAMessageBeforeTheKeyExchangeInitializationIsRejectedUnderStrictKeyExchange() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        let clientMessage = try server.exchangeVersions()

        // We cannot know that the server offers strict key exchange until it says so, and by then it is too late.
        XCTAssertNoThrow(try server.send(self.ignore))
        self.assertProtocolViolation(try server.exchangeKeys(clientMessage: clientMessage))
    }

    func testAMessageBeforeTheKeyExchangeInitializationIsToleratedOtherwise() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: false)
        let clientMessage = try server.exchangeVersions()

        XCTAssertNoThrow(try server.send(self.ignore))
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: clientMessage))
        XCTAssertNoThrow(try server.authenticate())
    }

    func testOtherMessagesAreToleratedAfterTheFirstKeyExchange() throws {
        let server = try self.makeServer(clientOffers: true, serverOffers: true)
        XCTAssertNoThrow(try server.exchangeKeys(clientMessage: try server.exchangeVersions()))
        XCTAssertNoThrow(try server.send(self.ignore))
        XCTAssertNoThrow(try server.authenticate())
        XCTAssertNoThrow(try server.send(self.ignore))

        // During a rekey they are tolerated too: the rule is for the first key exchange.
        XCTAssertNoThrow(try server.exchangeKeys(beforeNewKeys: [self.ignore]))
        XCTAssertNoThrow(try server.send(self.ignore))
    }

    func testAServerDoesNotOfferStrictKeyExchange() throws {
        let server = SSHKeyExchangeStateMachine(
            allocator: ByteBufferAllocator(),
            loop: EmbeddedEventLoop(),
            role: .server(
                .init(hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
            ),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        let algorithms = server.createKeyExchangeMessage().keyExchangeAlgorithms
        XCTAssertFalse(algorithms.contains(Self.serverMarker))
        XCTAssertFalse(algorithms.contains(Self.clientMarker))
    }
}
