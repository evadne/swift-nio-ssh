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

/// A single prompt in a keyboard-interactive challenge (RFC 4256).
public struct NIOSSHKeyboardInteractivePrompt: Hashable, Sendable {
    /// The text of the prompt, as worded by the server.
    public var prompt: String

    /// Whether the answer should be shown to the user as it is typed. When this is `false` the answer is a
    /// secret, such as a password.
    public var echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

/// A challenge issued by the server during keyboard-interactive authentication (RFC 4256).
///
/// A server may issue any number of challenges, one after another, before it accepts or rejects the
/// authentication attempt. Each challenge must be answered with exactly one response for each of its
/// ``prompts``, in order.
///
/// All the text in a challenge is chosen by the server, before the client has authenticated it as anything
/// but the holder of its host key. It should be filtered of control characters before it is displayed.
public struct NIOSSHKeyboardInteractiveChallenge: Hashable, Sendable {
    /// The name of the challenge, which may be empty.
    public var name: String

    /// The instructions for the user, which may be empty.
    public var instruction: String

    /// The prompts to answer, in order. This may be empty, in which case the challenge must be answered with no
    /// responses.
    public var prompts: [NIOSSHKeyboardInteractivePrompt]

    public init(name: String, instruction: String, prompts: [NIOSSHKeyboardInteractivePrompt]) {
        self.name = name
        self.instruction = instruction
        self.prompts = prompts
    }
}

extension NIOSSHKeyboardInteractiveChallenge {
    internal init(_ message: SSHMessage.UserAuthInfoRequestMessage) {
        self.name = message.name
        self.instruction = message.instruction
        self.prompts = message.prompts
    }
}
