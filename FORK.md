# This fork

This is a fork of [apple/swift-nio-ssh](https://github.com/apple/swift-nio-ssh), carried for
Looking Glass, a remote access application for iOS. It is Apple's package at a release, with a
small series of patches on top. Apple's README and licence stand as they are.

## How it is arranged

- `main` is Apple's `main`. Nothing is committed to it here.
- A branch named for the release it stands on, `looking-glass/0.15.1` first, is that release
  followed by the fork's own files and then the series of patches.
- The fork's own files are this one and `.gitlab-ci.yml`. They are not offered upstream.
- Remotes in the working clone: `upstream` is Apple's repository, `origin` this fork on GitHub,
  `demeter` the GitLab instance that runs the fork's continuous integration.
- The branch is pushed to `demeter` as changes are made. It is not pushed to `origin`: pushes to
  GitHub are suspended, and the working clone's push address for `origin` is set to a value that
  cannot be pushed to, until that is lifted. The branch is never force-pushed: a commit that has
  been pushed is corrected by a commit after it.
- Nothing is offered to Apple from this branch as it stands. A pull request to Apple is raised
  only on the operator's approval, as a separate process, which may need a small branch
  prepared for the purpose from Apple's `main`.

## What is carried, and what is not

A patch is carried because the application needs what it adds, and for no other reason. Each
is in the package's own style, with tests in the package's own test target. A patch that adds
a feature keeps Apple's behaviour as the default, so that an application which does not ask
for the feature sees no change. A patch that fixes a defect changes the defect and nothing
else. There is no refactoring of Apple's code here and no fix that the application does not
need. A fix found in another fork or in an open pull request may be picked, with its
attribution, when a test shows the defect on the release in use.

Every patch is the fork's to maintain from the moment it is in the series, whoever wrote it
first.

The series is the commits after `FORK.md` on the branch:

    git log --oneline --reverse 0.15.1..looking-glass/0.15.1

It has two parts. What was written for this fork stands before and after what was picked.

**Written for this fork**, nineteen commits.

Eleven come first, each a feature that is off or has Apple's value until the application sets
it: host certificate algorithms offered; keys of a custom kind that sign, and host keys of a
custom kind; keyboard-interactive authentication for a client; partial success reported;
global requests that NIOSSH does not know, sent and received; the peer's disconnect message
reported; the client's software version; strict key exchange; and extension negotiation.

Four follow what was picked, each the fix of a defect, made after a test showed the defect on
this branch:

- A message for a channel that the peer has not confirmed is a protocol violation of the
  connection, where it trapped. A server could answer a request for a channel with channel
  data and stop the client's process. The channel is left as it was. So is a channel that is
  not yet requested, which failed, and whose promise of creation was then never completed.
- A reply to a global request that is ready during a rekey is held and sent after it, in the
  order of the requests, where it was refused and lost.
- A global request that the application sends during a rekey is sent when the rekey ends,
  whichever peer ends it. Where the client's own new keys message ended it, the request waited
  until the server next sent something.
- A channel whose peer sets the maximum packet size to zero is refused, where the first
  write to it never returned. A server could confirm a channel so and hold the client's event
  loop. A channel that the client asked for fails with a protocol violation and is closed; one
  that the peer asks for is answered with a failure. The connection goes on. Every other
  value is worked with as before, down to a maximum packet size of one.

Three stand at the end of the series, after the fixes. Nothing in them is set by the
application: each is inert until a peer presents what failed before, or until the application
reads what is new.

- A certificate signed by a key of a kind that the package does not have, or with an
  algorithm that it does not have, is read, where it failed to parse with `unknownPublicKey`
  or `unknownSignature`. An RSA authority is the common case. A client that offers the host
  certificate algorithms could not reach a host whose certificate such an authority had
  signed: the key exchange reply did not parse, and the delegate was never asked. The
  certificate's signature key and its signature are kept as their bytes, which can be
  compared and written and which verify nothing. Key exchange verifies the host's signature
  under the certified key, as before, and the delegate is given the certificate. The
  package's own `NIOSSHCertifiedPublicKey.validate` refuses such a certificate, whatever
  signing keys it is given, with an error that says why: the application validates it from
  its bytes or takes its plain key. A key or a signature of an unknown kind is still refused
  everywhere else, and a malformed certificate is still refused.
- A certificate that was read is written as the bytes it was read from, where it was written
  again from its fields. By the tests, the two differ where the reserved field is not empty,
  where the key ID is not UTF-8, and where the extensions are not in order or repeat a name;
  by the source, the principals are read as the key ID is and the critical options as the
  extensions are. The exchange hash covers the host key as the host sent it, so key exchange
  with a host that presented such a certificate failed with `invalidExchangeHashSignature`;
  and what `String(openSSHPublicKey:)` gave an application were not the bytes that the
  authority had signed. Setting any property of a certificate makes the package write it
  from its fields again. Equality and `validate` are as they were.
- `NIOSSHHandler.sessionIdentifier`, the exchange hash of the first key exchange, for a
  signature that is defined over it, such as a host's proof of the keys it advertises
  (`hostkeys-prove-00@openssh.com`). It is `nil` until both peers have sent the new keys
  message of the first key exchange, and the same value from then on, whatever keys are
  exchanged later. It is read on the channel and may be read from a delegate's methods. It
  is a read and not an event: an event fired on every connection would change what an
  application that sets nothing sees, and the package's own test of the banner, which takes
  the first user event to be the banner or the success, then never finished.

What an application that sets nothing can observe of the first two: a certificate of the
kinds described can be read by `NIOSSHPublicKey.init(openSSHPublicKey:)`, where it threw; a
server that presents one although no certificate algorithm was negotiated is refused with
`invalidHostKeyForKeyExchange`, where it was refused with the parse error; and a certificate
that was read and not changed is written as it was read.

One more fix of a defect follows them, made after a test showed the defect on this branch:

- A certificate that names a certificate as the key that signed it is refused on the name of
  that key's format, before anything else of the key is read. It was refused before as well,
  but only once the certificate inside it had been read whole, and the one inside that, for
  as many as a peer had put inside one another, and each took stack. A server could present
  a host certificate nested so in its key exchange reply and stop the client's process,
  before the delegate was asked about the host key, and whether or not the client had
  offered a certificate algorithm. The tests do it with 900 certificates in one packet, read
  on a thread with a stack of half a megabyte. The refusal is `invalidCertificate`, as it
  was. A certificate for a key of a kind that the package does not have
  (`ssh-rsa-cert-v01@openssh.com`, say) would have been kept as its bytes, and is refused as
  a signature key in the same way: a format whose name ends in `-cert-v01@openssh.com` is a
  certificate, which is how OpenSSH 10.3 names every one of its certificate formats. OpenSSH
  reads the signature key of a certificate with certificates disallowed (`cert_parse` in its
  `sshkey.c`). One reader serves every place where a key is read: a host key, the key in a
  user authentication request and in its acceptance, and
  `NIOSSHPublicKey.init(openSSHPublicKey:)`.

**Picked from other works**, each after a test showed the defect on this branch; the works
are listed under [Attribution](#attribution):

- Validating a certificate that never expires no longer traps. A server could present such a
  certificate. A certificate valid from the epoch is no longer rejected.
- A child channel's writes during a rekey are held and sent after it, where they were refused,
  and lost without notice when they carried no promise. Two commits.
- EOF can be sent after the peer's EOF, and cannot be sent twice.
- A channel request of an unknown type is accepted whatever data it carries, where it ended
  the connection.
- Replies to global requests leave in the order of the requests, whenever the delegate
  completes them. A commit of the fork's own follows it and withdraws, from the documentation
  of `unknownGlobalRequest`, the duty to complete the promise before returning.
- A cipher that authenticates its own packets is negotiated without a MAC in common, so a
  client reaches a server whose configuration lists only encrypt-then-MAC MACs.
- A child channel follows the writability of the connection, so an application is told to
  wait when the peer stops reading or the path is slow. A commit of the fork's own follows it
  with a test of a peer that does not read.

**Considered and not picked**, since no test showed the defect on this branch: a window
adjustment sent on a channel that the peer has closed (t3chno/swift-nio-ssh `ef522d4`, and
apple/swift-nio-ssh#239). On this release the state in question lasts only within the handling
of the peer's close, which sends the channel's own close before any read is delivered.

## Moving to a new release

A new release of Apple's package gets a new branch. The series is replayed on the new tag
(`git rebase --onto <new tag> 0.15.1 <branch>` on a copy of the branch, or `git am` of
`git format-patch` output), a patch that Apple has since taken is dropped, the package's tests
are run, and continuous integration must pass before the application moves to it.

## Tests

`swift test`, in debug and in release. A release build needs `-Xswiftc -enable-testing`,
since the tests import the module as testable. Continuous integration runs both on Linux with
warnings as errors.

## Attribution

### Picked

A picked commit keeps its author as the commit's author, and its message ends with the commit
it was picked from. Where it was changed for this branch, its message says how. Each of these
is under the Apache License 2.0, as Apple's package is: it is a commit of a fork of the
package or of a pull request to it, in a tree that carries Apple's `LICENSE.txt` unchanged.

- jsoryu/swift-nio-ssh `8b34daa`, by Jonathan Soryu: certificate validity compared in whole
  seconds. Its tests were formatted.
- apple/swift-nio-ssh#253, commits `ce05c77` and `17e73fd`, by C0de-M0nkey: child channel
  writes held during a rekey.
- hiimtmac/swift-nio-ssh `95d1bc8`, by Taylor McIntyre: the state transitions for sending
  EOF. It had no tests; the tests in its commit were written for this fork.
- apple/swift-nio-ssh#222, commit `3a6193c`, by Jeff (jeffellin): the data of a channel
  request of an unknown type consumed.
- apple/swift-nio-ssh#264, commit `34a4baf`, by 0z5a: replies to global requests sent in
  request order. Adapted: upstream refuses a request of an unknown type at once, and here the
  delegate's reply to it takes its place in the queue.
- ferneast/swift-nio-ssh `9879e39`, by Johnson Zhang: a self-authenticating cipher negotiated
  without a common MAC.
- apple/swift-nio-ssh#252, commit `e2daad6`, by Adam Radestock: the parent channel's
  writability forwarded to child channels.

### Followed

The nineteen patches written for this fork copy no code from another work. Where one follows
the names or the design of another work, so that an application written against it needs
little change if Apple takes that work, the patch's message says so. Those works, all under
the Apache License 2.0:

- kitknox/swift-nio-ssh-rootshell at `58cec1b`, whose authors include Kit Knox and Joannis
  Orlandos: the name and default of `advertiseHostCertificateAlgorithms`; the names
  `NIOSSHPublicKeyProtocol`, `NIOSSHPrivateKeyProtocol` and `publicKeyPrefix`, and the idea of
  a key type that the application supplies; the bound of 256 prompts in a
  keyboard-interactive challenge.
- Pull requests to apple/swift-nio-ssh: #242 by noelmom (keyboard-interactive: the names of
  the public types, of the delegate requirement and of the two error types); #258 by
  jeffcaldwellca (the signature of the delegate requirement for partial success); #254 by
  C0de-M0nkey (the signature of `sendGlobalRequest`).
