# This fork

This is a fork of [apple/swift-nio-ssh](https://github.com/apple/swift-nio-ssh), carried for
Looking Glass, a remote access application for iOS. It is Apple's package at a release, with a
small series of patches on top. Apple's README and licence stand as they are.

## How it is arranged

- `main` is Apple's `main`. Nothing is committed to it here.
- A branch named for the release it stands on, `looking-glass/0.15.1` first, is that release
  followed by the fork's own files and then the series, one commit for each patch.
- The fork's own files are this one and `.gitlab-ci.yml`. They are not offered upstream.
- Remotes in the working clone: `upstream` is Apple's repository, `origin` this fork on GitHub,
  `demeter` the GitLab instance that runs the fork's continuous integration.

## What is carried, and what is not

A patch is carried because the application needs what it adds, and for no other reason. Each
is written in the package's own style, with tests in the package's own test target, and keeps
Apple's behaviour as the default, so that an application which does not ask for a feature sees
no change. There is no refactoring of Apple's code here and no fix that the application does
not need. A fix found in another fork or in an open pull request may be picked, with its
attribution, when a test shows the defect on the release in use.

Every patch is the fork's to maintain from the moment it is in the series, whoever wrote it
first.

The series is the commits after `FORK.md` on the branch:

    git log --oneline --reverse 0.15.1..looking-glass/0.15.1

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

Every patch in the series was written for this fork. No code was copied from another work.
Where a patch follows the names or the design of another work, so that an application written
against it needs little change if Apple takes that work, the patch's message says so. Those
works, all under the Apache License 2.0:

- kitknox/swift-nio-ssh-rootshell at `58cec1b`, whose authors include Kit Knox and Joannis
  Orlandos: the name and default of `advertiseHostCertificateAlgorithms`; the names
  `NIOSSHPublicKeyProtocol`, `NIOSSHPrivateKeyProtocol` and `publicKeyPrefix`, and the idea of
  a key type that the application supplies; the bound of 256 prompts in a
  keyboard-interactive challenge.
- Pull requests to apple/swift-nio-ssh: #242 by noelmom (keyboard-interactive: the names of
  the public types, of the delegate requirement and of the two error types); #258 by
  jeffcaldwellca (the signature of the delegate requirement for partial success); #254 by
  C0de-M0nkey (the signature of `sendGlobalRequest`).
