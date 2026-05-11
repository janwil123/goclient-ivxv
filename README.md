# IVXV Go Client

This repository contains a standalone Go client for the IVXV collector RPC
services. It is based on the server-side implementation published at
`valimised/ivxv` and speaks the same transport:

- TLS over TCP
- `net/rpc/jsonrpc`
- shared `SessionID` carried in the request/response header

The client currently covers the collector-facing workflow endpoints:

- `RPC.Authenticate` and `RPC.AuthenticateStatus` for Mobile-ID
- `RPC.GetCertificate`, `RPC.Sign`, and `RPC.SignStatus` for Mobile-ID vote signing
- `RPC.Choices`
- `RPC.VoterChoices`
- `RPC.Vote`
- `RPC.Verify`

## Important limitation

This project does not try to recreate the Estonian eID authentication stack.
The collector expects opaque authentication and data tokens produced by the
actual IVXV auth services and signed vote containers such as BDOC. Those are
accepted as inputs by this client.

## Configuration

All settings can be provided via a JSON config file. By default the client
looks for `config.json` in the working directory. A different path can be
specified with the global `-config` flag:

```bash
./ivxv-client -config /path/to/config.json interactive-mid-vote
```

A documented example is provided in [`config.json`](./config.json). The fields
and their defaults are:

| Field | Default | Description |
|---|---|---|
| `midAddr` | `ivxv1.ep.ivxv.ee:443` | Mobile-ID service host:port |
| `choicesAddr` | `ivxv1.ep.ivxv.ee:443` | Choices service host:port |
| `votingAddr` | `ivxv1.ep.ivxv.ee:443` | Voting service host:port |
| `verificationAddr` | _(empty)_ | Verification service host:port |
| `caPath` | _(empty)_ | CA certificate PEM path |
| `certPath` | _(empty)_ | Client certificate PEM path |
| `keyPath` | _(empty)_ | Client private key PEM path |
| `serverName` | `inttest.ivxv.ee` | TLS server name fallback for all services |
| `midServerName` | `mid.inttest.ivxv.ee` | Mobile-ID TLS server name |
| `choicesServerName` | `choices.inttest.ivxv.ee` | Choices TLS server name |
| `votingServerName` | `voting.inttest.ivxv.ee` | Voting TLS server name |
| `verificationServerName` | _(empty)_ | Verification TLS server name |
| `sessionFile` | _(empty)_ | File to persist the session ID |
| `authStateFile` | _(empty)_ | File to persist auth tokens and flow state |
| `osName` | `ivxv-codex-golang` | Client OS string sent to the collector |
| `timeout` | `15s` | Per-request timeout |
| `authMethod` | _(empty)_ | IVXV auth method (`id`, `mid`, `sid`, `wid`) |
| `electionID` | _(empty)_ | IVXV election identifier |
| `questionIDs` | `[]` | List of question identifiers |
| `encKeyPath` | _(empty)_ | ElGamal vote encryption public key PEM |
| `idCode` | _(empty)_ | Estonian personal code (prompted if absent) |
| `phoneNo` | _(empty)_ | Mobile-ID phone number (prompted if absent) |
| `pollEvery` | `2s` | Poll interval for Mobile-ID status requests |
| `submitVote` | `true` | Whether to submit the signed vote |
| `saveVoteTo` | _(empty)_ | Optional path to save the signed BDOC before submission |
| `origin` | `https://ivxv1.ep.ivxv.ee:443` | Signature origin URL |

Any field can be overridden on the command line — CLI flags always take
precedence over the config file.

## CLI

Build:

```bash
go build ./cmd/ivxv-client
```

### Interactive voting (recommended)

With a populated `config.json` the full Mobile-ID voting flow is a single
command:

```bash
./ivxv-client interactive-mid-vote
```

If `idCode` and `phoneNo` are not set in the config, the client prompts for
them interactively.

Individual fields can still be overridden on the command line:

```bash
./ivxv-client interactive-mid-vote -id-code 60001019906 -phone-no +37200000766
```

### Step-by-step commands

The individual RPC commands are also available for scripting or debugging.
They read connection settings from `config.json` and accept the same flags as
overrides:

```bash
./ivxv-client mid-auth -id-code 60001019906 -phone-no +37200000766

./ivxv-client mid-auth-status

./ivxv-client voter-choices

./ivxv-client vote -choices 100.1 -type bdoc -vote-file vote.bdoc

./ivxv-client verify -vote-id deadbeef
```

## Library

The reusable package is in [`client`](./client). It keeps the latest
`SessionID` in memory and updates it from server responses automatically.
It also includes typed Mobile-ID authentication methods that expose the
upstream IVXV `Authenticate` and `AuthenticateStatus` RPCs.

## Interactive voting details

The `interactive-mid-vote` command runs the IVXV RPC services in the expected
order for Mobile-ID voting:

1. `RPC.Authenticate`
2. `RPC.AuthenticateStatus`
3. `RPC.VoterChoices`
4. `RPC.GetCertificate`
5. `RPC.Sign`
6. `RPC.SignStatus`
7. `RPC.Vote`

Notes:

- The client dials `ivxv1.ep.ivxv.ee:443` for Mobile-ID, choices, and voting
  RPC calls and uses service-specific TLS SNI values for routing:
  `mid.inttest.ivxv.ee`, `choices.inttest.ivxv.ee`, and
  `voting.inttest.ivxv.ee`. The dial address and SNI are separate so either
  can be overridden independently.
- The vote container is built locally using the IVXV BDOC BES path. Both IVXV
  ModP ElGamal keys (`1.3.6.1.4.1.3029.2.1`) and IVXV elliptic-curve ElGamal
  keys (`1.3.6.1.4.1.99999.1`, `P-224` or `P-384`) are supported.
- For multi-question elections set `questionIDs` to a list of all question
  identifiers. The client produces one encrypted ballot per question, all
  packed into the same BDOC.
- Follow-up collector calls after Mobile-ID authentication use
  `AuthMethod: "ticket"` because the Mobile-ID service returns ticket tokens
  for the collector auth filter.

## Debugging a vote container

To validate a saved BDOC locally:

```bash
./ivxv-client validate-vote -file out.bdoc
```

If `encKeyPath` is set in `config.json` it is used automatically. The command
checks:

- the BDOC ZIP structure and required entries
- manifest and `SignedInfo` ballot references
- the signer certificate digest in `SignedProperties`
- the raw `SignatureValue` over the embedded `SignedInfo`
- the ASN.1 ballot ciphertext structure against the election public key

If all checks pass but the collector still returns `RPC.Vote: BAD_REQUEST`,
the remaining likely cause is that the collector canonicalizes `SignedInfo`
and `SignedProperties` before verification, while the current client still
builds and signs them as raw XML strings.
