---
title: KEM-based pre-shared-key handshakes for TLS 1.3
abbrev: AuthKEM-PSK
docname: draft-wiggers-tls-authkem-psk-latest
category: info

ipr: trust200902
submissiontype: IETF
area: SECAREA
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Wiggers
    name: Thom Wiggers
    org: PQShield
    city: Nijmegen
    country: The Netherlands
    email: thom@thomwiggers.nl

 -
    ins: S. Celi
    name: Sofía Celi
    org: Brave Software
    city: Lisbon
    country: Portugal
    email: cherenkov@riseup.net

 -
    ins: P. Schwabe
    name: Peter Schwabe
    org: "Radboud University and MPI-SP"
    email: peter@cryptojedi.org

 -
    ins: D. Stebila
    name: Douglas Stebila
    org: University of Waterloo
    city: "Waterloo, ON"
    country: Canada
    email: dstebila@uwaterloo.ca

 -
    ins: N. Sullivan
    name: Nick Sullivan
    email: nicholas.sullivan+ietf@gmail.com

venue:
  group: tlswg
  type: Working Group
  mail: tls@ietf.org
  github: kemtls/draft-celi-wiggers-tls-authkem

normative:
  RFC8446:
  RFC9180:

informative:
#  RFC5280:
  SSW20:
    title: "Post-Quantum TLS without Handshake Signatures"
    date: 2020-11
    author:
      - ins: D. Stebila
        name: Douglas Stebila
        org: University of Waterloo
      - ins: P. Schwabe
        name: Peter Schwabe
        org: "Radboud University and Max Planck Institute for Security and Privacy"
      - ins: T. Wiggers
        name: Thom Wiggers
        org: "Radboud University"
    seriesinfo:
      "ACM CCS 2020":
      DOI: 10.1145/3372297.3423350
      "IACR ePrint": https://ia.cr/2020/534
  SSW21:
    title: "More Efficient KEMTLS with Pre-Shared Keys"
    date: 2021-05
    author:
      - ins: D. Stebila
        name: Douglas Stebila
        org: University of Waterloo
      - ins: P. Schwabe
        name: Peter Schwabe
        org: "Radboud University and Max Planck Institute for Security and Privacy"
      - ins: T. Wiggers
        name: Thom Wiggers
        org: "Radboud University"
    seriesinfo:
      "ESORICS 2021":
      DOI: 10.1007/978-3-030-88418-5_1
      "IACR ePrint": https://ia.cr/2021/779
  CHSW22:
    title: "A tale of two models: formal verification of KEMTLS in Tamarin"
    date: 2022-08
    author:
      - ins: S. Celi
        name: Sofía Celi
        org: Brave Software
      - ins: J. Hoyland
        name: Jonathan Hoyland
        org: Cloudflare, Inc.
      - ins: D. Stebila
        name: Douglas Stebila
        org: University of Waterloo
      - ins: T. Wiggers
        name: Thom Wiggers
        org: "Radboud University"
    seriesinfo:
      "ESORICS 2022":
      DOI: 10.1007/978-3-031-17143-7_4
      "IACR ePrint": https://ia.cr/2022/1111
  NISTPQC:
    title: Post-Quantum Cryptography Standardization
    date: 2020
    author:
      - ins: NIST
        org: National Institute for Standards and Technology
  Wig24:
    title: "Post-Quantum TLS"
    date: 2024-01-09
    author:
      - ins: T. Wiggers
        name: Thom Wiggers
        org: Radboud University
    seriesinfo:
      "PhD thesis": "https://thomwiggers.nl/publication/thesis/"
  KW16:
    title: "The OPTLS Protocol and TLS 1.3"
    date: 2016
    seriesinfo: Proceedings of Euro S&P 2016
    target: https://ia.cr/2015/978
    author:
    -
      ins: H. Krawczyk
      name: Hugo Krawczyk
      org: IBM Research
    -
      ins: H. Wee
      name: Hoeteck Wee
      org: ENS, CNRS, INRIA and Columbia University
  MX22:
    title: Post-Quantum Anonymity of Kyber
    date: 2022
    author:
      - ins: V. Maram
        name: Varum Maram
        org: ETH Zurich
      - ins: K. Xagawa
        name: Keita Xagawa
        org: NTT Social Informatics Laboratories
    seriesinfo:
      "PKC": 2023
      "IACR ePrint": https://ia.cr/2022/1696
  FIPS203:
    title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    author:
      - ins: National Institute of Standards and Technology
    seriesinfo:
      DOI: 10.6028/NIST.FIPS.203

--- abstract

This document gives a construction in which (long-term) KEM public keys are
used in the place of TLS PSK keys, avoiding concerns that may affect
systems that use symmetric-key-based PSK, such as requiring key diversification
and protection of symmetric-keys' confidentiality.

This mechanism is inspired by AuthKEM (and could use AuthKEM certificate public
keys for resumption), but can be independently implemented.

--- middle

# Introduction

**Note:** This is a work-in-progress draft. We welcome discussion, feedback and
contributions through the IETF TLS working group mailing list or directly on
GitHub.

This document gives a construction for KEM-based, PSK-style abbreviated TLS 1.3
{{!RFC8446}} handshakes. It is similar in spirit to
{{?I-D.celi-wiggers-tls-authkem}}, but can be independently implemented.

The abbreviated handshake is appropriate for endpoints that have KEM public
keys, and where the client has the server's public key before initiation of the
connection. Though this is currently rare, certificates can be issued with
(EC)DH public keys as specified for instance in {{!RFC8410}}, or using a
delegation mechanism, such as delegated credentials {{?I-D.ietf-tls-subcerts}}.
The public keys need not necessarily be certificates, however. The client might
be provided with the public key as a matter of configuration.

In this proposal, we build on {{!RFC9180}}. This standard currently only covers
Diffie-Hellman based KEMs, but the first post-quantum algorithms have already
been put forward {{?I-D.westerbaan-cfrg-hpke-xyber768d00}}. This proposal
uses ML-KEM [FIPS203] {{?I-D.cfrg-schwabe-kyber}}, the first selected
algorithm for key exchange in the NIST post-quantum standardization project
[NISTPQC].

## Revision history
**This section should be removed prior to publication of a final version of this
document.**

* Revision draft-wiggers-tls-authkem-psk-02
  * Fixing a few links
  * Update to ML-KEM/FIPS203
* Revision draft-wiggers-tls-authkem-psk-01
  * Revised abstract
  * Minor edits
* Revision draft-wiggers-tls-authkem-psk-00
  * Split PSK mechanism off from {{?I-D.celi-wiggers-tls-authkem}}
* Revision draft-celi-wiggers-tls-authkem-01
  * Significant Editing
  * Use HPKE context
* Revision draft-celi-wiggers-tls-authkem-00
  * Initial version

## Related work

This proposal draws inspiration from {{?I-D.ietf-tls-semistatic-dh}}, which is
in turn based on the OPTLS proposal for TLS 1.3 [KW16]. However, these proposals
require a non-interactive key exchange: they combine the client's public key
with the server's long-term key. This imposes an extra requirement: the
ephemeral and static keys MUST use the same algorithm, which this proposal does
not require. Additionally, there are no post-quantum proposals for a
non-interactive key exchange currently considered for standardization, while
several KEMs are on the way.

## Organization

After covering preliminaries, we introduce the abbreviated AuthKEM-PSK
handshake, and its opportunistic client authentication mechanism. In the
remainder of the draft, we will discuss the necessary implementation mechanics,
such as code points, extensions, new protocol messages and the new key schedule.

# Conventions and definitions

{::boilerplate bcp14}

## Terminology

The following terms are used as they are in {{!RFC8446}}

client:
: The endpoint initiating the TLS connection.

connection:
: A transport-layer connection between two endpoints.

endpoint:
: Either the client or server of the connection.

handshake:
: An initial negotiation between client and server that establishes the
parameters of their subsequent interactions within TLS.

peer:
: An endpoint.  When discussing a particular endpoint, "peer" refers to the
endpoint that is not the primary subject of discussion.

receiver:
: An endpoint that is receiving records.

sender:
: An endpoint that is transmitting records.

server:
: The endpoint that responded to the initiation of the TLS connection. i.e. the
peer of the client.

## Key Encapsulation Mechanisms

As this proposal relies heavily on KEMs, which are not originally used by TLS,
we will provide a brief overview of this primitive. Other cryptographic
operations will be discussed later.

This definition matches the one from {{?I-D.celi-wiggers-tls-authkem}}.

A Key Encapsulation Mechanism (KEM) is a cryptographic primitive that defines
the methods ``Encapsulate`` and ``Decapsulate``. In this draft, we extend these
operations with context separation strings:

{:vspace}
``Encapsulate(pkR, context_string)``:
: Takes a public key, and produces a shared secret and encapsulation.

{:vspace}
``Decapsulate(enc, skR, context_string)``:
: Takes the encapsulation and the private key. Returns the shared secret.

We implement these methods through the KEMs defined in {{!RFC9180}} to export
shared secrets appropriate for using with key schedule in TLS 1.3:

~~~
def Encapsulate(pk, context_string):
  enc, ctx = HPKE.SetupBaseS(pk, "tls13 auth-kem")
  ss = ctx.Export(context_string, HKDF.Length)
  return (enc, ss)

def Decapsulate(enc, sk, context_string):
  return HPKE.SetupBaseR(enc, sk, "tls13 auth-kem")
             .Export(context_string, HKDF.Length)
~~~

Keys are generated and encoded for transmission following the conventions in
{{!RFC9180}}. The values of `context_string` are defined in
[](#kem-computations).

**Open question:** Should we keep using HPKE, or just use "plain" KEMs, as in
the original KEMTLS works? Please see the discussion at [Issue
#32](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/32).

# Abbreviated AuthKEM with pre-shared public KEM keys {#psk-protocol}

When the client already has the server's long-term public key, we can do a more
efficient handshake. The client will send the encapsulation to the server's
long-term public key in a ``ClientHello`` extension. An overview of the
abbreviated AuthKEM handshake is given in Figure 3.

A client that already knows the server, might also already know that it will be
required to present a client certificate. This is expected to be especially
useful in server-to-server scenarios. The abbreviated handshake allows to
encrypt the certificate and send it similarly to early data.

~~~~~
       Client                                        Server
Key  ^ ClientHello
Exch | + key_share
&    | + stored_auth_key
Auth | + signature_algorithms
     | + early_auth*
     | + early_data*
     | (Certificate*)
     | (Application Data*)    -------->        ServerHello  ^
     |                                         + key_share  |
     |                                   + stored_auth_key  | Key
     |                                       + early_auth*  | Exch,
     |                                       + early_data*  | Auth &
     |                               {EncryptedExtensions}  | Server
     |                                 {KEMEncapsulation*}  | Params
     |                       <--------          {Finished}  v
     |                       <-------- [Application Data*]
     | (EndOfEarlyData)
     v {Finished}            -------->

       [Application Data]    <------->  [Application Data]

        +  Indicates noteworthy extensions sent in the
           previously noted message.
        *  Indicates optional or situation-dependent
           messages/extensions that are not always sent.
        <> Indicates messages protected using keys
           derived from a
           client_early_handshake_traffic_secret.
        () Indicates messages protected using keys derived
           from a client_early_traffic_secret.
        {} Indicates messages protected using keys
           derived from a
           [sender]_handshake_traffic_secret.
        [] Indicates messages protected using keys
           derived from [sender]_application_traffic_secret_N.

      Figure 3: Abbreviated AuthKEM handshake, with optional
                opportunistic client authentication.
~~~~~

## Negotiation {#sec-authkem-pdk-negotiation}

**In an [](#psk-variant), we sketch a variant based on the PSK extension.**

A client that knows a server's long-term KEM public key MAY choose to attempt
the abbreviated AuthKEM handshake. If it does so, it MUST include the
``stored_auth_key`` extension in the ``ClientHello`` message. This message MUST
contain the encapsulation against the long-term KEM public key. Details of the
extension are described below. The shared secret resulting from the
encapsulation is mixed in to the `EarlySecret` computation.

The client MAY additionally choose to send a certificate to the server. It MUST
know what ciphersuites the server accepts before it does so. If it chooses to do
so, it MUST send the ``early_auth`` extension to the server. The ``Certificate``
is encrypted with the ``client_early_handshake_traffic_secret``.

The server MAY accept the abbreviated AuthKEM handshake. If it does, it MUST
reply with a ``stored_auth_key`` extension. If it does not accept the
abbreviated AuthKEM handshake, for instance because it does not have access to
the correct secret key anymore, it MUST NOT reply with a `stored_auth_key`
extension. The server, if it accepts the abbreviated AuthKEM handshake, MAY
additionally accept the ``Certificate`` message. If it does, it MUST reply with
a ``early_auth`` extension.

If the client, who sent a ``stored_auth_key`` extension, receives a
``ServerHello`` without ``stored_auth_key`` extension, it MUST recompute
``EarlySecret`` without the encapsulated shared secret.

If the client sent a ``Certificate`` message, it MUST drop that message from its
transcript. The client MUST then continue with a full AuthKEM handshake.

## 0-RTT, forward secrecy and replay protection

The client MAY send 0-RTT data, as in {{!RFC8446}} 0-RTT mode. The
``Certificate`` MUST be sent before the 0-RTT data.

As the ``EarlySecret`` is derived only from a key encapsulated to a long-term
secret, it does not have forward secrecy. Clients MUST take this into
consideration before transmitting 0-RTT data or opting in to early client auth.
Certificates and 0-RTT data may also be replayed.

This will be discussed in full under Security Considerations.

# Implementation

In this section we will discuss the implementation details such as extensions
and key schedule.

## Negotiation of AuthKEM algorithms

Clients and servers indicate support for AuthKEM authentication by negotiating
it as if it were a signature scheme (part of the `signature_algorithms`
extension). We thus add these new signature scheme values (even though, they are
not signature schemes) for the KEMs defined in {{!RFC9180}} Section 7.1. Note
that we will be only using their internal KEM's API defined there.

~~~
enum {
  dhkem_p256_sha256   => TBD,
  dhkem_p384_sha384   => TBD,
  dhkem_p521_sha512   => TBD,
  dhkem_x25519_sha256 => TBD,
  dhkem_x448_sha512   => TBD,
  kem_x25519kyber768  => TBD, /*draft-westerbaan-cfrg-hpke-xyber768d00*/
}
~~~

This matches the definition in {{?I-D.celi-wiggers-tls-authkem}}.

**Please give feedback on which KEMs should be included**

When present in the `signature_algorithms` extension, these values indicate
AuthKEM support with the specified key exchange mode. These values MUST NOT
appear in `signature_algorithms_cert`, as this extension specifies the signing
algorithms by which certificates are signed.

## ClientHello and ServerHello extensions

A number of AuthKEM messages contain tag-length-value encoded extensions
structures. We are adding those extensions to the `ExtensionType` list from TLS
1.3.

~~~
enum {
  ...
  stored_auth_key (TBD),                 /* RFC TBD */
  early_auth (TBD),                      /* RFC TBD */
  (65535)
} ExtensionType;
~~~

The table below indicates the messages where a given extension may
appear:

~~~
+---------------------------------------+-------------+
| Extension                             |    KEM-Auth |
+---------------------------------------+-------------+
| stored_auth_key [RFCTBD]              |      CH, SH |
|                                       |             |
| early_auth  [RFCTBD]                  |      CH, SH |
|                                       |             |
+---------------------------------------+-------------+
~~~

### Stored Auth Key

To transmit the early authentication encapsulation in the abbreviated AuthKEM
handshake, this document defines a new extension type
(``stored_auth_key (TBD)``). It is used in `ClientHello` and `ServerHello`
messages.

The `extension_data` field of this extension, when included in the
`ClientHello`, MUST contain the `StoredInformation` structure.

~~~
struct {
      select (type) {
        case client:
          opaque key_fingerprint<1..255>;
          opaque ciphertext<1..2^16-1>
        case server:
          AcceptedAuthKey '1';
      } body;
} StoredInformation
~~~

This extension MUST contain the following information when included in
``ClientHello`` messages:

* The client indicates the public key encapsulated to by its fingerprint
* The client submits the ciphertext

The server MUST send the extension back as an acknowledgement, if and only if it
wishes to negotiate the abbreviated AuthKEM handshake.

The fingerprint calculation proceeds this way:

1.  Compute the SHA-256 hash of the input data. Note that the computed hash only
    covers the input data structure (and not any type and length information of
    the record layer).
2.  Use the output of the SHA-256 hash.

If this extension is not present, the client and the server MUST NOT negotiate
the abbreviated AuthKEM handshake.

The presence of the fingerprint might reveal information about the identity of
the server that the client has. This is discussed further under [Security
Considerations](#sec-considerations).


### Early authentication

To indicate the client will attempt client authentication in the abbreviated
AuthKEM handshake, and for the server to indicate acceptance of attempting this
authentication mechanism, we define the ```early_auth (TDB)`` extension. It is
used in ``ClientHello`` and ``ServerHello`` messages.

~~~
struct {} EarlyAuth
~~~

This is an empty extension.

It MUST NOT be sent if the ``stored_auth_key`` extension is not present.

## Protocol messages

The handshake protocol is used to negotiate the security parameters
of a connection, as in TLS 1.3. It uses the same messages, except
for the addition of a `KEMEncapsulation` message and does not use
the `CertificateVerify` one.

Note that these definitions mirror {{?I-D.celi-wiggers-tls-authkem}}.

~~~
enum {
    ...
    kem_encapsulation(tbd),
    ...
    (255)
  } HandshakeType;

struct {
    HandshakeType msg_type;  /* handshake type */
    uint24 length;           /* remaining bytes in message */
    select (Handshake.msg_type) {
        ...
        case kem_encapsulation:     KEMEncapsulation;
        ...
    };
} Handshake;
~~~

Protocol messages MUST be sent in the order defined in [](#psk-protocol). A peer
which receives a handshake message in an unexpected order MUST abort the
handshake with an "unexpected_message" alert.

The `KEMEncapsulation` message is defined as follows:

~~~
struct {
    opaque certificate_request_context<0..2^8-1>
    opaque encapsulation<0..2^16-1>;
} KEMEncapsulation;
~~~

The encapsulation field is the result of a `Encapsulate()` function. The
``Encapsulate()`` function will also result in a shared secret (`ssS` or `ssC`,
depending on the peer) which is used to derive the `AHS` or `MS` secrets.

If the `KEMEncapsulation` message is sent by a server, the authentication
algorithm MUST be one offered in the client's `signature_algorithms` extension
unless no valid certificate chain can be produced without unsupported
algorithms.

If sent by a client, the authentication algorithm used in the signature MUST be
one of those present in the `supported_signature_algorithms` field of the
`signature_algorithms` extension in the `CertificateRequest` message.

In addition, the authentication algorithm MUST be compatible with the key(s) in
the sender's end-entity certificate.

The receiver of a `KEMEncapsulation` message MUST perform the `Decapsulate()`
operation by using the sent encapsulation and the private key of the public key
advertised in the end-entity certificate sent. The `Decapsulate()` function will
also result on a shared secret (`ssS` or `ssC`, depending on the Server or
Client executing it respectively) which is used to derive the `AHS` or `MS`
secrets.

`certificate_request_context` is included to allow the recipient to identify the
certificate against which the encapsulation was generated. It MUST be set to the
value in the `Certificate` message to which the encapsulation was computed.

## Cryptographic computations

The AuthKEM handshake establishes three input secrets which are combined to
create the actual working keying material, as detailed below. The key derivation
process incorporates both the input secrets and the handshake transcript.  Note
that because the handshake transcript includes the random values from the Hello
messages, any given handshake will have different traffic secrets, even if the
same input secrets are used.

### AuthKEM-PSK key schedule

The AuthKEM-PSK handshake follows the {{!RFC8446}} key schedule closely. We
change the computation of the ``EarlySecret`` as follows, and add a computation
for ``client_early_handshake_traffic_secret``:

~~~
            0
            |
            v
    SSs -> HKDF-Extract = Early Secret
            |
            ...
            +--> Derive-Secret(., "c e traffic", ClientHello)
            |                  = client_early_traffic_secret
            |
            +--> Derive-Secret(., "c e hs traffic", ClientHello)
            |                  = client_early_handshake_traffic_secret
            ...
            |
            v
            Derive-Secret(., "derived", "") = dES
            ...
~~~

We change the computation of ``Main Secret`` as follows:

~~~
            Derive-Secret(., "derived", "") = dHS
            |
            v
SSc||0 * -> HKDF-Extract = Main Secret
            |
            ...
~~~

`SSc` is included if client authentication is used; otherwise, the value `0` is
used.

### Computations of KEM shared secrets {#kem-computations}


As in {{?I-D.celi-wiggers-tls-authkem}}, operations to compute `SSs` or
`SSc` from the client are:

~~~
SSs, encapsulation <- Encapsulate(public_key_server,
                                  "server authentication")
               SSc <- Decapsulate(encapsulation, private_key_client,
                                  "client authentication")
~~~

The operations to compute `SSs` or `SSc` from the server are:

~~~
               SSs <- Decapsulate(encapsulation, private_key_server
                                  "server authentication")
SSc, encapsulation <- Encapsulate(public_key_client,
                                  "client authentication")
~~~

### Explicit Authentication Messages

AuthKEM upgrades implicit to explicit authentication through the `Finished`
message. With AuthKEM-PSK, the server achieves explicit authentication when
sending their ``Finished`` message and the client when they send their
``Finished`` message.

The key used to compute the ``Finished`` message MUST be computed from the
``MainSecret`` using HKDF. Specifically:

~~~
server/client_finished_key =
    HKDF-Expand-Label(MainSecret,
                      server/client_label,
                      "", Hash.length)
server_label = "tls13 server finished"
client_label = "tls13 client finished"
~~~

The ``verify_data`` value is computed as follows:

~~~
server/client_verify_data =
      HMAC(server/client_finished_key,
           Transcript-Hash(Handshake Context,
                           Certificate*,
                           KEMEncapsulation*,
                           Finished**)

*  Only included if present.
** The party who last sends the finished message in terms of flights
   includes the other party's Finished message.
~~~

These computations match {{?I-D.celi-wiggers-tls-authkem}}.

See [](#sec-authkem-pdk-negotiation) for special considerations for the
abbreviated AuthKEM handshake.

Any records following a Finished message MUST be encrypted under the appropriate
application traffic key as described in TLS 1.3. In particular, this includes
any alerts sent by the server in response to client ``Certificate`` and
``KEMEncapsulation`` messages.

# Security Considerations {#sec-considerations}

* Because the Main Secret is derived from both the ephemeral key exchange,
  as well as from the key exchanges completed for server and (optionally) client
  authentication, the MS secret always reflects the peers' views of the authentication
  status correctly. This is an improvement over TLS 1.3 for client authentication.

* The academic works proposing AuthKEM (KEMTLS) contains an in-depth technical
  discussion of and a proof of the security of the handshake protocol without
  client authentication ([SSW20], [Wig24]).

* The work proposing the variant protocol ([SSW21], [Wig24]) with pre-distributed public
  keys (the abbreviated AuthKEM handshake) has a proof for both unilaterally and
  mutually authenticated handshakes.

* We have machine-verified proofs of the security of KEMTLS and KEMTLS-PDK in
  Tamarin. [CHSW22]

* When the client opportunistically sends its certificate, it is not encrypted
  under a forward-secure key.  This has similar considerations and trade-offs as
  0-RTT data.  If it is a replayed message, there are no expected consequences
  for security as the malicious replayer will not be able to decapsulate the
  shared secret.

* A client that opportunistically sends its certificate, SHOULD send it
  encrypted with a ciphertext that it knows the server will accept. Otherwise,
  it will fail.

* If AuthKEM-PSK client authentication is used, the resulting shared secret is
  included in the key schedule. This ensures that both peers have a consistent
  view of the authentication status, unlike {{!RFC8446}}.

## Server Anonymity

The PDK extension identifies the public key to which the client has encapsulated
via a hash. This reveals some information about which server identity the client
has. {{?I-D.ietf-tls-esni}} may help alleviate this.

An alternative approach could be the use of trial decryption. If the KEM used
has anonymity, the ciphertext that the client sends is not linkable to the
server public key. ML-KEM offers post-quantum anonymity [MX22].


--- back

# Open points of discussion

The following are open points for discussion. The corresponding GitHub issues
will be linked.

## Alternative implementation based on the `pre_shared_key` extension {#psk-variant}

**This is discussed in [Issue
#25](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/25).**

{{!RFC8446}} defines a PSK handshake that can be used with symmetric keys from
e.g. session tickets. In this section, we sketch an alternative approach to
AuthKEM-PSK based on the `pre_shared_key` extension.

A client needs to be set up with the following information:

~~~
struct {
    uint32 authkem_psk_config_version;
    uint32 config_lifetime;
    opaque KEMPublicKey;
} AuthKEMPSKConfig;
~~~

The client computes a KEM ciphertext and shared secret as follows:

~~~
SSs, encapsulation <- Encapsulate(public_key_server,
                                  "server authentication")
~~~

`SSs` is used in place of `PSK` in the TLS 1.3 key schedule, and `binder_key` is
derived as follows:

~~~
          0
          |
          v
SSc ->  HKDF-Extract = Early Secret
          |
          +-----> Derive-Secret(., "ext binder" | "res binder", "")
          |                     = binder_key
          ...
~~~


In the `pre_shared_key` extension's `identities`, the client sends the following
data:

~~~
struct {
  uint32 authkem_psk_config_version;
  opaque KEMCiphertext;
} AuthKEMPSKIdentity
~~~

The server computes the shared secret `SSs` from
`AuthKEMPSKIdentity.KEMCiphertext` as follows:

~~~
SSs <- Decapsulate(encapsulation,
                   private_key_server
                   "server authentication")
~~~

The PSK binder value is computed as specified in {{!RFC8446}}, section 4.2.11.2.
The server MUST verify the binder before continuing and abort the handshake if
verification fails.

**To be determined: how to handle immediate client authentication.**

## Interactions with DTLS

It is currently open if there need to be made modifications to better support
integration with DTLS. Discussion is at [Issue
#23](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/23).

## Interaction with signing certificates

Tracked by [Issue
#20](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/20).

In the current state of the draft, we have not yet discussed combining
traditional signature-based authentication with KEM-based authentication. One
might imagine that the Client has a signing certificate and the server has a KEM
public key.

In the current draft, clients MUST use a KEM certificate algorithm if the server
negotiated AuthKEM.

# Acknowledgements
{: numbered="no"}

This work has been supported by the European Research Council through Starting
Grant No. 805031 (EPOQUE).

Part of this work was supported by the NLNet NGI Assure theme fund project
["Standardizing KEMTLS"](https://nlnet.nl/project/KEMTLS/)
