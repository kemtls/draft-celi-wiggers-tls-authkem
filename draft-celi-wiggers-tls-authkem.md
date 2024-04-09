---
title: KEM-based Authentication for TLS 1.3
abbrev: AuthKEM
docname: draft-celi-wiggers-tls-authkem-latest
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
  RFC5869:
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
  Wig24:
    title: "Post-Quantum TLS"
    date: 2024-01-09
    author:
      - ins: T. Wiggers
        name: Thom Wiggers
        org: Radboud University
    seriesinfo:
      "PhD thesis": "https://thomwiggers.nl/publication/thesis/"
  NISTPQC:
    title: Post-Quantum Cryptography Standardization
    date: 2020
    author:
      - ins: NIST
        org: National Institute for Standards and Technology
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
  K22:
    title: Polynomial Multiplication for Post-Quantum Cryptography
    author:
      - ins: M. J. Kannwischer
        name: Matthias J. Kannwischer
        org: Radboud University
    target: https://kannwischer.eu/thesis/
    date: 2022-04-22
    seriesinfo:
      "Ph.D.": thesis
  KYBER:
    target: https://pq-crystals.org/kyber/
    title: CRYSTALS-Kyber
    author:
      - ins: R. Avanzi
      - ins: J. Bos
      - ins: L. Ducas
      - ins: E. Kiltz
      - ins: T. Lepoint
      - ins: V. Lyubashevsky
      - ins: J. Schanck
      - ins: P. Schwabe
      - ins: G. Seiler
      - ins: D. Stehlé
    date: 2021
  DILITHIUM:
    target: https://pq-crystals.org/dilithium/
    title: CRYSTALS-Dilithium
    author:
      - ins: L. Ducas
      - ins: E. Kiltz
      - ins: T. Lepoint
      - ins: V. Lyubashevsky
      - ins: P. Schwabe
      - ins: G. Seiler
      - ins: D. Stehlé
    date: 2021
  FALCON:
    target: https://falcon-sign.info
    title: Falcon
    author:
      - ins: P.-A. Fouque
      - ins: J. Hoffstein
      - ins: P. Kirchner
      - ins: V. Lyubashevsky
      - ins: T. Pornin
      - ins: T. Ricosset
      - ins: G. Seiler
      - ins: W. Whyte
      - ins: Z. Zhang
    date: 2021

--- abstract

This document gives a construction for a Key Encapsulation Mechanism (KEM)-based
authentication mechanism in TLS 1.3. This proposal authenticates peers via a key
exchange protocol, using their long-term (KEM) public keys.

--- middle

# Introduction

**Note:** This is a work-in-progress draft. We welcome discussion, feedback and
contributions through the IETF TLS working group mailing list or directly on
GitHub.

This document gives a construction for KEM-based authentication in TLS 1.3
{{!RFC8446}}. Authentication happens via asymmetric cryptography by the usage of
KEMs advertised as the long-term KEM public keys in the Certificate.

TLS 1.3 is in essence a signed key exchange protocol (if using certificate-based
authentication). Authentication in TLS 1.3 is achieved by signing the handshake
transcript with digital signatures algorithms. KEM-based authentication provides
authentication by deriving a shared secret that is encapsulated against the
public key contained in the Certificate. Only the holder of the private key
corresponding to the certificate's public key can derive the same shared secret
and thus decrypt its peer's messages.

This approach is appropriate for endpoints that have KEM public keys. Though
this is currently rare, certificates can be issued with (EC)DH public keys as
specified for instance in {{?RFC8410}}, or using a delegation mechanism, such as
delegated credentials {{?I-D.ietf-tls-subcerts}}.

In this proposal, we build on {{!RFC9180}}. This standard currently only covers
Diffie-Hellman based KEMs, but the first post-quantum algorithms have already
been put forward {{?I-D.draft-westerbaan-cfrg-hpke-xyber768d00}}. This proposal
uses Kyber [KYBER] {{?I-D.draft-cfrg-schwabe-kyber}}, the first selected
algorithm for key exchange in the NIST post-quantum standardization project
[NISTPQC].

## Using key exchange instead of signatures for authentication

The elliptic-curve and finite-field-based key exchange and signature algorithms
that are currently widely used are very similar in sizes for public keys,
ciphertexts and signatures. As an example, RSA signatures are famously "just"
RSA encryption backwards.

This changes in the post-quantum setting. Post-quantum key exchange and
signature algorithms have significant differences in implementation, performance
characteristics, and key and signature sizes.

This also leads to increases in code size: For example, implementing highly
efficient polynomial multiplication for post-quantum KEM Kyber and signature
scheme Dilithium [DILITHIUM] requires significantly different approaches, even
though the algorithms are related [K22].

Using the protocol proposed in this draft allows to reduce the amount of data
exchanged for handshake authentication. It also allows to re-use the
implementation that is used for ephemeral key exchange for authentication, as
KEM operations replace signing. This decreases the code size requirements, which
is especially relevant to protected implementations. Finally, KEM operations may
be more efficient than signing, which might especially affect embedded
platforms.

## Evaluation of handshake sizes
**Should probably be removed before publishing**

In the following table, we compare the sizes of TLS 1.3- and AuthKEM-based
handshakes. We give the transmission requirements for handshake authentication
(public key + signature), and certificate chain (intermediate CA certificate
public key and signature + root CA signature). For clarity, we are not listing
post-quantum/traditional hybrid algorithms; we also omit mechanisms such as
Certificate Transparency {{?RFC6962}} or OCSP stapling {{?RFC6960}}. We use
Kyber-768 instead of the smaller Kyber-512 parameter set, as the former is
currently used in experimental deployments. For signatures, we use Dilithium,
the "primary" algorithm selected by NIST for post-quantum signatures, as well as
Falcon [FALCON], the algorithm that offers smaller public key and signature sizes, but
which NIST indicates can be used if the implementation requirements can be met.

| Handshake | HS auth algorithm | HS Auth bytes | Certificate chain bytes | Sum  |
| TLS 1.3   | RSA-2048          | 528           | 784  (RSA-2048)         | 1312 |
| TLS 1.3   | Dilithium-2       | 3732          | 6152 (Dilithium-2)      | 9884 |
| TLS 1.3   | Falcon-512        | 1563          | 2229 (Falcon-512)       | 3792 |
| TLS 1.3   | Dilithium-2       | 3732          | 2229 (Falcon-512)       | 5961 |
| AuthKEM   | Kyber-768         | 2272          | 6152 (Dilithium-2)      | 8424 |
| AuthKEM   | Kyber-768         | 2272          | 2229 (Falcon-512)       | 4564 |
{: title="Size comparison of public-key cryptography in TLS 1.3 and AuthKEM handshakes." }

Note that although TLS 1.3 with Falcon-512 is the smallest instantiation,
Falcon is very challenging to implement: signature generation requires (emulation of)
64-bit floating point operations in constant time. It is also very difficult to
protect against other side-channel attacks, as there are no known methods of
masking Falcon. In light of these difficulties, use of Falcon-512 in online
handshake signatures may not be wise.

Using AuthKEM with Falcon-512 in the certificate chain remains an attractive
option, however: the certificate issuance process, because it is mostly offline,
could perhaps be set up in a way to protect the Falcon implementation against
attacks. Falcon signature verification is fast and does not require floating-point
arithmetic. Avoiding online usage of Falcon in TLS 1.3 requires two implementations
of the signature verification routines, i.e., Dilithium and Falcon, on top of
the key exchange algorithm.

In all examples, the size of the certificate chain still dominates the TLS
handshake, especially if Certificate Transparency SCT statements are included,
which is relevant in the context of the WebPKI. However, we believe that if
proposals to reduce transmission sizes of the certificate chain in the WebPKI
context are implemented, the space savings of AuthKEM naturally become
relatively larger and more significant. We discuss this in
[](#cert-compression).

## Related work

### OPTLS
This proposal draws inspiration from {{?I-D.ietf-tls-semistatic-dh}}, which is
in turn based on the OPTLS proposal for TLS 1.3 [KW16]. However, these proposals
require a non-interactive key exchange: they combine the client's public key
with the server's long-term key. This imposes an extra requirement: the
ephemeral and static keys MUST use the same algorithm, which this proposal does
not require. Additionally, there are no post-quantum proposals for a
non-interactive key exchange currently considered for standardization, while
several KEMs are on the way.

### Compressing certificates and certificate chains {#cert-compression}

AuthKEM reduces the amount of data required for authentication in TLS. In
recognition of the large increase in handshake size that a naive adoption of
post-quantum signatures would affect, several proposals have been put forward
that aim to reduce the size of certificates in the TLS handshake. {{?RFC8879}}
proposes a certificate compression mechanism based on compression algorithms,
but this is not very helpful to reduce the size of high-entropy public keys and
signatures. Proposals that offer more significant reductions of sizes of
certificate chains, such as {{?I-D.draft-jackson-tls-cert-abridge}},
{{?I-D.ietf-tls-ctls}}, {{?I-D.draft-kampanakis-tls-scas-latest}}, and
{{?I-D.draft-davidben-tls-merkle-tree-certs}} all mainly rely on some form of
out-of-band distribution of intermediate certificates or other trust anchors in
a way that requires a robust update mechanism. This makes these proposals mainly
suitable for the WebPKI setting; although this is also the setting that has the
largest number of certificates due to the inclusion of SCT statements
{{?RFC6962}} and OSCP staples {{?RFC6960}}.

AuthKEM complements these approaches in the WebPKI setting. On its own the gains
that AuthKEM offers may be modest compared to the large sizes of certificate
chains. But when combined with compression or certificate suppression mechanisms
such as those proposed in the referenced drafts, the reduction in handshake size
when replacing Dilithium-2 by Kyber-768 becomes significant again.

## Organization

After a brief introduction to KEMs, we will introduce the AuthKEM authentication
mechanism. For clarity, we discuss unilateral and mutual authentication
separately. In the remainder of the draft, we will discuss the necessary
implementation mechanics, such as code points, extensions, new protocol messages
and the new key schedule. The draft concludes with ah extensive discussion of
relevant security considerations.

A related mechanism for KEM-based PSK-style handshakes is discussed in
{{?I-D.draft-wiggers-tls-authkem-psk}}.

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

A Key Encapsulation Mechanism (KEM) is a cryptographic primitive that defines
the methods ``Encapsulate`` and ``Decapsulate``. In this draft, we extend these
operations with context separation strings, per HPKE {{!RFC9180}}:

{:vspace}
``Encapsulate(pkR, context_string)``:
: Takes a public key, and produces a shared secret and encapsulation.

{:vspace}
``Decapsulate(enc, skR, context_string)``:
: Takes the encapsulation and the private key. Returns the shared secret.

We implement these methods through the KEMs defined in {{!RFC9180}} to export
shared secrets appropriate for using with the HKDF in TLS 1.3:

~~~
def Encapsulate(pk, context_string):
  enc, ctx = HPKE.SetupBaseS(pk, "tls13 auth-kem " + context_string)
  ss = ctx.Export("", HKDF.Length)
  return (enc, ss)

def Decapsulate(enc, sk, context_string):
  return HPKE.SetupBaseR(enc,
                         sk,
                         "tls13 auth-kem " + context_string)
             .Export("", HKDF.Length)
~~~

Keys are generated and encoded for transmission following the conventions in
{{!RFC9180}}. The values of `context_string` are defined in
[](#kem-computations).

# Full 1.5-RTT AuthKEM Handshake Protocol

Figure 1 below shows the basic KEM-authentication (AuthKEM) handshake, without
client authentication:

~~~~~
       Client                                     Server

Key  ^ ClientHello
Exch | + key_share
     v + signature_algorithms
                          -------->
                                             ServerHello  ^ Key
                                             + key_share  v Exch
                                   <EncryptedExtensions>
                                           <Certificate>  ^
       <KEMEncapsulation>  -------->                      |
       {Finished}          -------->                      | Auth
       [Application Data]  -------->                      |
                           <--------          {Finished}  v

       [Application Data]  <------->  [Application Data]

        +  Indicates noteworthy extensions sent in the
           previously noted message.
        <> Indicates messages protected using keys
           derived from a [sender]_handshake_traffic_secret.
        {} Indicates messages protected using keys
           derived from a
           [sender]_authenticated_handshake_traffic_secret.
        [] Indicates messages protected using keys
           derived from [sender]_application_traffic_secret_N.

       Figure 1: Message Flow for KEM-Authentication (KEM-Auth)
                 Handshake without client authentication.
~~~~~

This basic handshake captures the core of AuthKEM. Instead of using a signature
to authenticate the handshake, the client encapsulates a shared secret to the
server's certificate public key. Only the server that holds the private key
corresponding to the certificate public key can derive the same shared secret.
This shared secret is mixed into the handshake's key schedule. The client does
not have to wait for the server's ``Finished`` message before it can send data.
The client knows that its message can only be decrypted if the server was able
to derive the authentication shared secret encapsulated in the
``KEMEncapsulation`` message.

``Finished`` messages are sent as in TLS 1.3, and achieve full explicit
authentication.

## Client authentication

For client authentication, the server sends the ``CertificateRequest`` message
as in {{!RFC8446}}. This message can not be authenticated in the AuthKEM
handshake: we will discuss the implications below.

As in {{!RFC8446}}, section 4.4.2, if and only if the client receives
``CertificateRequest``, it MUST send a ``Certificate`` message. If the client
has no suitable certificate, it MUST send a ``Certificate`` message containing
no certificates. If the server is satisfied with the provided certificate, it
MUST send back a ``KEMEncapsulation`` message, containing the encapsulation to
the client's certificate. The resulting shared secret is mixed into the key
schedule. This ensures any messages sent using keys derived from it are covered
by the authentication.

The AuthKEM handshake with client authentication is given in Figure 2.

~~~~~
       Client                                     Server

Key  ^ ClientHello
Exch | + key_share
     v + signature_algorithms
                          -------->
                                             ServerHello  ^ Key
                                             + key_share  v Exch
                                   <EncryptedExtensions>  ^ Server
                                    <CertificateRequest>  v Params
                                           <Certificate>  ^
     ^ <KEMEncapsulation>                                 |
     | {Certificate}       -------->                      |
Auth |                     <--------  {KEMEncapsulation}  | Auth
     v {Finished}          -------->                      |
       [Application Data]  -------->                      |
                           <-------           {Finished}  v

       [Application Data]  <------->  [Application Data]

        +  Indicates noteworthy extensions sent in the
           previously noted message.
        <> Indicates messages protected using keys
           derived from a [sender]_handshake_traffic_secret.
        {} Indicates messages protected using keys
           derived from a
           [sender]_authenticated_handshake_traffic_secret.
        [] Indicates messages protected using keys
           derived from [sender]_application_traffic_secret_N.

       Figure 2: Message Flow for KEM-Authentication (KEM-Auth)
                 Handshake with client authentication.
~~~~~

If the server is not satisfied with the client's certificates, it MAY, at its
discretion, decide to continue or terminate the handshake. If it decides to
continue, it MUST NOT send back a ``KEMEncapsulation`` message and the client
and server MUST compute the encryption keys as in the server-only authenticated
AuthKEM handshake. The `Certificate` remains included in the transcript. The
client MUST NOT assume it has been authenticated.

Unfortunately, AuthKEM client authentication requires an extra round-trip.
Clients that know the server's long-term public KEM key MAY choose to use the
abbreviated AuthKEM handshake and opportunistically send the client certificate
as a 0-RTT-like message. This mechanism is discussed in
{{?I-D.draft-wiggers-tls-authkem-psk}}.

## Relevant handshake messages

After the Key Exchange and Server Parameters phase of TLS 1.3 handshake, the
client and server exchange implicitly authenticated messages. KEM-based
authentication uses the same set of messages every time that certificate-based
authentication is needed.  Specifically:

* ``Certificate``:  The certificate of the endpoint and any per-certificate
  extensions.  This message MUST be omitted by the client if the server did not
  send a `CertificateRequest` message (thus indicating that the client should
  not authenticate with a certificate). For AuthKEM, `Certificate` MUST include
  the long-term KEM public key. Certificates MUST be handled in accordance with
  {{!RFC8446}}, section 4.4.2.4.

* ``KEMEncapsulation``: A key encapsulation against the certificate's long-term
  public key, which yields an implicitly authenticated shared secret.

## Overview of key differences with RFC8446 TLS 1.3

* New types of ``signature_algorithms`` for KEMs.
* Public keys in certificates are KEM algorithms.
* New handshake message ``KEMEncapsulation``.
* The key schedule mixes in the shared secrets from the authentication.
* The ``Certificate`` is sent encrypted with a new handshake encryption key.
* The client sends ``Finished`` before the server.
* The client sends data before the server has sent ``Finished``.

## Implicit and explicit authentication

The data that the client MAY transmit to the server before having received the
server's ``Finished`` is encrypted using ciphersuites chosen based on the
client's and server's advertised preferences in the ``ClientHello`` and
``ServerHello`` messages. The ``ServerHello`` message can however not be
authenticated before the ``Finished`` message from the server is verified. The
full implications of this are discussed in the Security Considerations section.

Upon receiving the client's authentication messages, the server responds with
its ``Finished`` message, which achieves explicit authentication. Upon receiving
the server's ``Finished`` message, the client achieves explicit authentication.
Receiving this message retroactively confirms the server's cryptographic
parameter choices.

## Authenticating ``CertificateRequest``

The ``CertificateRequest`` message can not be authenticated during the AuthKEM
handshake; only after the ``Finished`` message from the server has been
processed, it can be proven as authentic. The security implications of this are
discussed later.

**This is discussed in [GitHub issue
#16](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/16). We
would welcome feedback there.**

Clients MAY choose to only accept post-handshake authentication.

**TODO: Should they indicate this? TLS Flag?**

# Implementation

In this section we will discuss the implementation details such as extensions
and key schedule.

## Negotiation of AuthKEM

Clients will indicate support for this mode by negotiating it as if it were a
signature scheme (part of the `signature_algorithms` extension). We thus add
these new signature scheme values (even though, they are not signature schemes)
for the KEMs defined in {{!RFC9180}} Section 7.1. Note that we will be only
using their internal KEM's API defined there.

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

**Please give feedback on which KEMs should be included**

When present in the `signature_algorithms` extension, these values indicate
AuthKEM support with the specified key exchange mode. These values MUST NOT
appear in `signature_algorithms_cert`, as this extension specifies the signing
algorithms by which certificates are signed.

## Protocol messages

The handshake protocol is used to negotiate the security parameters of a
connection, as in TLS 1.3. It uses the same messages, expect for the addition of
a `KEMEncapsulation` message and does not use the `CertificateVerify` one.

~~~
enum {
    ...
    kem_encapsulation(30),
    ...
    (255)
  } HandshakeType;

struct {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* remaining bytes in message */
    select (Handshake.msg_type) {
        ...
        case kem_encapsulation:     KEMEncapsulation;
        ...
    };
} Handshake;
~~~

Protocol messages MUST be sent in the order defined in Section 4. A peer which
receives a handshake message in an unexpected order MUST abort the handshake
with a "`unexpected_message`" alert.

The `KEMEncapsulation` message is defined as follows:

~~~
struct {
    opaque certificate_request_context<0..2^8-1>
    opaque encapsulation<0..2^16-1>;
} KEMEncapsulation;
~~~

The encapsulation field is the result of a `Encapsulate` function. The
``Encapsulate()`` function will also result in a shared secret (`ssS` or `ssC`,
depending on the peer) which is used to derive the `AHS` or `MS` secrets (See
[](#key-schedule)).

If the `KEMEncapsulation` message is sent by a server, the authentication
algorithm MUST be one offered in the client's `signature_algorithms` extension.
Otherwise, the server MUST terminate the handshake with an
"`unsupported_certificate`" alert.

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

### Key schedule for full AuthKEM handshakes {#key-schedule}

AuthKEM uses the same `HKDF-Extract` and `HKDF-Expand` functions as defined by
TLS 1.3, in turn defined by {{RFC5869}}.

Keys are derived from two input secrets using the `HKDF-Extract` and
`Derive-Secret` functions.  The general pattern for adding a new secret is to
use `HKDF-Extract` with the Salt being the current secret state and the Input
Keying Material (IKM) being the new secret to be added.

The notable differences are:

* The addition of the ``Authenticated Handshake Secret`` and a new set of
  handshake traffic encryption keys.
* The inclusion of the ``SSs`` and ``SSc`` (if present) shared secrets as IKM to
  ``Authenticated Handshake Secret`` and ``Main Secret``, respectively.

The full key schedule proceeds as follows:

~~~
            0
            |
            v
    PSK -> HKDF-Extract = Early Secret
            |
            +--> Derive-Secret(., "ext binder" | "res binder", "")
            |                  = binder_key
            |
            +--> Derive-Secret(., "c e traffic", ClientHello)
            |                  = client_early_traffic_secret
            |
            +--> Derive-Secret(., "e exp master", ClientHello)
            |                  = early_exporter_master_secret
            v
            Derive-Secret(., "derived", "")
            |
            v
(EC)DHE -> HKDF-Extract = Handshake Secret
            |
            +--> Derive-Secret(., "c hs traffic",
            |                  ClientHello...ServerHello)
            |                  = client_handshake_traffic_secret
            |
            +--> Derive-Secret(., "s hs traffic",
            |                  ClientHello...ServerHello)
            |                  = server_handshake_traffic_secret
            v
            Derive-Secret(., "derived", "") = dHS
            |
            v
    SSs -> HKDF-Extract = Authenticated Handshake Secret
            |
            +--> Derive-Secret(., "c ahs traffic",
            |                  ClientHello...KEMEncapsulation)
            |         = client_handshake_authenticated_traffic_secret
            |
            +--> Derive-Secret(., "s ahs traffic",
            |                  ClientHello...KEMEncapsulation)
            |         = server_handshake_authenticated_traffic_secret
            v
            Derive-Secret(., "derived", "") = dAHS
            |
            v
SSc||0 * -> HKDF-Extract = Main Secret
            |
            +--> Derive-Secret(., "c ap traffic",
            |                  ClientHello...client Finished)
            |                  = client_application_traffic_secret_0
            |
            +--> Derive-Secret(., "s ap traffic",
            |                  ClientHello...server Finished)
            |                  = server_application_traffic_secret_0
            |
            +--> Derive-Secret(., "exp master",
            |                  ClientHello...server Finished)
            |                  = exporter_master_secret
            |
            +--> Derive-Secret(., "res master",
                               ClientHello...server Finished)
                               = resumption_master_secret

*: if client authentication was requested, the `SSc` value should
   be used. Otherwise, the `0` value is used.
~~~

### Computations of KEM shared secrets {#kem-computations}


The operations to compute `SSs` or `SSc` from the client are:

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
message. Note that in the full handshake, AuthKEM achieves explicit
authentication only when the server sends the final ``Finished`` message (the
client is only implicitly authenticated when they send their ``Finished``
message).

Full downgrade resilience and forward secrecy is achieved once the AuthKEM
handshake completes.

The key used to compute the ``Finished`` message MUST be computed from the
``MainSecret`` using HKDF (instead of a key derived from HS as in {{!RFC8446}}).
Specifically:

~~~
server/client_finished_key =
  HKDF-Expand-Label(MainSecret,
                    server/client_label,
                    "", Hash.length)
server_label = "tls13 server finished"
client_label = "tls13 client finished"
~~~

The ``verify_data`` value is computed as follows. Note that instead of what is
specified in {{!RFC8446}}, we use the full transcript for both server and client
Finished messages:

~~~
server/client_verify_data =
      HMAC(server/client_finished_key,
           Transcript-Hash(Handshake Context,
                           Certificate*,
                           KEMEncapsulation*,
                           Finished**))

*  Only included if present.
** The party who last sends the finished message in terms of flights
   includes the other party's Finished message.
~~~

Any records following a `Finished` message MUST be encrypted under the
appropriate application traffic key as described in {{!RFC8446}}. In particular,
this includes any alerts sent by the server in response to client
``Certificate`` and ``KEMEncapsulation`` messages.

See [SSW20] for a full treatment of implicit and explicit authentication.

# Security Considerations {#sec-considerations}

## Implicit authentication

Because preserving a 1/1.5RTT handshake in KEM-Auth requires the client to send
its request in the same flight when the `ServerHello` message is received, it
can not yet have explicitly authenticated the server. However, through the
inclusion of the key encapsulated to the server's long-term secret, only an
authentic server should be able to decrypt these messages.

However, the client can not have received confirmation that the server's choices
for symmetric encryption, as specified in the `ServerHello` message, were
authentic. These are not authenticated until the `Finished` message from the
server arrived. This may allow an adversary to downgrade the symmetric
algorithms, but only to what the client is willing to accept. If such an attack
occurs, the handshake will also never successfully complete and no data can be
sent back.

If the client trusts the symmetric algorithms advertised in its `ClientHello`
message, this should not be a concern. A client MUST NOT accept any
cryptographic parameters it does not include in its own `ClientHello` message.

If client authentication is used, explicit authentication is reached before any
application data, on either client or server side, is transmitted.

Application Data MUST NOT be sent prior to sending the Finished message, except
as specified in Section 2.3 of {{!RFC8446}}.  Note that while the client MAY
send Application Data prior to receiving the server's last explicit
Authentication message, any data sent at that point is, being sent to an
implicitly authenticated peer.

## Authentication of Certificate Request

Due to the implicit authentication of the server's messages during the full
AuthKEM handshake, the ``CertificateRequest`` message can not be authenticated
before the client received ``Finished``.

The key schedule guarantees that the server can not read the client's
certificate message (as discussed above). An active adversary that maliciously
inserts a ``CertificateRequest`` message will also result in a mismatch in
transcript hashes, which will cause the handshake to fail.

However, there may be side effects. The adversary might learn that the client
has a certificate by observing the length of the messages sent. There may also
be side effects, especially in situations where the client is prompted to e.g.
approve use or unlock a certificate stored encrypted or on a smart card.

## Other security considerations

* Because the Main Secret is derived from both the ephemeral key exchange,
  as well as from the key exchanges completed for server and (optionally) client
  authentication, the MS secret always reflects the peers' views of the authentication
  status correctly. This is an improvement over TLS 1.3 for client authentication.

* The academic works proposing AuthKEM (KEMTLS) contains an in-depth technical
  discussion of and a proof of the security of the handshake protocol without
  client authentication [SSW20] [Wig24].

* The work proposing the variant protocol [SSW21] [Wig24] with pre-distributed public
  keys (the abbreviated AuthKEM handshake) has a proof for both unilaterally and
  mutually authenticated handshakes.

* We have proofs of the security of KEMTLS and KEMTLS-PDK in Tamarin. [CHSW22]

* Application Data sent prior to receiving the server's last explicit
  authentication message (the Finished message) can be subject to a client
  certificate suite downgrade attack. Full downgrade resilience and forward
  secrecy is achieved once the handshake completes.

* The client's certificate is kept secret from active observers by the
  derivation of the `client_authenticated_handshake_secret`, which ensures that
  only the intended server can read the client's identity.

* If AuthKEM client authentication is used, the resulting shared secret is
  included in the key schedule. This ensures that both peers have a consistent
  view of the authentication status, unlike {{!RFC8446}}.


--- back


# Open points of discussion

The following are open points for discussion. The corresponding Github issues
will be linked.

## Authentication concerns for client authentication requests.

Tracked by [Issue
#16](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/16).

The certificate request message from the server can not be authenticated by the
AuthKEM mechanism. This is already somewhat discussed above and under security
considerations. We might want to allow clients to refuse client auth for
scenarios where this is a concern.

## Interaction with signing certificates

Tracked by [Issue
#20](https://github.com/kemtls/draft-celi-wiggers-tls-authkem/issues/20).

In the current state of the draft, we have not yet discussed combining
traditional signature-based authentication with KEM-based authentication. One
might imagine that the Client has a sigining certificate and the server has a
KEM public key.

In the current draft, clients MUST use a KEM certificate algorithm if the server
negotiated AuthKEM.

# Acknowledgements
{: numbered="no"}

Early versions of this work were supported by the European Research Council through Starting
Grant No. 805031 (EPOQUE).
