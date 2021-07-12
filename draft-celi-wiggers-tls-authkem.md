---
title: KEMTLS
abbrev: KEMTLS
docname: draft-celi-wiggers-tls-authkem-latest
category: info

ipr: trust200902
area: General
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: S. Celi
    name: Sofía Celi
    org: Cloudflare
    email: cherenkov@riseup.net

 -
    ins: P. Schwabe
    name: Peter Schwabe
    org: "Radboud University and Max Planck Institute for Security and Privacy"
    email: peter@cryptojedi.org

 -
    ins: D. Stebila
    name: Douglas Stebila
    org: University of Waterloo
    email: dstebila@uwaterloo.ca

 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare
    email: nick@cloudflare.com

 -
    ins: T. Wiggers
    name: Thom Wiggers
    org: Radboud University
    email: thom@thomwiggers.nl

normative:
  RFC8446:

informative:
  KEMTLS:
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
      DOI: 10.1145/3372297.3423350
      "IACR ePrint": https://ia.cr/2020/534
  KEMTLSPDK:
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
  NISTPQC:
    title: Post-Quantum Cryptography Standardization
    date: 2020
    author:
      - ins: NIST
        org: National Institute for Standards and Technology


--- abstract

TODO

--- middle

# Introduction

DISCLAIMER: This is a work-in-progress draft.

This document gives a construction for KEM-based authentication in TLS
1.3.  The overall design approach is a simple: usage of Key Encapsulation
Mechanisms (KEM) for certificate-based authentication. Authentication happens via
asymmetric cryptography by the usage of KEMs by using the long-term KEM public
keys in the Certificate.

TLS 1.3 is in essence a signed key exchange protocol. Authentication
in TLS 1.3 is achieved by signing the handshake transcript. KEM-based
authentication provides authentication by deriving a shared secret that
is encapsulated against the public key contained in the certificate.
Only the holder of the private key corresponding to the certificate's
public key can derive the same shared secret and thus decrypt it's peers
messages.

In this proposal we will use the DH-based KEMs from  {{!I-D.irtf-cfrg-hpke}},
but KEMs are of interest to the TLS protocol because NIST is in the process of
standardizing post-quantum KEM algorithms to replace "classic" key exchange
based on elliptic curve or finite-field Diffie-Hellman [NISTPQC].

This proposal draws inspiration from {{!I-D.ietf-tls-semistatic-dh}} which is in
turn based on the OPTLS proposal for TLS 1.3 [KW16].  However, these proposals
requires non-interactive key exchange: they combine the client's public key with
the server's long-term key.  This does impose a requirement that the ephemeral and
static keys use the same algorithm, which this proposal does not require. Additionally,
there are no post-quantum proposals for non-interactive key exchange currently
considered for standardization, while several KEMs are on the way.

# Requirements Notation

{::boilerplate bcp14}

# Terminology

The following terms are used as they are in {{!RFC8446}}

client:  The endpoint initiating the TLS connection.

connection:  A transport-layer connection between two endpoints.

endpoint:  Either the client or server of the connection.

handshake:  An initial negotiation between client and server that
  establishes the parameters of their subsequent interactions
  within TLS.

peer:  An endpoint.  When discussing a particular endpoint, "peer"
  refers to the endpoint that is not the primary subject of
  discussion.

receiver:  An endpoint that is receiving records.

sender:  An endpoint that is transmitting records.

server:  The endpoint that this did initiate the TLS connection.
  i.e. the peer of the client.

## Key Encapsulation Mechanisms

As this proposal relies heavily on KEMs, which are not originally
used by TLS, we will provide a brief overview of this primitive.

A Key Encapsulation Mechanism (KEM), defined as in {{!I-D.irtf-cfrg-hpke}}
is a cryptographic primitive that defines the methods ``Encap`` and ``Decap``:

``Encaps(pkR)``:  Takes a public key, and produces a shared secret and
  encapsulation.

``Decap(enc, skR)``:  Takes the encapsulation and the private key. Returns
  the shared secret.


# Protocol Overview

Figure 1 below shows the basic full KEM-authentication handshake:

~~~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     v + (kem)signature_algorithms      -------->
                                                      ServerHello  ^ Key
                                                +       key_share  v Exch
                                            <EncryptedExtensions>  ^  Server
                                             <CertificateRequest>  v  Params
     ^                                              <Certificate>  ^
Auth | <KEMEncapsulation>                                          |  Auth
     | {Certificate}                -------->                      |
     |                              <--------  {KEMEncapsulation}  |
     | {Finished}                   -------->                      |
     | [Application Data*]          -------->                      |
     v                              <-------           {Finished}  |
                                                                   v
       [Application Data]           <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              <> Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              {} Indicates messages protected using keys
                 derived from a [sender]_authenticated_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

             Figure 1: Message Flow for KEM-Authentication Handshake
~~~~~

When using KEMs for authentication, the handshake can be thought of in four
phases compared to the three ones from TLS 1.3. It achieves both confidentiality
and authentication (certificate-based).

After the Key Exchange and Server Parameters phase of TLS 1.3 handshake, the
client and server exchange implicity authenticated messages.
KEM-based authentication uses the same set of messages every time that
certificate-based authentication is needed.  Specifically:

* Certificate:  The certificate of the endpoint and any per-certificate
  extensions.  This message is omitted by the client if the server
  did not send CertificateRequest (thus indicating that the client
  should not authenticate with a certificate). The Certificate
  should include a long-term KEM public key.

* KEMEncapsulation: A key encapsulation against the certificate's long-term
  public key, which yields an implicitly authenticated shared secret.

Upon receiving the server's messages, the client responds with its
Authentication messages, namely Certificate and KEMEncapsulation (if
requested).

Application Data MUST NOT be sent prior to sending the Finished
message, except as specified in Section 2.3.  Note that while the
client may send Application Data prior to receiving the server's
last Authentication message, any data sent at that point is, of course,
being sent to an implicitly authenticated peer. It is worth noting
that Application Data sent prior to receiving the server's last
Authentication message can be subject to a client downgrade
attack. Full downgrade resilience is only achieved when explicit
authentication is achieved: when the Client receives the Finished
message from the Server.

## Prior-knowledge KEMTLS

Given the added number of round-trips of KEM-based auth compared to the TLS 1.3,
the handshake can be improved by the usage of pre-distributed
KEM authentication keys to achieve explicit authentication and full downgrade
resilience as early as possible. A peer's long-term KEM authentication key can
be cached in advance, as well.

Figure 2 below shows a pair of handshakes in which the first handshake
establishes cached information and the second handshake uses it:

~~~~~
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
     v + (kem)signature_algorithms      -------->
                                                      ServerHello  ^ Key
                                                +  (kem)key_share  v Exch
                                            <EncryptedExtensions>  ^  Server
                                             <CertificateRequest>  v  Params
     ^                                              <Certificate>  ^
Auth | <KEMEncapsulation>                                          |  Auth
     | {Certificate}                -------->                      |
     |                           <--------     {KEMEncapsulation}  |
     | {Finished}                   -------->                      |
     | [Cached Server Certificate]
     | [Application Data*]          -------->                      |
     v                              <-------           {Finished}  |
                                      [Cached Client Certificate]  |
                                                                   v
       [Application Data]           <------->  [Application Data]

       Client                                           Server

Key  ^ ClientHello
Exch | + key_share
&    | + cached_info_extension
Auth | + kem_encapsulation_extension
     | + (kem)signature_algorithms
     | <Certificate>                -------->                      |
     |                                                ServerHello  ^ Key
     |                                          +       key_share  | Exch,
     |                                 +  {cached_info_extension}  | Auth &
     |                                      {EncryptedExtensions}  | Server
     |                                         {KEMEncapsulation}  | Params
     |                              <--------          {Finished}  v
     |                              <-------- [Application Data*]
     v {Finished}                   -------->

       [Application Data]           <------->  [Application Data]
~~~~~

In some applications, such as in a VPN, the client already knows that the
server will require mutual authentication. This means that a client can proactively
authenticate by sending its certificate as early in the handshake as possible.
The client's certificate have to be sent encrypted by using the shared secret
derived from the kem_encapsulation message.

# Handshake protocol

The handshake protocol is used to negotiate the security parameters
of a connection, as in TLS 1.3. It uses the same messages, expect
for the addition of a `KEMEncapsulation` message and does not use
the `CertificateVerify` one.

~~~
enum {
          ...
          encrypted_extensions(8),
          certificate(11),
          kem_ciphertext(tbd),
          certificate_request(13),
          ...
          message_hash(254),
          (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;    /* handshake type */
          uint24 length;             /* remaining bytes in message */
          select (Handshake.msg_type) {
              ...
              case encrypted_extensions:  EncryptedExtensions;
              case certificate_request:   CertificateRequest;
              case certificate:           Certificate;
              case kem_ciphertext:        KEMEncapsulation;
              ...
          };
      } Handshake;
~~~

Protocol messages MUST be sent in the order defined in Section 4.
A peer which receives a handshake message in an unexpected order MUST
abort the handshake with an "unexpected_message" alert.

## Key Exchange Messages

KEMTLS uses the same key exchange messages as TLS 1.3 with this
exceptions:

- Usage of a new message `KEMEncapsulation`.
- The `CertificateVerify` message is not used.
- Two extensions can be added to the `ClientHello` message: "cached_information"
  and "kem_ciphertext".
- One extensions can be added to the `ServerHello` message: "cached_information".

KEMTLS preserves the same cryptographic negotiation with the addition
of more algorithms to the "supported_groups" and "signature_algorithms".

### Client Hello

KEMTLS uses the `ClientHello` message as described for TLS 1.3. When used
in a pre-distributed mode, however, two extensions are mandatory: "cached_information"
and "kem_ciphertext" for server authentication. This extensions are
described later in the document.

Note that in KEMTLS with pre-distributed information, the client's `Certificate`
message gets send alongside the `ClientHello` one for mutual authentication.

### Server Hello

KEMTLS uses the `ServerHello` message as described for TLS 1.3. When used
in a pre-distributed mode, however, one extension is mandatory: "cached_information"
for server authentication. This extension is described later in the document.

When the ServerHello message is received:

- the client and server derive handshake traffic secrets `CHTS` and `SHTS` which are
  used to encrypt subsequent flows in the handshake
- it is derived the “derived handshake secret”: `dHS` which is kept as the
  current secret state of the key schedule.

### Hello Retry Request

KEMTLS uses the `ServerHello` message as described for TLS 1.3. When used
in a pre-distributed mode for mutual authentication, a `HelloRetryRequest`
message, but the client's `Certificate` message is ignored.

### Extensions

A number of KEMTLS messages contain tag-length-value encoded extensions
structures. We are adding those extensions to the `ExtensionType` list
from TLS 1.3.

~~~
enum {
    ...
    signature_algorithms_cert(50),              /* RFC 8446 */
    key_share(51),                              /* RFC 8446 */
    kem_ciphertext(TBD),                        /* RFC TBD */
    cached_info(TBD),                           /* RFC TBD */
    (65535)
} ExtensionType;
~~~

The table below indicates the messages where a given extension may
appear:

~~~
   +--------------------------------------------------+-------------+
   | Extension                                        |     KEM TLS |
   +--------------------------------------------------+-------------+
   | cached_info [RFCTBD]                             |      CH, SH |
   |                                                  |             |
   | kem_ciphertext [RFCTBD]                          |          CH |
   |                                                  |             |
   +--------------------------------------------------+-------------+
~~~

#### Signature Algorithms

This extension works the same was as with TLS 1.3; but certain algorithms
are added to the `SignatureScheme` list:

~~~
  enum {
      ...
      /* EdDSA algorithms */
      ed25519(0x0807),
      ed448(0x0808),

      /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
      rsa_pss_pss_sha256(0x0809),
      rsa_pss_pss_sha384(0x080a),
      rsa_pss_pss_sha512(0x080b),

      /* Post-quantum KEM authentication algorithms */
      kyber512(TBD),
      kyber768(TBD),
      kyber1024(TBD),
      ntru2048509(TBD),
      ntru2048677(TBD),
      ntru4096821(TBD),
      light_saber(TBD),
      saber(TBD),
      fira_saber(TBD),

      /* Post-quantum signature algorithms */
      dilithium2(TBD),
      dilithium3(TBD),
      dilithium5(TBD),
      falcon512(TBD),
      falcon1024(TBD),
      rainbowI(TBD),
      rainbowIII(TBD),
      rainbowV(TBD),

      /* Hybrid authentication algorithms */
      kyber512_secp256r1(TBD),
      ntru2048509_secp256r1(TBD),
      light_saber_secp256r1(TBD),

      kyber768_secp384r1(TBD),
      ntru2048677_secp384r1(TBD),
      saber_secp384r1(TBD),

      kyber1024_secp521r1(TBD),
      ntru4096821_secp521r1(TBD),
      fira_saber_secp521r1(TBD),

      kyber512_x25519(TBD),
      ntru2048509_x25519(TBD),
      light_saber_x25519(TBD),

      kyber768_x448(TBD),
      ntru2048677_x448(TBD),
      saber_x448(TBD),

      /* Legacy algorithms */
      rsa_pkcs1_sha1(0x0201),
      ecdsa_sha1(0x0203),

      /* Reserved Code Points */
      private_use(0xFE00..0xFFFF),
      (0xFFFF)
  } SignatureScheme;
~~~

The algorithms added here correspond to the round-3 finalists of the post-quantum
NIST competition. They are made available as follows:

- If the `KEM` has L1 security, NIST's P256 curve or ed25519 is used with it
- If `KEM` has L3 security, NIST's P384 curve or ed448 is used with it.
- If `KEM` has L5 security, NIST's P521 curve is used with it.

####  Supported Groups

This extension works the same was as with TLS 1.3; but certain algorithms
are added to the `NamedGroup` list:

~~~
  enum {

      /* Elliptic Curve Groups (ECDHE) */
      secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
      x25519(0x001D), x448(0x001E),

      /* Finite Field Groups (DHE) */
      ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
      ffdhe6144(0x0103), ffdhe8192(0x0104),

      /* Post-Quantum KEMs (PQKEM) */
      kyber512(TBD), kyber768(TBD), kyber1024(TBD),
      ntru2048509(TBD), ntru2048677(TBD), ntru4096821(TBD),
      light_saber(TBD), saber(TBD), fira_saber(TBD),

      /* Hybrid KEMs (HKEM) */
      kyber512_secp256r1(TBD), ntru2048509_secp256r1(TBD),
      light_saber_secp256r1(TBD),

      kyber768_secp384r1(TBD), ntru2048677_secp384r1(TBD),
      saber_secp384r1(TBD),

      kyber1024_secp521r1(TBD), ntru4096821_secp521r1(TBD),
      fira_saber_secp521r1(TBD),

      kyber512_x25519(TBD), ntru2048509_x25519(TBD),
      light_saber_x25519(TBD),

      kyber768_x448(TBD), ntru2048677_x448(TBD),
      saber_x448(TBD),

      /* Reserved Code Points */
      ecdhe_private_use(0xFE01..0xFEFF),
      (0xFFFF)
  } NamedGroup;
~~~

The algorithms added here correspond to the round-3 finalists of the post-quantum
NIST competition. ecurity, NIST's P521 curve is used with it.


Post-Quantum KEMs (PQKEM):  Indicates support for the
  corresponding named post-quantum KEM corresponding to the round-3 finalists of
  the post-quantum NIST competition. They correspond to a L1, L3 or L5
  security level.

Hybrid KEMs (HKEM): Indicates support for the
  corresponding named hybrid KEMs (a "classical" -ECDHE- and post-quantum algorithms).
  They are made available as follows:
  - If the `KEM` has L1 security, NIST's P256 curve or x25519 is used with it
  - If `KEM` has L3 security, NIST's P384 curve or x448 is used with it.
  - If `KEM` has L5 security, NIST's P512 curve.

#### Key Share

KEMTLS uses the same mechanism as TLS 1.3 for advertising the endpoint's
cryptographic parameters, with these changes:

~~~
  struct {
      NamedGroup group;
      HybridKeyExchange hybrid_key_exchanges;
  } KeyShareEntry;
~~~

The HybridKeyExchange sent as part of the ClientHello or HelloRetryMessage
corresponds to:

~~~
   struct {
       opaque key_exchange_1<1..2^16-1>; ----> the classical public key
       opaque key_exchange_2<1..2^16-1>; ----> the post-quantum public key
   } HybridKeyExchange
~~~

The HybridKeyExchange sent as part of the ServerHello:

~~~
   struct {
       opaque key_exchange_1<1..2^16-1>; ----> the classical public key
       opaque key_exchange_2<1..2^16-1>; ----> the KEM encapsulation
   } HybridKeyExchange
~~~

If a hybrid mode is not in use, only the post-quantum public key or
encapsulation is advertised.

##### Post-Quantum KEM Parameters

Post-Quantum KEM Parameters for both clients and servers are encoded in the
opaque key_exchange field of a KeyShareEntry in a
HybridKeyShare structure.  The opaque value contains either:

- the KEM public value
- the KEM encapsulation value

for the specified algorithm encoded as a big-endian integer and padded to
the left with zeros to the size of p in bytes.

Peers MUST validate each other's public key.

##### Hybrid KEM Parameters

Hybrid KEM parameters for both clients and servers are encoded in the
opaque key_exchange field of a KeyShareEntry in a HybridKeyShare structure.
The opaque value contains:

- the KEM public value or
- the KEM encapsulation value

and

- the ECDHE public value

#### Cached Information

This document defines a new extension type ("cached_info(TBD)"), which
is used in ClientHello and ServerHello messages.  The extension type
is specified as follows.

~~~
  enum {
       cached_info(TBD), (65535)
  } ExtensionType;
~~~

The extension_data field of this extension, when included in the
ClientHello, MUST contain the `CachedInformation` structure.  The
client MAY send multiple CachedObjects of the same `CachedInformationType`.
This may, for example, be the case when the client has cached multiple
certificates from the server.

~~~
  enum {
       cert(1) (255)
  } CachedInformationType;

  struct {
       select (type) {
         case client:
           CachedInformationType type;
           opaque hash_value<1..255>;
         case server:
           CachedInformationType type;
       } body;
  } CachedObject;

  struct {
       CachedObject cached_info<1..2^16-1>;
  } CachedInformation;
~~~

This document defines the following type:

- 'cert' type for not sending the complete server certificate message:
   With the type field set to 'cert', the client MUST include the
   fingerprint of the Certificate message in the hash_value field.
   For this type, the fingerprint MUST be calculated using the
   procedure below, using the Certificate message as the input data.

The fingerprint calculation proceeds this way:

1.  Compute the SHA-256 hash of the input data. Note that the computed
    hash only covers the input data structure (and not any type and
    length information of the record layer).
2.  Use the output of the SHA-256 hash.

The purpose of the fingerprint provided by the client is to help the
server select the correct information.  The fingerprint identifies the server
certificate (and the corresponding private key) for use with the rest
of the handshake.

If this extension is not present, the `kem_encapsulation` extension MUST
not be present as well. If present, it will be ignored.

### Implicit Authentication Messages

As discussed, KEMTLS generally uses a common set of messages for implicit
authentication and key confirmation: Certificate and KEMEncapsulation.

The computations for the Authentication messages take the following inputs:

-  The certificate and authentication key to be used.
-  A Handshake Context consisting of the set of messages to be included in the
   transcript hash.
-  A Shared Secret Key (from the PQ KEM operations) to be used to compute an
   authenticated handshake shared key.
-  A Handshake Context consisting of the set of messages to be
   included in the transcript hash.

Based on these inputs, the messages then contain:

Certificate:  The certificate to be used for authentication, and any supporting
  certificates in the chain.

KEMEncapsulation: The post-quantum KEM encapsulation (or a hybrid one) against the
  certificate's public key(s).

KEMTLS follows the TLS 1.3 key schedule, which applies a sequence of HKDF
operations to the Shared Secret Keys and the handshake context to derive:

- the client and server authenticated handshake traffic secrets
  `CAHTS` and `SAHTS` which are used to encrypt subsequent flows
  in the handshake
- updated secret state `dAHS` of the key schedule.
- a Master Key.

### Certificate

KEMTLS uses the same Certificate message as TLS 1.3 with these changes:

~~~
  enum {
      X509(0),
      RawHybridPublicKey(2),
      (255)
  } CertificateType;

  struct {
      select (certificate_type) {
          case RawHybridPublicKey:
            /* From RFC TBD */
            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>; ----> the classical KEM public key
            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>; ----> the post-quantum KEM public key

          case X509:
            opaque cert_data<1..2^24-1>;
      };
      Extension extensions<0..2^16-1>;
  } CertificateEntry;

  struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
  } Certificate;
~~~

In a hybrid mode, the end-entity Certificate or the RawHybridPublicKey MUST
contain both a classical KEM public key and a post-quantum one.
In a non-hybrid mode, the leaf Certificate or the RawHybridPublicKey MUST
contain a post-quantum KEM public key.

Note that we are only specifying here the algorithms in the end-entity
Certificate. A Certificate chain MUST advertise post-quantum algorithms
and sign in a quantum-safe way each entry in order to be considered fully
post-quantum safe.  All certificates provided by the server or client MUST be
signed by an authentication algorithm advertised by the server or client.

### KEM Encapsulation

This message is used to provide implicit proof that an endpoint
possesses the private key(s) corresponding to its certificate by sending
the appropriate parameters that will be used to calculate the implicity
authenticated shared secret.

The calculation of the shared secret also provides integrity for the handshake
up to this point. Servers MUST send this message when authenticating
via a certificate. Clients MUST send this message whenever
authenticating via a certificate (i.e., when the Certificate message
is non-empty). When sent, this message MUST appear immediately after
the Certificate message has been received and prior to the Finished message.

Structure of this message:

~~~
  struct {
      SignatureScheme algorithm;
      opaque encapsulation<0..2^16-1>;
  } KEMEncapsulation;
~~~

The algorithm field specifies the authentication algorithm used.  The
encapsulation field is the result of a Encapsulation() function. In the
hybrid mode, it is a concatenation of the two fields returned by the of
Encapsulation() functions:

~~~
  concatenated_encapsulation = encapsulation from (EC)-DH || encapsulation from PQ-KEM
~~~

If the KEMEncapsulation message is sent by a server, the authentication
algorithm MUST be one offered in the client's "signature_algorithms"
extension unless no valid certificate chain can be produced without
unsupported algorithms.

If sent by a client, the authentication algorithm used in the signature
MUST be one of those present in the supported_signature_algorithms
field of the "signature_algorithms" extension in the
CertificateRequest message.

In addition, the authentication algorithm MUST be compatible with the key(s)
in the sender's end-entity certificate.

The receiver of a KEMEncapsulation message MUST perform the Decapsulation()
operation by using the sent encapsulation (or the concatenated ones)  and the
private key(s) of the public key(s) advertised in the end-entity certificate sent.

### Explicit Authentication Messages

As discussed, KEMTLS generally uses a message for explicit
authentication: Finished message. Note that in the non pre-distributed mode,
KEMTLS achieves explicit authentication only when the server sends the final
`Finished` message (the client is only implicitly authenticated when they
send their `Finished` message). In a pre-distributed mode, the server achieves
explicit authentication when sending their `Finished` message (one round-trip
earlier) and the client, in turn, when they send their `Finished` message
(one round-trip earlier). Full downgrade resilience and forward secrecy
is achieved once the KEMTLS handshake completes.

The key used to compute the Finished message is computed from the
Master Key using HKDF. Specifically:

~~~
 finished_key =
     HKDF-Expand-Label(MasterKey, "finished", "", Hash.length)
~~~

Structure of this message:

~~~
  struct {
      opaque verify_data[Hash.length];
  } Finished;
~~~

The verify_data value is computed as follows:

~~~
  verify_data =
      HMAC(finished_key,
           Transcript-Hash(Handshake Context,
                           Certificate*, KEMEncapsulation*))
~~~

* Only included if present.

Any records following a Finished message MUST be encrypted under the
appropriate application traffic key as described in TLS 1.3.  In
particular, this includes any alerts sent by the server in response
to client Certificate and KEMEncapsulation messages.

# Record Protocol

KEMTLS uses the same TLS 1.3 Record Protocol.

# Alert Protocol

KEMTLS uses the same TLS 1.3 Alert Protocol.

# Cryptographic Computations

The KEMTLS handshake establishes three input secrets which are
combined to create the actual working keying material, as detailed below. The
key derivation process incorporates both the input secrets and the handshake
transcript.  Note that because the handshake transcript includes the random
values from the Hello messages, any given handshake will have different traffic
secrets, even if the same input secrets are used.

## Key schedule

KEMTLS uses the same HKDF-Extract and HKDF-Expand functions as defined by
TLS 1.3.

Keys are derived from two input secrets using the HKDF-Extract and
Derive-Secret functions.  The general pattern for adding a new secret
is to use HKDF-Extract with the Salt being the current secret state
and the Input Keying Material (IKM) being the new secret to be added.

In this version of KEMTLS, the input secret is:

 -  KEM shared secret which could be just one PQKEM or the concatenation
    of the PQKEM with the "classical" KEM.

The key schedule proceeds as follows:

~~~
             0
             |
             v
   PSK ->  HKDF-Extract = Early Secret
             |
             +-----> Derive-Secret(., "ext binder" | "res binder", "")
             |                     = binder_key
             |
             +-----> Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   KEM ->  HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "") = dHS
             |
             v
   KEM ->  HKDF-Extract = Authenticated Handshake Secret
             |
             +-----> Derive-Secret(., "c ahs traffic",
             |                     ClientHello...KEMEncapsulation)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s ahs traffic",
             |                     ClientHello...KEMEncapsulation)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "") = AHS
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
             +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret
~~~

# (Middlebox) Compatibility Considerations

Like in TLS 1.3, after the ephemeral key is derived
a ``ChangeCipherSpec`` message is sent and the messages afterwards are
encrypted. This will make the following messages opaque to non-decrypting
middle boxes.

The ``ClientHello`` and ``ServerHello`` messages are still in the clear
and these require the addition of new ``key_share`` types.
Typical KEM public-key and encapsulation sizes are also significantly bigger
than pre-quantum (EC)DH keyshares. This may still cause problems.

# Integration with Delegated Credentials

# Security Considerations {#sec-considerations}

TODO:

* sending data to an implicitly authenticated and not-full downgrade
resilient peer
* address CA and pq keys
* consider implicit vs explicit authentication
* consider downgrade resilience

# IANA Considerations

* We need a new OID for each KEM to encode them in X.509 certificates.

--- back

# Acknowledgements

This work has been supported by the European Research Council through Starting Grant No. 805031 (EPOQUE).
