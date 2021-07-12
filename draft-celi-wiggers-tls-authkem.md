---
title: KEM-based Authentication for TLS 1.3
abbrev: AuthKEM
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
    org: "Radboud University & MPI S&P"
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
  RFC5869:
  KEMTLS:
    title: "Post-Quantum TLS without Handshake Signatures"
    date: 2020-11
    author:
      - ins: D. Stebila
        name: Douglas Stebila
        org: University of Waterloo
      - ins: P. Schwabe
        name: Peter Schwabe
        org: "Radboud University & MPI S&P"
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
  KW16:
       title: "The OPTLS Protocol and TLS 1.3"
       date: 2016
       seriesinfo: Proceedings of Euro S&quot;P 2016
       target: https://eprint.iacr.org/2015/978
       author:
       -
         ins: H. Krawczyk
       -
         ins: H. Wee


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
       Client                                     Server

Key  ^ ClientHello
Exch | + key_share
     v + (kem)signature_algorithms
                          -------->
                                             ServerHello  ^ Key
                                       +       key_share  v Exch
                                   <EncryptedExtensions>  ^  Server
                                    <CertificateRequest>  v  Params
     ^                                     <Certificate>  ^
Auth | <KEMEncapsulation>                                 |  Auth
     | {Certificate}       -------->                      |
     |                     <--------  {KEMEncapsulation}  |
     | {Finished}          -------->                      |
     | [Application Data*] -------->                      |
     v                     <-------           {Finished}  |
                                                          v
       [Application Data]  <------->  [Application Data]

        +  Indicates noteworthy extensions sent in the
           previously noted message.
        *  Indicates optional or situation-dependent
           messages/extensions that are not always sent.
        <> Indicates messages protected using keys
           derived from a [sender]_handshake_traffic_secret.
        {} Indicates messages protected using keys
           derived from a
           [sender]_authenticated_handshake_traffic_secret.
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
     v + (kem)signature_algorithms  -------->
                                                      ServerHello  ^ Key
                                                +  (kem)key_share  v Exch
                                            <EncryptedExtensions>  ^  Server
                                             <CertificateRequest>  v  Params
     ^                                              <Certificate>  ^
Auth | <KEMEncapsulation>                                          |  Auth
     | {Certificate}                -------->                      |
     |                              <--------  {KEMEncapsulation}  |
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
     | <Certificate>          -------->                      |
     |                                          ServerHello  ^ Key
     |                                    +  (kem)key_share  | Exch,
     |                           +  {cached_info_extension}  | Auth &
     |                                {EncryptedExtensions}  | Server
     |                                   {KEMEncapsulation}  | Params
     |                        <--------          {Finished}  v
     |                        <-------- [Application Data*]
     v {Finished}             -------->

       [Application Data]     <------->  [Application Data]
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
          kem_encapsulation(tbd),
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
              case kem_encapsulation:     KEMEncapsulation;
              ...
          };
      } Handshake;
~~~

Protocol messages MUST be sent in the order defined in Section 4.
A peer which receives a handshake message in an unexpected order MUST
abort the handshake with an "unexpected_message" alert.

## Key Exchange Messages

KEM-auth based uses the same key exchange messages as TLS 1.3 with this
exceptions:

- Usage of a new message `KEMEncapsulation`.
- The `CertificateVerify` message is not used.
- Two extensions can be added to the `ClientHello` message: "cached_information"
  and "kem_encapsulation".
- One extensions can be added to the `ServerHello` message: "cached_information".

KEM-auth preserves the same cryptographic negotiation with the addition
of the KEM algorithms to the "signature_algorithms".

### Client Hello

KEMTLS uses the `ClientHello` message as described for TLS 1.3. When used
in a pre-distributed mode, however, two extensions are mandatory: "cached_information"
and "kem_encapsulation" for server authentication. This extensions are
described later in the document.

Note that in KEM-auth with pre-distributed information, the client's `Certificate`
message gets send alongside the `ClientHello` one for mutual authentication.

### Server Hello

KEMTLS uses the `ServerHello` message as described for TLS 1.3. When used
in a pre-distributed mode, however, one extension is mandatory: "cached_auth_key"
for server authentication. This extension is described later in the document.

When the ServerHello message is received:

- the client and server derive handshake traffic secrets `CHTS` and `SHTS` which are
  used to encrypt subsequent flows in the handshake
- the “handshake secret” is derived: `dHS` which is kept as the
  current secret state of the key schedule.

### Hello Retry Request

KEM-Auth uses the `ServerHello` message as described for TLS 1.3. When used
in a pre-distributed mode for mutual authentication, a `HelloRetryRequest`
message can be sent, but the client's `Certificate` message is ignored.

### Extensions

A number of KEM-Auth messages contain tag-length-value encoded extensions
structures. We are adding those extensions to the `ExtensionType` list
from TLS 1.3.

~~~
enum {
    ...
    signature_algorithms_cert(50),              /* RFC 8446 */
    key_share(51),                              /* RFC 8446 */
    kem_encapsulation (TBD),                    /* RFC TBD */
    cached_auth_key(TBD),                       /* RFC TBD */
    (65535)
} ExtensionType;
~~~

The table below indicates the messages where a given extension may
appear:

~~~
   +--------------------------------------------------+-------------+
   | Extension                                        |      KEMTLS |
   +--------------------------------------------------+-------------+
   | cached_auth_key [RFCTBD]                         |      CH, SH |
   |                                                  |             |
   | kem_encapsulation  [RFCTBD]                      |          CH |
   |                                                  |             |
   +--------------------------------------------------+-------------+
~~~

#### Cached Auth Key

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
server/client_finished_key =
  HKDF-Expand-Label(MasterKey,
                    server/client_label,
                    "", Hash.length)

server_label = "tls13 server finished"
client_label = "tls13 client finished"
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
TLS 1.3, in turn defined by {{RFC5869}}.

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
      PSK -> HKDF-Extract = Early Secret
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
  (EC)DHE -> HKDF-Extract = Handshake Secret
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
       SSs -> HKDF-Extract = Authenticated Handshake Secret
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
      SSc -> HKDF-Extract = Master Secret
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

The client computes the following input values as follows:
`SSs`, the shared secret from the server's long-term public key is
computed from the public key `pk_server` included by
the server's certificate.

If client authentication via KEM is used, `SSc`, the shared secret
encapsulated against the client's long-term public key, is computed
by decapsulating the encapsulation sent by the server to the client.
If client authentication is not used, this value is 0.

~~~
SSs, encapsulation <- Encap(pk_server)
               SSc <- Decap(encapsulation, sk_client)
~~~

The server computes `SSs`, the shared secret encapsulated against
its long-term public key; and `SSc`, the shared secret encapsulated
against the clients long-term public key (if client authentication is used)
as follows:

~~~
               SSs <- Decap(encapsulation, sk_server)
SSc, encapsulation <- Encap(pk_client)
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

The academic works proposing KEMTLS contain a in-depth technical discussion of
and a proof of the security of the handshake protocol without client
authentication [KEMTLS]. The work proposing the variant protocol [KEMTLSPDK]
with pre-distributed public keys has a proof for both unilaterally and mutually
authenticated handshakes.

## Implicit authentication

Because preserving a 1/1.5RTT handshake in KEMTLS requires the client to
send its request in the same flight as in which it receives the `ServerHello`
message, it can not yet have fully authenticated the server. However,
through the inclusion of the key encapsulated to the server's long-term
secret, only an authentic server should be able to decrypt these messages.

However, the client can not have received confirmation that the server's
choices for symmetric encryption, as specified in the `ServerHello` message,
were authentic. These are not authenticated until the `Finished` message from
the server arrived. This may allow an adversary to downgrade the symmetric
algorithms, but only to what the client is willing to accept. If the client 
trusts the symmetric algorithms advertised in its `ClientHello` message,
this should not be a concern. A client MUST NOT accept any cryptographic
parameters it does not include in its own `ClientHello` message.

If client authentication is used, explicit authentication is reached before
any application data, on either client or server side, is transmitted.

TODO / check if covered above:

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
