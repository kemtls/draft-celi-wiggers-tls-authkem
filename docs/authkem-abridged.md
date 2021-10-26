---
title: AuthKEM abridged
authors:
 - Thom Wiggers
 - Sofía Celi
description: |
  High-level introduction to the AuthKEM proposal for TLS.

# Formatting
breaks: false
toc: true


header-includes: |
  <style>
    div.info, div.warning {
      padding: 5px 15px 5px 15px;
      margin-bottom: 20px;
      border: 1px solid transparent;
      border-radius: 4px;
      box-sizing: border-box;
    }
    div.info {
      color: #31708f;
      background-color: #d9edf7;
      border-color: #bce8f1;
    }
    div.warning {
      color: #8a6d3b;
      background-color: #fcf8e3;
      border-color: #faebcc;
    }
  </style>
---
This serves as a high-level overview and introduction to [`draft-celi-wiggers-authkem`][draft-celi-wiggers-authkem]. We're trying to go for clarity here, not the most compact or complete description. We will try to answer all of your questions.

[draft-celi-wiggers-authkem]: https://www.ietf.org/id/draft-celi-wiggers-tls-authkem-00.html "draft-celi-wiggers-authkem"

::: info
Anything should be made more clear? Please send us an email.
:::

## Authentication via KEM

Our proposal is to allow authentication via Key Encapsulation Mechanisms (KEMs). This requires a certificate or [delegated credential][] that advertises a KEM public key. We will later show how you can also use previously cached or pre-installed KEM public keys for more efficient mechanisms, without the downsides of PSK resumption.
<!-- like having to store secret keys, etc. write later -->

[delegated credential]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-subcerts-11 "draft-ietf-tls-subcerts-11"

### What is a KEM?

A KEM is a public key key-exchange algorithm that defines two operations:

* `Encaps(pk)` which, given a public key generates a _shared secret_ and an _encapsulation_
* `Decaps(encapsulation, sk)`, which takes the encapsulation and returns the shared secret.

KEM public keys _can't sign messages_; they're only suitable for _key exchange_. But, this mechanism can be used for authentication: arriving to the same shared secret proves that only the other correct party is the one you are communicating with. The consequence of using this new authentication is that we need to define a new message flow for authentication.

### What KEMs are out there?

Current key exchange algorithms, like (EC)DH, can normally be rewritten as KEMs.
Our proposal is defined using the KEMs from [HPKE][]; this currently defines a few KEMs based on ECDH algorithms like P-256 and X25519.
[NIST is currently standardizing _Post-Quantum_ KEMs][nistpqc], which we expect will be added to HPKE.

[HPKE]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/ "draft-irtf-cfrg-hpke"
[nistpqc]: https://nist.gov/pqcrypto

### Why consider KEMs for authentication?

#### Same algorithm for key exchange and authentication
Using AuthKEM allows you to use the same public-key algorithm for both key exchange and authentication.
This means you only require (side-channel protected) code for the `encaps` and `decaps` operations.
For validation of the PKI (you still need certificates that are signed) only signature validation is needed.
This could allow for considerable savings in code size for embedded devices.

For optimized implementations of post-quantum algorithms, it's likely that there will not be much code that can be shared between different algorithms (such one might with e.g. X25519 and Ed25519).

#### _Quantum_ computers are coming

Will a large-scale quantum computer be built? The answer is complicated. Many scientists believe it to be a significant engineering challenge. The main discussion point at this moment seems to be _when_ rather than _if_, though. Google recently announced that it will be building a practical quantum computer by 2029.

Historically, it has taken almost two decades to deploy our modern public key cryptography infrastructure. Therefore, regardless of whether we can estimate the exact time of the arrival of the quantum computing era, we must begin now to prepare our systems to be able to resist quantum computing.

#### Why should we care about _quantum-resistant authentication_?

Even though the main worry of a quantum computer existance is that an attacker can pre-record traffic to break it later with a quantum computer (thus, breaking confidentiality), authentication MUST be taken into account as well. An attacker can pre-record traffic, as well, to retroactively frame participants. Therefore, authentication should be also taken into account.


#### _Post-Quantum_ signatures might not fit your application, requiring an alternative

All Post-Quantum signature schemes currently being considered for standardization by NIST have some downsides compared to RSA and elliptic curves.
Notably they're all quite a bit larger.
[Experiments have shown][NDSS paper] only Dilithium and Falcon seem suitable for use in TLS at all.
Both algorithms are based on structured lattices; Dilithium is quite big (and its smallest parameter set has gotten bigger since experiments were done); Falcon requires fast, constant-time 64-bit floating point arithmetic and is [complicated to implement correctly][falcon impl].
NIST has announced it expects to standardize **at most one** of these two schemes.

[NDSS paper]: https://eprint.iacr.org/2020/071/ "Post-Quantum Authentication in TLS 1.3: A Performance Study"
[falcon impl]: https://eprint.iacr.org/2019/893.pdf "New Efficient, Constant-Time Implementations of Falcon (See section 6)"

Post-Quantum KEMs are also larger than the typical ECDH key exchange, but the sum of the sizes of a KEM public key and encapsulation message is significantly smaller than sum of the sizes of a Dilithium public key and signature. The sum of the sizes of a Falcon public key and signature is roughly the same size the public keys and ciphertexts of the post-quantum KEM finalists Kyber, NTRU and SABER, but the KEMs are much more computationally efficient. (Admittedly, Falcon is still quite fast with the correct hardware support (like AVX2)).

### Why now, post-quantum KEMs or post-quantum signatures aren't standardized yet?

Writing up this draft now serves to facilitate experiments and discussion.
We appreciate that it might feel as a big change to TLS, which is all the more reason to take the time now to carefully understand the pros and cons of this proposal while we _have_ time.
We expect any move to post-quantum authentication to have big impact, even just due to the new and often much larger algorithms.

This draft, to reach its full potential, will eventually require quantum-safe certificates with KEM public keys and root certificates with post-quantum signature algorithms.
The transition to post-quantum cryptography will present a massive challenge to the PKI infrastructure and certificate issuers. We think it's not wise to wait for them, however. We especially think that this proposal could be a wake-up call that we might need other algorithms than just signature schemes in the PKI ecosystem.


## TLS Server authentication via KEM

1. To negotiate server authentication via AuthKEM, we extend the `signature_algorithms` with our supported KEMs. This way the client indicates support to the server.

::: info
**Why extend `signature_algorithms`? It's not a signature scheme!**

This extension really identifies *authentication* algorithms.
And if we would add a new extension we would have to _ignore_ the
`signature_algorithms`-indicated algorithms, which is also just messy.
:::

2. The Client responds with `KemEncapsulation` message.
3. The shared secret that the client obtained from the `Encapsulate` operation is combined with the existing handshake keys to derive a new "authenticated" handshake traffic secret (-AHS- This secret key will mostly be useful for client certificate authentication later).
4. The client now immediately derives the Main Secret and submits `Finished` message, **after which it can start sending its application data**.


This means we have the following protocol overview:

             Client                                  Server
           ClientHello         -------->
                               <--------         ServerHello
                                                       <...>
                               <--------       <Certificate>  ^
           <KEMEncapsulation>                                 | Auth
           {Finished}          -------->                      |
           [Application Data]  -------->                      |
                               <--------          {Finished}  v

           [Application Data]  <------->  [Application Data]

          <msg>: encrypted w/ keys derived from ephemeral KEX (HS)
          {msg}: encrypted w/ keys derived from HS+KEM (AHS)
          [msg]: encrypted w/ traffic keys derived from AHS (MS)


Note that we allow the client to send `Finished` first, unlike in TLS 1.3 where the Server sends `Finished` first (along its certificate).
We make this change to avoid the penalty of an extra half round-trip.

### Why we think the extra half round-trip doesn't matter for performance

As shown above, in this mode KEMTLS does not allow the server to send `Finished` and its first application data along the `ServerHello` and `Certificate` messages.
This is due to the nature of KEMs, which are "interactive" protocols: they require the participation of two parties to complete the key exchange. Signature schemes don't require the participation of another party, so they allow non-interactive authentication.

We avoid a full round-trip penalty that a naive implementation of KEM authentication would imply, by moving the `Finished` message and letting the client send its data immediately.
This still allows a client to send its application data to the server in the same place as it would have been sent in TLS 1.3.

We think that in almost any application, like in HTTP, a client will first have to indicate what action they want the server to perform or what data they need, before any useful non-public data can be sent by the server.
KEMTLS allows both the request and the response to be sent in the same place.

::: info
**Note:** For applications like HTTP/2, which send mostly-public connection settings in this first message from the server, something like a server-side version of ALPN might be useful to avoid performance penalties when KEMTLS is used.
:::

### Why we think sending Client Data to the server early is fine

In the above protocol, the client sends its (probably sensitive) request to the server before it received the server's `Finished` message.
This has some consequences:

1. The client can't be sure if the server is actually present to receive its request
1. The server has not confirmed its choices of CipherSuite, etc. advertised in ServerHello

We will now explain why we think this is not a problem.

#### Presence of the server

An adversary might replay the server's certificate to an unsuspecting client.
This would eventually be foiled by the server's `Finished` message, but the client will have already transmitted data at that point.
That data **is encrypted under a key only the legitimate server can obtain**, so its confidentiality is ensured.
But until the client receives the handshake completion messages from the server, the client can not be sure if the legitimate server was ever present in the handshake.

This is not different from _truncation attacks_ already possible in TLS 1.3 or any other encrypted transport protocol, however.
An application must be prepared to deal with interrupted/unsuccesful transmissions.
An adversary can always simply cut a network connection at an opportune time.
This is why it is important for TLS implementations to carefully handle the record layer protections against truncation attacks: this is no different for KEMTLS.

#### Choices of ciphersuites

This is the "cryptographically least pretty" part of KEMTLS: not waiting for "explicit" server authentication in the form of the MAC means we have not confirmed the server's choices of ciphersuites have not been messed with.

This means that technically, an adversary might trivially downgrade the traffic encryption (and MAC) algorithms.
The data most at risk here is the client's first request to the server, which might contain credentials such as session cookies.

**Such an attacked connection will not be able to complete, because the attacker will not be able to forge the server's `Finished` message.** This also means that, when attacked, no reply from the server can be received by the client. Once the `Finished` message is received from the server, the connection is **retroactively fully secure**: it's guaranteed that the ciphersuites have not been tampered with.

However, a correctly implemented client will **only accept ciphersuites it advertised in its ClientHello**.
Clients should not advertise "weak" algorithms they did not trust in the first place.

We also benefit from the work done in TLS 1.3, which massively trimmed down the available algorithm choices to mainly AES and ChaCha20; well-tested algorithms which we do not expect to see broken any time soon: no more `EXPORT` ciphers are present.

Any such attacks will be _noisy_; as the handshakes can not be completed clients under attack will see failed connection attempts and won't be receiving any server data.
This makes this attack not suitable for "store and decrypt later" adversaries that might want to downgrade to a weaker primitive.

### Academic analysis of the security of KEMTLS

KEMTLS was originally proposed in [an academic paper](https://ia.cr/2020/534). This paper also has a security proof of the server-only authenticated protocol and discusses the above security characteristics in more detail.

The mode where we use AuthKEM with known server long-term keys was discussed in [another paper](https://ia.cr.2021/779). This paper also contains a security proof.

We are currently undertaking the formal analysis of the KEMTLS protocol (which should extend the AuthKEM one) in Tamarin, building on the existing TLS 1.3 model. There's still a lot to be done, but we hope to be able to back this draft proposal with some machine-checked analysis in the future.

## TLS Client authentication via KEM


Of course, TLS also has a mode where the client proves its identify through a client certificate.
For client authentication, we follow a similar mechanism.
Unfortunately, we do suffer the full penalty of the additional round-trip necessary for authentication via key exchange here.

::: info
We will later discuss how to avoid this penalty _if_ the client already knows the server's long-term public key _and_ knows that it will want to authenticate.
:::


In the below picture we sketch the message flow of client authentication.

1. The server indicates it wants the client to authenticate through the `CertificateRequest` method as per usual.
2. The client replies with its certificate (which contains its KEM public key), to which the server creates an encapsulation.
3. The resulting shared secret is mixed with the ephemeral key exchange shared secret and the server authentication shared secret to finally derive the traffic keys to encrypt the application data.

```
             Client                                  Server
           ClientHello         -------->
                               <--------         ServerHello
                                                       <...>
                                        <CertificateRequest>
                               <--------       <Certificate>  ^
           <KEMEncapsulation>                                 | Auth
         ^ {Certificate}       -------->                      |
    Auth |                                                    |
         |                     <--------  {KEMEncapsulation}  |
         | {Finished}          -------->                      |
         | [Application Data]  -------->                      |
         v                     <-------           {Finished}  v

           [Application Data]  <------->  [Application Data]

          <msg>: enc. w/ keys derived from ephemeral KEX (HS)
          {msg}: enc. w/ keys derived from HS+srv. KEM Auth (AHS)
          [msg]: enc. w/ keys derived from AHS+cl. KEM Auth (MS)
```

We added AHS to the key schedule earlier.
This is necessary because the client certificate needs to be sent securely.
TLS requires the client's identity (its certificate) to be protected against both passive and active attackers. Encrypting it with (keys derived from) AHS ensures that only the real server can read it.

::: info
**What about server auth with AuthKEM and client auth with signatures?**

Good question. The current design and proofs use the key schedule and that the client authentication result is mixed into the final handshake secrets.
We can _probably_ prove the protocol correct still if the client uses signed key exchange, but it would  be good if this work is done.
:::


::: warning
**Does this mean the CertificateRequest isn't authenticated?**

Although the client's certificate is protected, it is possible for an active attacker to try to trigger a client to attempt to authenticate.
They will not be able to read the certificate, but might learn that a client has one or even just trigger confusing or annoying UI popups.
If this is a concern in your application (web browsers?), we might need to consider allowing the client to indicate it will only allow post-handshake authentication.

We're tracking this in [issue #16: Authentication concerns for the client authentication requests](https://github.com/claucece/draft-celi-wiggers-tls-authkem/issues/16).
:::

## More efficient AuthKEM if you've already got the keys

Because KEMs are key exchange mechanisms, we can use them to enable resumption-style scenarios that are more efficient than the regular AuthKEM handshake, but are still full handshakes.
This does not rely on shared secrets (like PSK resumption in TLS 1.3).
This means that these handshakes do not tie back to an original handshake's security properties.
Clients do not need to manage a secret key, and servers do not need to keep track of secret keys per client.
Also, because this just requires plain KEM public keys rather than (stateful) opaque session tickets, we expect fewer privacy or tracking concerns.

::: info
We call this "pre-distributed keys" (or PDK) because:

 * PSK is already taken
 * PSK typically refers to symmetric keys
 * Server public keys might be cached by clients, but they could also be installed (_i.e. pre-distributed_) through, for example, firmware.
:::

### Server authentication with pre-distributed keys

The idea is simple: if the client already has the server's long-term public key (typically their certificate), it can start the AuthKEM authentication process one step "early".

1. It transmits the `KEMEncapsulation` message immediately along the `ClientHello` message as an extension.
2. The server decapsulates it to obtain the authentication shared secret. It also completes the ephemeral key exchange as usual. The server does not need to transmit the `Certificate` anymore.
3. As the server now has all the information to derive the traffic keys, it can now also immediately reply with `Finished` and start writing application data.

               Client                               Server

           ClientHello
            + KemEncapsulation
                               -------->
                               <--------         ServerHello
                                                       <...>
                               <--------          <Finished>
                               <--------  [Application Data]
           <Finished>          -------->
           [Application Data]  <------->  [Application Data]

          <msg>: enc. w/ keys derived from KEX+srv. KEM auth (HS)
          [msg]: enc. w/ traffic keys derived from HS (MS)

To enable the client-authentication scenario that is to follow, we mix in the shared secret obtained by encapsulating to the server's long-term public key into the key schedule early: specifically, we derive the Early Secret (ES) key in TLS's handshake key schedule from it.
This also mirrors that this key does not have any forward secrecy (which can only be obtained once the ephemeral key exchange is completed), just like ES in "normal" TLS 1.3.

::: info
If the server rejects the `KEMEncapsulation` sent by the client in the `ClientHello` extension, the handshake can simply continue as usual; just ignoring the attempted "resumption".
:::

### Client authentication with pre-distributed keys

In many scenarios, the client might already know that they will need to authenticate.
This could for example be the case in server-to-server or IoT applications of mutually-authenticated TLS.

We can also speed up this handshake by allowing the client to send the client certificate immediately following the `ServerHello` message, as a sort of 0-RTT data.
The server can then already send the client authentication `KEMEncapsulation` message immediately following its usual `ServerHello` and `EncryptedExtensions` messages.


               Client                               Server

           ClientHello
            + KemEncapsulation
            {Certificate}      -------->
                               <--------         ServerHello
                                                       <...>
                                          <KEMEncapsulation>
                               <--------          <Finished>
                               <--------  [Application Data]
           <Finished>          -------->
           [Application Data]  <------->  [Application Data]

          {msg}: enc. w/ keys derived from srv. KEM auth (ES)
          <msg>: enc. w/ keys derived from KEX+srv. KEM auth (HS)
          [msg]: enc. w/ keys derived from HS+cl. KEM auth (MS)


Again, the server can immediately derive the final handshake secret and the traffic secret keys, which allows it to complete the handshake by sending `Finished` in its first response to the client's `ClientHello`.

#### Encrypting the client certificate

In many ways, we're using a similar data flow as the 0-RTT data in TLS 1.3 PSK resumption.
We have similar security properties for the client's certificate.
As it's not encrypted with ephemeral keys, is not forward-securely encrypted.
The server also has no idea it's not replayed.
However, we argue that this has fairly low impact on the security of the protocol and the privacy of the client.
The client is also actively opting in to this message flow.
If its identity is _very_ sensitive, the client might opt to use any of the other authentication flows.


## Other properties

### Deniability

Auth-KEM, unlike the signature-authenticated handshake of TLS 1.3, provides offline deniability: given just the long-term public keys of the
parties, it is possible to forge transcripts indistinguishable from real ones produced by honest parties following the protocol specification after the protocol execution.

## Further reading

* Peter Schwabe, Douglas Stebila and Thom Wiggers. **Post-Quantum TLS Without Handshake Signatures**, ACM CCS 2020. https://ia.cr/2020/534
* Peter Schwabe, Douglas Stebila and Thom Wiggers. **More efficient KEMTLS with pre-distributed keys**, ESORICS 2021. https://ia.cr/2021/779
* Sofía Celi, Armando Faz-Hernández, Nick Sullivan, Goutam Tamvada, Luke Valenta, Bas Westerbaan,  Thom Wiggers, Chris Wood. **Implementing and Measuring KEMTLS** Latincrypt 2021, https://ia.cr/2021/1019
* Sofía Celi, Peter Schwabe, Douglas Stebila, Nick Sullivan, Thom Wiggers. **[draft-celi-wiggers-authkem][]**, IETF draft
