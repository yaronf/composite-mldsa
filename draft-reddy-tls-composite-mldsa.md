---
title: "Use of Composite ML-DSA in TLS 1.3"
abbrev: "Use of Composite ML-DSA in TLS 1.3"
category: std

docname: draft-reddy-tls-composite-mldsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "TLS"

keyword:
 - ML-DSA
 - FIPS204
 - Composite

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Timothy Hollebeek
    organization: DigiCert
    city: Pittsburgh
    country: USA
    email: "tim.hollebeek@digicert.com"
 -
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
 -
    fullname: Scott Fluhrer
    organization: Cisco Systems
    email: "sfluhrer@cisco.com"

normative:
 RFC8446:
 TLSIANA: I-D.ietf-tls-rfc8447bis
 I-D.ietf-lamps-pq-composite-sigs:
informative:
 RFC5246:
 RFC8017:
 I-D.ietf-pquip-pqt-hybrid-terminology:
 FIPS204:
   title: "FIPS-204: Module-Lattice-Based Digital Signature Standard"
   target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
   date: false
 BSI2021:
   title: "Quantum-safe cryptography - fundamentals, current developments and recommendations"
   target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Brochure/quantum-safe-cryptography.pdf
   author:
     - org: "Federal Office for Information Security (BSI)"
   date: October 2021
 
--- abstract

Compositing the post-quantum ML-DSA signature with traditional signature algorithms provides protection against potential breaks or critical bugs in ML-DSA or the ML-DSA implementation. This document specifies how such a composite signature can be formed using ML-DSA with RSA-PKCS#1 v1.5, RSA-PSS, ECDSA, Ed25519, and Ed448 to provide authentication in TLS 1.3.

--- middle

# Introduction

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA, Diffie-Hellman, DSA, and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}. 

One practical way to implement a hybrid signature scheme is through a composite signature algorithm. In this approach, the composite signature consists of two signature components, each produced by a different signature algorithm. A composite key is treated as a single key that performs a single cryptographic operation such as key generation, signing and verification by using its internal sequence of component keys as if they form a single key.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite schemes provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies {{BSI2021}}.

ML-DSA {{FIPS204}} is a post-quantum signature schemes standardised by NIST. It is a module-lattice based scheme.

This memo specifies how a composite ML-DSA can be negotiated for authentication in TLS 1.3 via the "signature_algorithms" and "signature_algorithms_cert" extensions. Hybrid signatures provide additional safety by ensuring protection even if vulnerabilities are discovered in one of the constituent algorithms. For deployments that cannot easily tweak configuration or effectively enable/disable algorithms, a composite signature combining PQC signature algorithm with an traditional signature algorithm offers the most viable solution.

The rationale for this approach is based on the limitations of fallback strategies. For example, if a traditional signature system is compromised, reverting to a PQC signature algorithm would prevent attackers from forging new signatures that are no longer accepted. However, such a fallback process leaves systems exposed until the transition to the PQC signature algorithm is complete, which can be slow in many environments. In contrast, using hybrid signatures from the start mitigates this issue, offering robust protection and encouraging faster adoption of PQC.

Further, zero-day vulnerabilities, where an exploit is discovered and used before the vulnerability is publicly disclosed, highlights this risk. The time required to disclose such attacks and for organizations to reactively switch to alternative algorithms can leave systems critically exposed. By the time a secure fallback is implemented, attackers may have already caused irreparable damage. Adopting hybrid signatures preemptively helps mitigate this window of vulnerability, ensuring resilience even in the face of unforeseen threats.

## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This document is consistent with the terminology defined in {{I-D.ietf-pquip-pqt-hybrid-terminology}}. It defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

# ML-DSA SignatureSchemes Types

As defined in {{RFC8446}}, the SignatureScheme namespace is used for
the negotiation of signature scheme for authentication via the
"signature_algorithms" and "signature_algorithms_cert" extensions.
This document adds new SignatureSchemes types for the composite ML-DSA as follows.

~~~
enum {
  mldsa44_ecdsa_secp256r1_sha256 (0x0907),
  mldsa65_ecdsa_secp384r1_sha384 (0x0908),
  mldsa87_ecdsa_secp384r1_sha384 (0x0909),
  mldsa44_ed25519 (0x090A),
  mldsa65_ed25519 (0x090B),
  mldsa44_rsa2048_pkcs1_sha256 (0x090C),
  mldsa65_rsa3072_pkcs1_sha256 (0x090D),
  mldsa65_rsa4096_pkcs1_sha384 (0x090E),
  mldsa44_rsa2048_pss_pss_sha256 (0x090F),
  mldsa65_rsa3072_pss_pss_sha256 (0x0910),
  mldsa65_rsa4096_pss_pss_sha384 (0x0911),
  mldsa87_ed448 (0x0912)
} SignatureScheme
~~~

Each entry specifies a unique combination of an ML-DSA parameter, an elliptic curve or RSA variant, and a hashing function. The first algorithm corresponds to ML-DSA-44, ML-DSA-65, and ML-DSA-87, as defined in {{FIPS204}}. It is important to note that the mldsa* entries represent the pure versions of these algorithms and should not be confused with prehashed variants, such as HashML-DSA-44, also defined in {{FIPS204}}. Support for prehashed variants is not required because TLS computes the hash of the message (e.g., the transcript of the TLS handshake) that needs to be signed. 

ML-DSA supports two signing modes: deterministic and hedged. In the deterministic mode, the signature is derived solely from the message and the private key, without requiring fresh randomness at signing time. While this eliminates dependence on an external random number generator (RNG), it may increase susceptibility to side-channel attacks, such as fault injection. The hedged mode mitigates this risk by incorporating both fresh randomness generated at signing time and precomputed randomness embedded in the private key, thereby offering stronger protection against such attacks. In the context of TLS, authentication signatures are computed over unique handshake transcripts, making each signature input distinct for every session. This property allows the use of either signing mode. The hedged signing mode can be leveraged to provide protection against the side-channel attack. The choice between deterministic and hedged modes does not affect interoperability, as the verification process is the same for both. In both modes, the context parameter defined in Algorithm 2 and Algorithm 3 of {{FIPS204}} MUST be set to the empty string.

The signature MUST be computed and verified as specified in {{Section 4.4.3 of RFC8446}}. The Composite-ML-DSA.Sign function, defined in {{I-D.ietf-lamps-pq-composite-sigs}}, will be utilized by the sender to compute the signature field of the CertificateVerify message. Conversely, the Composite-ML-DSA.Verify function, also defined in {{I-D.ietf-lamps-pq-composite-sigs}}, will be employed by the receiver to verify the signature field of the CertificateVerify message. 

The corresponding end-entity certificate when negotiated MUST
use the First AlgorithmID and Second AlgorithmID respectively as
defined in {{I-D.ietf-lamps-pq-composite-sigs}}.

The schemes defined in this document MUST NOT be used in TLS 1.2 {{RFC5246}}. A peer that receives ServerKeyExchange or CertificateVerify message in a TLS 1.2 connection with schemes defined in this document MUST abort the connection with an illegal_parameter alert.

# Signature Algorithm Restrictions

TLS 1.3 removed support for RSASSA-PKCS1-v1_5 {{RFC8017}} in CertificateVerify messages, opting for RSASSA-PSS instead. Similarly, this document restricts the use of the composite signature algorithms mldsa44_rsa2048_pkcs1_sha256, mldsa65_rsa3072_pkcs1_sha256, and mldsa65_rsa4096_pkcs1_sha384 algorithms to the "signature_algorithms_cert" extension. These composite signature algorithms MUST NOT be used with the "signature_algorithms" extension. These values refer solely to signatures which appear in certificates (see {{Section 4.4.2.2 of RFC8446}}) and are not defined for use in signed TLS handshake messages.

A peer that receives a CertificateVerify message indicating the use of the RSASSA-PKCS1-v1_5 algorithm as one of the component signature algorithms MUST terminate the connection with a fatal illegal_parameter alert.

# Selection Criteria for Composite Signature Algorithms

The composite signatures specified in the document are restricted set of cryptographic pairs, chosen from the intersection of two sources:

* The composite algorithm combinations as recommended in {{I-D.ietf-lamps-pq-composite-sigs}}, which specify both PQC and traditional signature algorithms.
* The mandatory-to-support or recommended traditional signature algorithms listed in TLS 1.3.

By limiting algorithm combinations to those defined in both {{I-D.ietf-lamps-pq-composite-sigs}} and TLS 1.3, this specification ensures that each pair: 

* Meets established security standards for composite signatures in a post-quantum context, as described in {{I-D.ietf-lamps-pq-composite-sigs}}.
* Is compatible with traditional digital signatures recommended in TLS 1.3, ensuring interoperability and ease of adoption within the TLS ecosystem.

This conservative approach reduces the risk of selecting unsafe or incompatible configurations, promoting security by requiring only trusted and well-vetted pairs. Future updates to this specification may introduce additional algorithm pairs as standards evolve, subject to similar vetting and inclusion criteria.

# Security Considerations

The security considerations discussed in Section 11 of {{I-D.ietf-lamps-pq-composite-sigs}} needs
to be taken into account. 

Ed25519 and Ed448 ensure SUF security, which may remain secure even if ML-DSA is broken, at least until CRQCs
emerge. Applications that prioritize SUF security may benefit from using them in composite with ML-DSA to
mitigate risks if ML-DSA is eventually broken.

TLS clients that support both post-quantum and traditional-only signature algorithms are vulnerable to downgrade attacks. In such a scenario, an attacker with access to a CRQC could forge a traditional server certificate, thereby impersonating the server. If the client accepts traditional-only certificates, it will be exposed to this risk. To mitigate such attacks, clients SHOULD enforce a policy to reject traditional-only certificates once post-quantum or composite authentication is broadly deployed and the need to interoperate with legacy servers has passed. In the interim, accepting traditional-only certificates remains necessary for compatibility with the existing ecosystem, where many servers have not yet upgraded to PQ or composite authentication mechanisms. 

# IANA Considerations

This document requests new entries to the TLS SignatureScheme registry,
according to the procedures in {{Section 6 of TLSIANA}}.


| Value   | Description                         | Recommended | Reference      |
|---------|-------------------------------------|-------------|----------------|
| 0x0907  | mldsa44_ecdsa_secp256r1_sha256      | N           | This document. |
| 0x0908  | mldsa65_ecdsa_secp384r1_sha384      | N           | This document. |
| 0x0909  | mldsa87_ecdsa_secp384r1_sha384      | N           | This document. |
| 0x090A  | mldsa44_ed25519                     | N           | This document. |
| 0x090B  | mldsa65_ed25519                     | N           | This document. |
| 0x090C  | mldsa44_rsa2048_pkcs1_sha256        | N           | This document. |
| 0x090D  | mldsa65_rsa3072_pkcs1_sha256        | N           | This document. |
| 0x090E  | mldsa65_rsa4096_pkcs1_sha384        | N           | This document. |
| 0x090F  | mldsa44_rsa2048_pss_pss_sha256      | N           | This document. |
| 0x0910  | mldsa65_rsa3072_pss_pss_sha256      | N           | This document. |
| 0x0911  | mldsa65_rsa4096_pss_pss_sha384      | N           | This document. |
| 0x0912  | mldsa87_ed448                       | N           | This document. |

## Restricting Composite Signature Algorithms to the signature_algorithms_cert Extension

IANA is requested to add a footnote indicating that the mldsa44_rsa2048_pkcs1_sha256, mldsa65_rsa3072_pkcs1_sha256, and mldsa65_rsa4096_pkcs1_sha384 algorithms are defined exclusively for use with the signature_algorithms_cert extension and are not intended for use with the signature_algorithms extension.

--- back

# Migration Scenarios

This appendix describes a likely migration scenario as different parts of the industry move at different rates from TLS with traditional crypto, into TLS with composite certificates and eventually TLS with "pure" PQ certificates. We then define a small TLS extension designed to secure TLS connections from rollback attacks during parts of this migration.

## Migration Phases

Following we list a likely chronological progression from today’s predominantly classical ecosystem to one using exclusively post-quantum (PQ) certificates. Based on our collective experience with TLS version migration and the PKI migration from RSA to ECDSA, we expect each phase to be measured in years.

1. Most TLS implementations start by adopting hybrid key exchange. As of this writing, the relevant drafts are nearly finalized, making this adoption feasible. Moreover, there is already good client-side adoption in the open Web.
2. Next, composite certificates become available for some portion of the server population.
3. Clients start using these certificates, and the common policy is "I would trust a server that presents either a traditional or a composite certificate".
4. Once the industry has reached a high percentage of Composite adoption on the client side, and trust in pure PQ is established, servers may begin presenting both Composite and pure PQ certificates.
5. Clients can then be configured to reject traditional certificates.
6. Finally, as PQ certificate adoption increases on the server side, clients can be configured to accept only pure PQ certificates.

We expect cryptography-relevant quantum computers (CRQC) to become available, at least in small quantities, sometime during this timeline. It is likely that early ones will be kept secret by state actors.

If this happens during phases (3) and (4), clients would be vulnerable to rollback attacks by a CRQC that can generate a fake traditional certificate. This vulnerability would exist despite the use of hybrid key exchange, and even if the majority of servers have already adopted Composite certificates. The next section proposes a TLS extension to mitigate this issue.

We believe that similar migration phases, similar risks and similar mitigations apply to the Dual Certificate scheme.

## The pq_cert_available Extension

The extension we define enables the TLS client to cache an indication that the server is able to present a (Composite or pure) PQ certificate, for some duration of time, e.g. one year. As a result:

* Clients that reconnect to an already known server within the validity period are protected from rollback to classic certificates.
* "New" clients are protected as soon as they connect to a server that is not fronted by a MITM attacker.

The explicitly communicated caching time allows clients to implement a caching policy with no risk of sudden breakage, and allows servers to revert to classic certificates if they ever see the need to do so.

This extension is modeled on HSTS {{?RFC6797}}, but whereas HSTS is at the HTTP layer, our extension is implemented at the TLS layer.

On the open Web, we expect this extension to be used mainly for caching the fact that a server is presenting a PQ certificate. However in other use cases such as service-to-service traffic, it would often make sense to use it for both clients and servers.

### Extension Definition

This is a TLS extension, as per sec. 4.2 of {{!RFC8446}}. The extension type for `pq_cert_available` is TBD by IANA.

It MAY appear in the Client Hello (CH) and Certificate (CT) messages sent by either client or server.

A client that supports this extension MUST send it in Client Hello, with an empty extension data.

Once a client asserted its support, the server MAY include the extension along with the certificate it presents. A client MUST NOT use this extension in the Certificate message if the server did not include it in its own Certificate message.

The extension data when sent in the Certificate message is:

~~~
struct {
    SignatureScheme signature_algorithm;
    uint32 algorithm_validity;
}
~~~

For symmetry, a server MAY send an empty `pq_cert_available` extension in its Certificate message to signal support for this mechanism, even if no signature algorithm or duration is specified.

Note on terminology: Since the extension can be sent by both client and server, in the following text we will use the term "sender" for the peer that sent the extension in its Certificate message and "recipient" for the other peer. We use `signature_algorithm` for the respective extension sent in the Client Hello message or for the equivalent extension sent within the server's CertificateRequest message.

The `signature_algorithm` in this extension MUST be the signature algorithm that the sender's certificate is associated with.

The `algorithm_validity` field is the time duration, in seconds, that the sender commits to continue to present a certificate that addresses this signature scheme. The time duration is measured starting with the TLS handshake and is unrelated to any particular certificate or its lifecycle.

### Recipient Behavior

A recipient that supports this extension MUST behave as follows:

1. If the recipient holds no cached information for the sender, and the sender includes it:

   * The recipient SHOULD cache the provided information after the handshake is completed successfully and after the extension's data has been validated.
   * The recipient MAY choose to cache the signature algorithm for a shorter period than specified.

2. If the recipient holds unexpired cached information for the sender:

   * The recipient SHOULD include the cached algorithm in its `signature_algorithms` list.
   * It MAY include other PQ signature algorithms.
   * Most importantly, it MUST abort the handshake if the sender does not present a certificate associated with one of the requested algorithms.

3. If the recipient holds unexpired cached information for the sender, and receives a returned extension from the sender:

   * The recipient should validate the `signature_algorithm` relative to the certificate being presented and SHOULD extend its cache period if the received time value would expire later than its current cache expiry.
   * It SHOULD NOT accept an `algorithm_validity` value if it would decrease its existing value (within a few seconds' tolerance).
   * It SHOULD replace its cached signature algorithm for the sender by a different PQ algorithm is such is sent in the extension, and in this case, it SHOULD use the validity time as-is.

4. If the recipient holds unexpired cached information for the sender, and receives no returned extension from the sender, the recipient SHOULD NOT modify its cache.

OPEN ISSUE: do we discuss how the cache is indexed? Service identity per RFC 9525?

### Sender Behavior

1. A TLS client or server that receives indication that its peer supports this extension SHOULD send this extension in the Certificate message, provided a PQ signature algorithm is used.
2. The sender MUST keep track of the time duration it has committed to, and use a PQ certificate to authenticate itself for that entire duration. The sender MAY change its certificates and may switch between PQ signature algorithms at will, as long as the peer indicates acceptance of these algorithms.

### Operational Considerations

This extension establishes a (potentially) long-term commitment of the sender to support PQ signature algorithms. As such, we recommend that deployers first experiment with short validity periods (e.g. one day), and only when satisfied that peers populate and depopulate their cache correctly, can move to a longer duration. In the case of HSTS, the industry has settled on 1 year as a common value.

# Acknowledgments
{:numbered="false"}

Thanks to Bas Westerbaan, Alicja Kario, Ilari Liusvaara, Dan Wing and Sean Turner for the discussion and comments.
