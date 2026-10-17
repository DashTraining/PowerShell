# Modern X.509 v3 Certificate Field Reference

**Research cutoff:** 16 October 2026  
**Primary target:** A future PowerShell certificate builder running on Windows  
**Orientation:** Microsoft-first for private PKI; standards-first and CA/B Forum-compliant for public trust

## 1. Purpose and limits

This is a field catalog, not a single universal certificate template. X.509 defines a container and path-validation model; the application consuming a certificate defines the actual profile. A field can consequently be mandatory for public TLS, forbidden for an OCSP responder, and irrelevant to code signing.

The catalog covers practical modern profiles. It does not attempt to enumerate every private enterprise OID ever registered. Unknown critical extensions cause conforming clients to reject a certificate, so arbitrary private extensions must not be offered as casual options.

### Requirement notation

| Code | Meaning |
|---|---|
| **M** | Mandatory for the named profile. |
| **C** | Conditional: mandatory when the stated condition applies. |
| **O** | Optional and valid; often recommended. |
| **X** | Forbidden or incompatible with the profile. |
| **A** | Avoid: technically possible in some profiles, but obsolete, unsafe, or harmful to interoperability. |
| **—** | Not applicable. |

`M-RFC`, `M-CABF`, and `M-MS` identify the authority imposing a requirement. `BP` means operational best practice rather than a universal protocol requirement.

### Scenario keys

| Key | Scenario |
|---|---|
| **TLS-PUB** | Publicly trusted TLS server certificate. |
| **TLS-PRV** | Private TLS server: IIS, SQL Server, LDAPS, internal APIs, and similar services. |
| **mTLS** | General TLS client authentication. |
| **EAP-C / EAP-S** | EAP-TLS client / NPS, RADIUS, VPN, or Wi-Fi server. |
| **AD-USR** | AD user/device certificate authentication, smart-card logon, PKINIT, or Windows Hello certificate trust. |
| **DC-KDC** | Domain controller/Kerberos Authentication certificate; also commonly supports LDAPS. |
| **INTUNE** | User/device certificate provisioned by Intune SCEP or PKCS. |
| **SMIME** | S/MIME signing and/or encryption certificate. |
| **CODE** | Authenticode or other code-signing certificate. |
| **DOC** | Human-readable document signing, including Microsoft Office. |
| **TSA** | RFC 3161 timestamp authority certificate. |
| **OCSP** | Delegated OCSP responder certificate. |
| **ROOT / SUBCA** | Root CA / issuing or constrained subordinate CA. |
| **IKE** | IKEv2/IPsec and certificate-based VPN peer authentication. |
| **WORKLOAD** | Short-lived service/workload mTLS, including SPIFFE X.509-SVID. |
| **SIGSTORE** | Sigstore/Fulcio short-lived code-signing certificate. |
| **EFS/RDS** | Windows EFS, recovery, or Remote Desktop-specific purposes. |
| **PKI-ADMIN** | AD CS enrollment-agent, key-recovery-agent, and CA key-exchange certificates. |

### Decision precedence

1. The relying product's documented requirements.
2. Applicable public-trust rules, such as the current CA/B Forum profile.
3. Current RFC requirements.
4. Microsoft-supported guidance for a Windows private-PKI scenario.
5. General best practice.

Public-trust rules are not relaxed merely because a Microsoft product accepts a broader private-PKI profile.

## 2. High-frequency fields

These fields occur in essentially every modern certificate or every common end-entity certificate. Their order is qualitative, not telemetry-derived.

### 2.1 Core certificate fields

| Field | OID | PowerShell prompt or behavior | Allowed and recommended value | Scenario status | Notes |
|---|---|---|---|---|---|
| Version | N/A | **Do not prompt.** Set X.509 v3. | Encoded version value `2` (displayed as v3). | **M-RFC:** all profiles in this reference. | Extensions are available only in v3. Public TLS, public S/MIME, and CA/B code-signing profiles require v3. |
| Serial number | N/A | **Do not prompt.** `Generate a unique certificate serial number.` | Positive, unique per issuer, no more than 20 octets. Default: 128 random bits with the high bit cleared and a nonzero result. Public-trust profiles require a non-sequential value below `2^159` with at least 64 CSPRNG-derived bits. | **M-RFC:** all; stricter **M-CABF:** TLS-PUB, SMIME public, CODE public, TSA public. | Do not use a timestamp, counter, hash prefix, or user-entered serial as the only entropy source. |
| Validity (`notBefore`, `notAfter`) | N/A | `When should the certificate become valid?` and `How long should it remain valid?` | Store UTC. Allow small backdating only to absorb clock/enrollment skew. Default private leaf: 365 days; short-lived workload: minutes to hours; private CA lifetime must be an explicit PKI policy decision. | **M:** all. | At the cutoff, TLS-PUB subscriber maximum is 200 days; 100 days applies 15 Mar 2027 and 47 days 15 Mar 2029. Public S/MIME Strict/Multipurpose maximum is 825 days. Public CODE issued from 1 Mar 2026 has a 460-day maximum. TSA certificate maximum is 135 months, but its key may be used for at most 15 months. Never default to the exact public maximum; leave time for rounding. |
| Subject Public Key Info: algorithm and key | Algorithm-specific | `Choose the subject public-key algorithm.` | Microsoft-compatible default: RSA 3072 for broad interoperability or ECDSA P-256 where all consumers are known to support it. Minimum general Microsoft RSA: 2048. See algorithm table below. | **M:** all. | The certificate contains only the public key. Provider, TPM/HSM storage, and exportability are creation controls, not certificate fields. |
| TBS signature algorithm | Algorithm-specific | `Choose the issuer signature algorithm.` Usually derive from issuer key and policy. | Default RSA issuer: SHA-256 with PKCS#1 v1.5 where required for compatibility; prefer RSA-PSS only after consumer testing. ECDSA P-256: SHA-256; P-384: SHA-384. EdDSA and pure ML-DSA do not take a separate external hash choice. | **M:** all. | The inner `tbsCertificate.signature` and outer `signatureAlgorithm` must match. SHA-1 and MD5 are prohibited defaults. |
| Issuer | X.500 Name; component OIDs below | **Do not prompt for an issued certificate.** Copy the issuing certificate's Subject exactly. For a root, derive from the new root Subject. | Nonempty issuer DN. | **M-RFC:** all. | It identifies the signing CA, not the owner of the leaf. A self-issued certificate is not automatically a trusted root. |
| Subject | X.500 Name; component OIDs below | `Enter the certified identity (or leave empty when the selected profile permits SAN-only identity).` | Use only verified identity attributes. For modern TLS service identity, SAN is authoritative. Empty Subject is permitted only when the profile supports it and SAN is present and critical. | **M/C:** see Subject table. | Avoid stuffing DNS names, IP addresses, UPNs, or unverified labels into CN. AD templates should prefer identity from AD DS rather than requester-supplied values. |
| Certificate signature value | N/A | **Do not prompt.** Produced by issuer signing operation. | Must verify over the DER-encoded `tbsCertificate` using the declared algorithm. | **M:** all. | A builder should fail if signing cannot be completed; it must never emit a partially signed artifact. |

### 2.2 Public-key and signature algorithm choices

| Choice | OID(s) | Friendly prompt | Recommended use | Constraints and compatibility |
|---|---|---|---|---|
| RSA public key | `rsaEncryption` `1.2.840.113549.1.1.1` | `Use RSA for maximum compatibility?` | Default when targeting mixed Windows versions, smart cards, network appliances, or unknown clients. Use 3072 bits when practical; 2048 is Microsoft's general minimum and remains common for TLS leaves. CA keys should normally be stronger and hardware-protected. | RSA supports signatures and key transport. Do not infer that `keyEncipherment` is needed merely because the key is RSA. TLS 1.3 needs `digitalSignature`; static RSA key exchange is obsolete. |
| RSA-PSS signature | `rsassaPss` `1.2.840.113549.1.1.10` | `Use RSA-PSS signatures?` | Modern signature profile after testing all Windows, appliance, boot, smart-card, and library consumers. | Parameters are part of the algorithm identifier and must be encoded consistently. PKCS#1 v1.5 remains the broad Microsoft compatibility choice for certificate signatures. |
| SHA-256 with RSA | `1.2.840.113549.1.1.11` | Normally derived | Broad default for RSA certificates. | SHA-256 is the floor, not a reason to retain RSA-2048 for long-lived CA keys. |
| SHA-384 with RSA | `1.2.840.113549.1.1.12` | Normally derived | Suitable with stronger RSA keys and longer-lived CA profiles. | Verify legacy consumer support. |
| ECDSA public key | `id-ecPublicKey` `1.2.840.10045.2.1` | `Use an ECDSA key?` | Efficient modern TLS, mTLS, signing, and private PKI where consumers are controlled. Default curve P-256; use P-384 where policy requires more security margin. | Named curves: P-256 `1.2.840.10045.3.1.7`, P-384 `1.3.132.0.34`, P-521 `1.3.132.0.35`. No `keyEncipherment`. Some Microsoft product profiles explicitly require RSA. |
| ECDSA with SHA-256 / SHA-384 | `1.2.840.10045.4.3.2` / `1.2.840.10045.4.3.3` | Normally derived | Match P-256 with SHA-256 and P-384 with SHA-384 by default. | Public TLS permits supported EC profiles; validate current CA policy. |
| Ed25519 / Ed448 | `1.3.101.112` / `1.3.101.113` | `Use EdDSA? (advanced)` | Controlled OpenSSL/Linux ecosystems, modern S/MIME profiles, and Sigstore where supported. | Parameters must be absent. Windows and many network/security products have uneven support; do not offer as a Microsoft default. Signature-only: `digitalSignature`, never encipherment. |
| ML-DSA-44 / 65 / 87 | `2.16.840.1.101.3.4.3.17` / `.18` / `.19` | `Use pure ML-DSA? (experimental/controlled deployment)` | Specialized Windows Server 2025 AD CS deployments after full chain and relying-party tests. | Microsoft support requires Windows Server 2025 with the May 2026 update or later and current Windows 11 clients. ML-DSA is signature-only, uses CNG, has no separate hash selection, and is not a general compatibility default. Composite ML-DSA was still planned, not available, at the cutoff. |

### 2.3 Subject distinguished-name attributes

Subject is a sequence of RDNs, not a flat display string. Preserve escaping and ordering through a proper X.500-name API.

| Attribute | OID | Friendly prompt | Recommended use and validation |
|---|---|---|---|
| Common Name (`CN`) | `2.5.4.3` | `Common/display name (not a TLS identity):` | Optional for many modern leaves. For TLS, do not validate service identity from CN; put DNS/IP identity in SAN. A private Microsoft product may still display or search CN, so mirroring the primary DNS SAN can be a tested compatibility aid, not the security identity. |
| Organization (`O`) | `2.5.4.10` | `Verified organization name:` | Include only when verified or in a controlled enterprise PKI. Public DV TLS must not invent organization identity. |
| Organizational Unit (`OU`) | `2.5.4.11` | `Verified organizational unit (optional):` | Optional and frequently overused. Do not encode authorization decisions in an easily changed OU string. Public profiles restrict or validate its use. |
| Country (`C`) | `2.5.4.6` | `Two-letter country code (optional):` | Exactly two ISO 3166-1 letters when present. |
| State/Province (`ST`) | `2.5.4.8` | `Verified state or province (optional):` | Use only with an identity-bearing profile. |
| Locality (`L`) | `2.5.4.7` | `Verified locality (optional):` | Use only with an identity-bearing profile. |
| Serial number attribute | `2.5.4.5` | `Verified subject registration identifier (optional):` | This is a Subject identity attribute, not the certificate serial number. Follow the applicable S/MIME/identity profile. |
| Given name / surname | `2.5.4.42` / `2.5.4.4` | `Verified given name:` / `Verified surname:` | Relevant to individual or sponsor-validated S/MIME and enterprise identity profiles. Do not derive from an untrusted display name. |
| Email address in DN | `1.2.840.113549.1.9.1` | Do not offer by default | Legacy compatibility only. Modern S/MIME mailbox identity belongs in SAN `rfc822Name` or `id-on-SmtpUTF8Mailbox`. |

**Scenario status:** Subject is nonempty for **ROOT/SUBCA (M)** and normally for identity-bearing **CODE/DOC/SMIME (M/C)**. It may be empty for **TLS-PUB, TLS-PRV, mTLS, WORKLOAD, SIGSTORE (O/C)** only when SAN carries the identity and is critical. **DC-KDC** Microsoft templates may use an empty Subject and a DNS SAN. **AD-USR** may need a DN hint in specific Windows Hello certificate-trust deployments.

## 3. Common v3 extensions

### 3.1 Subject Alternative Name (SAN)

**Extension OID:** `2.5.29.17`  
**Friendly prompt:** `Add the identities this certificate is allowed to represent.`  
**Criticality:** Non-critical when Subject is nonempty; **critical when Subject is empty**.  
**Status:** **TLS-PUB M-CABF**, **TLS-PRV M-BP**, **EAP-C/S M-MS**, **AD-USR M/C-MS**, **DC-KDC M-MS**, **SMIME M-CABF/RFC**, **WORKLOAD M**, **SIGSTORE M**.

| SAN name form | OID/type | Friendly prompt | Allowed/recommended values | Scenarios and caveats |
|---|---|---|---|---|
| DNS name | `dNSName` | `DNS name the service answers as:` | FQDN in A-label form for internationalized labels. Wildcard only as the complete leftmost label, for example `*.example.com`; prefer explicit names. | **TLS-PUB M** (at least DNS or IP); **TLS-PRV M-BP**; **EAP-S M-MS**; **DC-KDC M-MS**. RFC 9525 forbids CN as the service identity. |
| IP address | `iPAddress` | `Exact IPv4 or IPv6 service address:` | Encode raw 4- or 16-octet address, not a text string and not a CIDR range. | **TLS C** when clients connect by literal IP. Public TLS validation and policy rules apply. |
| Email mailbox | `rfc822Name` | `ASCII mailbox address:` | Valid mailbox with an ASCII local part. | **SMIME M/C**. Do not use it as an AD strong mapping. It is a weak/reusable name. |
| International mailbox | `otherName` `id-on-SmtpUTF8Mailbox` `1.3.6.1.5.5.7.8.9` | `Internationalized mailbox address:` | UTF-8 mailbox encoded per the current RFC 9598 update to RFC 8398. | **SMIME M/C** when the local part is non-ASCII. |
| URI | `uniformResourceIdentifier` | `URI identity:` | Absolute URI in the syntax required by the consuming profile. Do not treat an arbitrary URI as a TLS DNS identity. | **WORKLOAD M** for SPIFFE; **INTUNE C** for SID mapping; also protocol-specific URI identities. |
| Microsoft UPN | `otherName` `1.3.6.1.4.1.311.20.2.3` | `User principal name (UPN):` | ASN.1 UTF8 string containing the actual AD UPN. | **AD-USR M/C-MS**, smart-card logon and **EAP-C M-MS** for user certificates. UPN alone is not a current AD strong mapping. |
| Intune SCEP SID URI | URI value, not a distinct extension OID | **Derive**, do not free-type: `{{OnPremisesSecurityIdentifier}}` | `tag:microsoft.com,2022-09-14:sid:<SID>` in a URI SAN. | **INTUNE C/M-MS** for **SCEP** user certificates authenticating to an AD KDC; device support is for Entra hybrid-joined Windows devices. Intune PKCS uses the SID security extension instead; see below. |
| SPIFFE ID | URI form | `SPIFFE ID:` | Exactly one URI SAN such as `spiffe://trust-domain/workload/path`. | **WORKLOAD M-SPIFFE**. Leaf X.509-SVID may contain other SAN types but exactly one URI SAN/SPIFFE ID. Subject may be empty, making SAN critical. |
| Directory name | `directoryName` | `Alternative X.500 directory name (advanced):` | Properly encoded, verified DN. | Specialized S/MIME or directory profiles. Avoid duplicating unvalidated Subject data. |
| SRV name | `otherName` `id-on-dnsSRV` `1.3.6.1.5.5.7.8.7` | `Restricted service name (advanced):` | `_service.domain.example` as defined by the consuming protocol. | Standards-based service scoping. Support is much less universal than DNS SAN. |

**Microsoft/Linux difference:** Modern OpenSSL and RFC 9525 use SAN for TLS identity and reject reliance on CN in strict configurations. Some Microsoft documentation for LDAPS still accepts the DC FQDN in either Subject CN or DNS SAN. Generate DNS SAN and, only if a tested older Microsoft consumer needs it, mirror it in CN. Never generate CN-only TLS certificates.

### 3.2 Key Usage

**Extension OID:** `2.5.29.15`  
**Friendly prompt:** `Select the cryptographic operations allowed for this key.`  
**Criticality:** Default **critical**. Public TLS recommends/requires critical when present; CA, public code-signing, SPIFFE, and OCSP profiles require it critical.

| Bit | Friendly option | Use | Mandatory/optional scenarios |
|---|---|---|---|
| `digitalSignature` | `Sign authentication data or content` | Entity authentication, TLS 1.3 handshake signatures, mTLS, code/document/email signing, OCSP and timestamp responses. | **TLS-PUB ECDSA M; RSA recommended**, **mTLS/EAP/AD-USR/DC-KDC/CODE/DOC/TSA/OCSP/WORKLOAD/SIGSTORE M**. |
| `contentCommitment` (`nonRepudiation`) | `Create commitment/non-repudiation signatures` | A policy/legal assertion, not a stronger algorithm. | **SMIME/DOC O** where the governing profile expects it. **TLS-PUB X**. Do not set automatically for ordinary signatures. |
| `keyEncipherment` | `Unwrap transported session/content keys` | RSA key transport, S/MIME key management, and some older Microsoft TLS profiles. | **SMIME RSA encryption M**; **DC-KDC M-MS**; **TLS-PUB RSA O but normally unnecessary for modern TLS**. Never set for ECDSA, EdDSA, or ML-DSA. |
| `dataEncipherment` | `Encrypt application data directly (legacy)` | Direct bulk-data encryption with the public key. | **A** almost everywhere. Public TLS currently says not recommended. S/MIME legacy multipurpose profiles may permit it, but use `keyEncipherment` for RSA content-encryption-key transport. |
| `keyAgreement` | `Perform key agreement` | Static DH/ECDH key agreement or S/MIME EC key management. | **SMIME EC encryption M/C**; **TLS-PUB ECC A/not recommended**; not required for ephemeral TLS ECDHE when the certificate key signs. |
| `keyCertSign` | `Sign certificates` | CA signing. | **ROOT/SUBCA M** and only when Basic Constraints has `cA=true`; **X** for leaves. |
| `cRLSign` | `Sign CRLs` | CRL signing. | **ROOT/SUBCA M** when the key signs CRLs; normally set with `keyCertSign`. **X** for ordinary leaves. |
| `encipherOnly` / `decipherOnly` | `Restrict a key-agreement key to encipher/decipher` | Refines `keyAgreement`. | **SMIME EC O/C** only when `keyAgreement` is set. **X** otherwise. |

When both KU and EKU exist, the permitted use is their intersection. A script must reject contradictory combinations, such as ECDSA plus `keyEncipherment`, a leaf plus `keyCertSign`, or TSA EKU without `digitalSignature`.

### 3.3 Extended Key Usage (EKU)

**Extension OID:** `2.5.29.37`  
**Friendly prompt:** `Select the application purposes for this certificate.`  
**Criticality:** Normally non-critical for Microsoft interoperability. Exceptions include RFC 3161 TSA certificates, whose sole timestamping EKU is critical.  
**Default:** Choose the narrowest purpose set. Do not silently add Client Authentication to every certificate.

| Purpose | OID | Friendly option | Scenario status and recommended use |
|---|---|---|---|
| TLS server authentication | `1.3.6.1.5.5.7.3.1` | `Authenticate a TLS server` | **TLS-PUB M-CABF; TLS-PRV/EAP-S M-MS/BP; DC-KDC M-MS.** IIS, LDAPS, NPS/RADIUS, internal HTTPS, and similar services. |
| TLS client authentication | `1.3.6.1.5.5.7.3.2` | `Authenticate a TLS client, user, or device` | **mTLS/EAP-C/INTUNE M/C; DC-KDC M-MS.** Public TLS server certificates may include it, but separation is preferable. Public S/MIME may include it only in allowed multipurpose profiles and, from 1 Jul 2027, it is the sole optional extra EKU. |
| Code signing | `1.3.6.1.5.5.7.3.3` | `Sign executable code or software artifacts` | **CODE/SIGSTORE M.** Use only with `digitalSignature`. Public code-signing keys require current hardware protection rules. |
| Email protection | `1.3.6.1.5.5.7.3.4` | `Sign or encrypt S/MIME email` | **SMIME M.** Use KU to distinguish signing, encryption/key management, or dual use. Prefer separate signing and encryption certificates for lifecycle and archival reasons. |
| Timestamping | `1.3.6.1.5.5.7.3.8` | `Operate an RFC 3161 timestamp authority` | **TSA M**, must be the sole EKU and critical under RFC 3161. Do not put it on a normal code-signing certificate. |
| OCSP signing | `1.3.6.1.5.5.7.3.9` | `Sign delegated OCSP responses` | **OCSP M.** The responder certificate must be issued directly by the CA for which it responds under RFC 6960. |
| Smart-card logon | `1.3.6.1.4.1.311.20.2.2` | `Allow Windows smart-card sign-in` | **AD-USR M/C-MS.** Pair with `digitalSignature`, UPN SAN, current strong mapping, and usually Client Authentication. |
| KDC authentication | `1.3.6.1.5.2.3.5` | `Authenticate an Active Directory KDC` | **DC-KDC M-MS** for strict Windows Hello/Entra-joined scenarios; use with Server Authentication and Client Authentication per Microsoft's Kerberos Authentication template guidance. |
| General document signing | `1.3.6.1.5.5.7.3.36` | `Sign human-readable documents (standards profile)` | **DOC M/C** for applications supporting RFC 9336. Prefer this outside a vendor-controlled Microsoft Office PKI. |
| Microsoft Office document signing | `1.3.6.1.4.1.311.10.3.12` | `Sign Microsoft Office documents` | **DOC M/C-MS** for Microsoft Office policy. Microsoft documentation uses this OID. The current CA/B Code Signing BR displays `1.3.6.1.4.1.311.3.10.3.12`; do not substitute that value for Microsoft products without explicit relying-party confirmation. |
| IKE intermediate/IPsec | `1.3.6.1.5.5.8.2.2` | `Authenticate an IKE/IPsec peer (Microsoft compatibility)` | **IKE C-MS.** RFC 4945 recommends omitting EKU for pure IKE or using `id-kp-ipsecIKE` (`1.3.6.1.5.5.7.3.17`) when restriction is needed. Older IPsec end-system/tunnel/user EKUs are deprecated for IKE. Test the VPN product. |
| EFS encryption | `1.3.6.1.4.1.311.10.3.4` | `Encrypt files with Windows EFS` | **EFS M-MS.** Requires encryption-capable KU/key algorithm and key recovery planning. |
| EFS recovery | `1.3.6.1.4.1.311.10.3.4.1` | `Recover Windows EFS files` | **EFS recovery M-MS.** Highly privileged; separate template, key, operator, and protection. |
| Remote Desktop Authentication | `1.3.6.1.4.1.311.54.1.2` | `Restrict a certificate to Remote Desktop authentication` | **RDS C-MS/product-specific.** Use only when the RDS deployment explicitly requires it; ordinary RDP TLS commonly uses Server Authentication. |
| Certificate Request Agent | `1.3.6.1.4.1.311.20.2.1` | `Authorize enrollment on behalf of another subject` | **PKI-ADMIN M/C-MS.** Extremely privileged. Scope enrollment-agent restrictions, eligible templates, and operators; use a dedicated protected signing key. |
| Key Recovery Agent | `1.3.6.1.4.1.311.21.6` | `Authorize recovery of archived private keys` | **PKI-ADMIN M/C-MS.** Dedicated recovery role and protected key; do not combine with ordinary user purposes. |
| CA Exchange | `1.3.6.1.4.1.311.21.5` | `Protect key archival exchange with an AD CS CA` | **PKI-ADMIN C-MS.** CA-managed operational certificate; derive from AD CS policy rather than exposing as a general self-signed option. |
| Lifetime signing | `1.3.6.1.4.1.311.10.3.13` | `Limit Authenticode signature validity to certificate validity` | **CODE O/A.** It deliberately changes timestamp semantics; do not add unless policy explicitly calls for it. |
| Any Extended Key Usage | `2.5.29.37.0` | Do not offer normally | **A/X** for modern leaf profiles; forbidden by public TLS, public code-signing, and strict S/MIME profiles. Absence of EKU can also be broadly permissive in Windows, so omit EKU only when a documented profile requires omission. |

### 3.4 Basic Constraints

**Extension OID:** `2.5.29.19`  
**Friendly prompt:** `May this certificate issue other certificates?`  
**Defaults:** Leaf `cA=false`, no path length; CA `cA=true`.  
**Criticality:** **Critical for CA certificates.** For leaves, omit it or encode `cA=false` according to the application profile; public TLS permits it only as critical when present.

| Setting | Scenario status | Rule |
|---|---|---|
| `cA=true` | **ROOT/SUBCA M** | KU must contain `keyCertSign`. Never permit on an ordinary leaf. |
| `pathLenConstraint` absent | **ROOT O/BP; leaf M** | Root public profiles generally discourage a path length. Leaves must not contain it. |
| `pathLenConstraint=0` | **SUBCA C/BP** | Issuing CA may issue leaves but no non-self-issued subordinate CA below it. Count semantics are RFC 5280 path semantics, not a simple chain-length count. |
| `cA=false` | **Leaves O/C** | Clear statement that the certificate is an end entity. Some profiles omit the extension instead. |

### 3.5 Subject Key Identifier and Authority Key Identifier

| Extension | OID | Prompt/behavior | Status and criticality |
|---|---|---|---|
| Subject Key Identifier (SKI) | `2.5.29.14` | **Generate/derive:** `Create a key identifier from the subject public key.` | **ROOT/SUBCA M-RFC/profile**, common/recommended for most private leaves, non-critical. Public TLS subscriber profile currently says not recommended, so follow the issuing CA's profile. A SHA-1-derived SKI is an identifier, not a certificate signature; nevertheless allow a policy-defined derivation. |
| Authority Key Identifier (AKI) | `2.5.29.35` | **Derive:** copy the issuer's SKI into `keyIdentifier`. Root may copy its own SKI when the profile uses AKI. | **Issued certificates M/BP**, non-critical. Public TLS, public S/MIME, code-signing, and OCSP profiles require it. Do not ask a human to enter it. |

AKI/SKI assist path building but do not establish trust by themselves.

## 4. Common but infrastructure-dependent extensions

### 4.1 Authority Information Access (AIA)

**Extension OID:** `1.3.6.1.5.5.7.1.1`  
**Friendly prompt:** `Publish issuer-certificate or OCSP discovery URLs?`  
**Criticality:** Non-critical.

| Access method | OID | Recommended value | Scenario status |
|---|---|---|---|
| CA Issuers | `1.3.6.1.5.5.7.48.2` | Stable HTTP URL returning the issuing CA certificate. | **TLS-PUB SHOULD-CABF; private issued cert O/BP; CODE public M.** Do not put AIA on an offline root merely to point to itself. |
| OCSP | `1.3.6.1.5.5.7.48.1` | Stable HTTP OCSP responder URL. | **C** when the issuer operates OCSP; public profiles constrain content. **OCSP responder leaf A/X** when No Check is used. |

Windows can retrieve missing intermediates through AIA; OpenSSL deployments often require the server to send the chain and may not fetch AIA automatically. AIA is not a substitute for configuring IIS or another TLS server with its intermediate chain.

### 4.2 CRL Distribution Points (CDP)

**Extension OID:** `2.5.29.31`  
**Friendly prompt:** `CRL URL for certificates issued by this CA:`  
**Default:** Stable HTTP URL, non-critical.  
**Status:** **CODE public M**, **SMIME public M**, **CA-issued private certificates O/M-policy**, **DC-KDC M-MS unless OCSP AIA provides the accepted revocation path**, **OCSP delegated responder X in the current public TLS profile**.

Prefer HTTP for heterogeneous clients. AD CS often emits LDAP and HTTP; HTTP is usable by off-domain Windows and non-Windows clients. Never publish an unreachable internal LDAP URL as the only revocation source for certificates used externally.

### 4.3 Certificate Policies

**Extension OID:** `2.5.29.32`  
**Friendly prompt:** `Certificate policy OIDs asserted by this certificate:`  
**Criticality:** Normally non-critical.  
**Status:** **TLS-PUB, public SMIME, public CODE M-CABF**; private PKI **O/C**; roots frequently omit it.

Use only OIDs backed by a documented CP/CPS. Do not use `anyPolicy` (`2.5.29.32.0`) as a convenience default. Current public TLS DV/IV/OV/EV and public S/MIME profiles have reserved policy OIDs. Public code-signing subscribers issued from 15 September 2026 must contain exactly one applicable reserved policy OID.

### 4.4 Certificate Transparency extensions

| Extension | OID | Prompt/behavior | Use |
|---|---|---|---|
| Embedded SCT list | `1.3.6.1.4.1.11129.2.4.2` | **Issuer/CT workflow generated; do not prompt.** | Common in **TLS-PUB** and required by browser/root-program policy where applicable; also used by Sigstore/Fulcio. Non-critical. |
| Precertificate poison | `1.3.6.1.4.1.11129.2.4.3` | **CT workflow only; never copy into final certificate.** | Critical extension in a precertificate. A final certificate containing it is invalid for ordinary use. |

Private enterprise TLS does not gain security merely by copying public CT extensions without an operated log and verification policy.

### 4.5 TLS Feature / OCSP Must-Staple

**Extension OID:** `1.3.6.1.5.5.7.1.24`  
**Friendly prompt:** `Require the TLS server to staple an OCSP response? (advanced)`  
**Value:** `status_request` feature `5`; non-critical.  
**Status:** **TLS O**, but enable only when the server reliably staples fresh responses and every operational path is monitored. Client enforcement is inconsistent, especially outside browsers. It is not a workaround for an unreliable responder.

## 5. Scenario-specific and Microsoft extensions

### 5.1 AD object SID security extension

**Extension OID:** `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`)  
**Contained SID type OID:** `1.3.6.1.4.1.311.25.2.1`  
**Prompt:** **Do not free-type.** `Derive the AD object SID from the authenticated enrollment identity.`  
**Criticality:** Non-critical.  
**Status:** **AD-USR/DC authentication C/M-MS** for certificates issued by updated AD CS and mapped by the KDC.

The SID binds the certificate to the AD object used to construct its subject. Treat requester-supplied SID values as hostile. On updated domain controllers, full strong-mapping enforcement is the normal state. The `StrongCertificateBindingEnforcement` compatibility switch has been unsupported since the 9 September 2025 Windows update.

If a certificate cannot be reissued with the SID extension, Microsoft's supported migration alternative is a strong explicit `altSecurityIdentities` mapping using Issuer+Serial, SKI, or SHA-1 of the public key. Issuer+Subject, Subject-only, and RFC822 mappings are weak and must not be presented as equivalent.

### 5.2 Intune strong-mapping URI

This is a SAN URI value, not a new extension OID:

```text
tag:microsoft.com,2022-09-14:sid:<on-premises-SID>
```

Prompt by profile variable rather than literal text: `Add {{OnPremisesSecurityIdentifier}} for AD KDC strong mapping?` Microsoft Intune documents this URI mechanism for **SCEP** user certificates on supported platforms and for hybrid-joined Windows device certificates. The user or device must be synchronized from on-premises AD. Confirm third-party CA support for the URI tag.

For **Intune PKCS**, Certificate Connector 6.2406.0.1001 or later can add the SID security extension (`1.3.6.1.4.1.311.25.2`) when `EnableSidSecurityExtension=1` is configured on the connector. Model SCEP URI mapping and PKCS extension mapping as separate enrollment capabilities.

### 5.3 AD CS certificate-template identification

| Extension | OID | Behavior | Use |
|---|---|---|---|
| Certificate Template Name | `1.3.6.1.4.1.311.20.2` | **Derive from AD CS template; do not let a generic self-signed workflow claim an enterprise template.** | Legacy/v1 template name encoded as a BMPString. Kerberos Authentication templates may carry `DomainController` here. |
| Certificate Template Information | `1.3.6.1.4.1.311.21.7` | **Derive from AD CS issuance.** | Template OID and version information for newer templates. Non-critical. |

These extensions describe issuance policy; adding them to an unrelated self-signed certificate does not grant enrollment or domain-controller semantics.

### 5.4 OCSP No Check

**Extension OID:** `1.3.6.1.5.5.7.48.1.5`  
**Friendly prompt:** `Trust this delegated responder for its certificate lifetime without recursively checking its revocation?`  
**Value:** ASN.1 NULL; non-critical.  
**Status:** **OCSP M** in the current public TLS responder profile; otherwise **X/A**.

Use a dedicated, short-lived responder certificate and protect the key as seriously as a CRL-signing key. Never add No Check to ordinary server, client, signing, or CA certificates.

### 5.5 S/MIME capabilities

**OID:** `1.2.840.113549.1.9.15`  
**Friendly prompt:** `Advertise S/MIME cryptographic capabilities?`  
**Criticality:** Non-critical.  
**Status:** **SMIME O**. It can advertise algorithms a recipient supports; it is not a replacement for KU/EKU and should be emitted only by an S/MIME-aware implementation.

### 5.6 Freshest CRL

**Extension OID:** `2.5.29.46`  
**Friendly prompt:** `Delta CRL distribution point (advanced):`  
**Criticality:** Non-critical.  
**Status:** **O/C** only when the PKI publishes correct base and delta CRLs and all important relying parties support them. HTTP publication is preferable for heterogeneous estates.

## 6. Specialized CA and policy extensions

These are low-frequency and should be hidden behind an advanced CA-profile mode.

| Extension | OID | Prompt/default | Rules and scenarios |
|---|---|---|---|
| Name Constraints | `2.5.29.30` | `Permitted and excluded subordinate namespaces:` | **SUBCA O/C**, normally critical. Never in an end-entity certificate. Use to constrain DNS, email, IP, directory, or supported URI namespaces. Test Windows and OpenSSL path validation; URI constraints have known ecosystem gaps, including SPIFFE. |
| Policy Mappings | `2.5.29.33` | `Map issuer-domain policy OIDs to subject-domain policy OIDs:` | **SUBCA rare.** Never map to/from `anyPolicy`. Used in cross-certification, not normal enterprise issuance. |
| Policy Constraints | `2.5.29.36` | `Require explicit policy or inhibit policy mapping after N certificates:` | **SUBCA rare**, critical when present under RFC 5280. Many applications have limited operational testing. |
| Inhibit anyPolicy | `2.5.29.54` | `Stop anyPolicy processing after N certificates:` | **SUBCA rare**, critical. Use only in a designed policy hierarchy. |
| Issuer Alternative Name | `2.5.29.18` | Do not offer normally | Rare; it does not replace Issuer DN or AKI and is poorly useful in modern general PKI. |
| Subject Directory Attributes | `2.5.29.9` | `Verified subject attributes (specialized):` | Specialized identity/qualified-certificate use. Prohibited by strict and multipurpose public S/MIME profiles at the cutoff. |
| Private Key Usage Period | `2.5.29.16` | Do not offer | Obsolete/poorly interoperable. Control key lifetime operationally and with certificate validity. |

## 7. Modern specialized profiles

### 7.1 SPIFFE X.509-SVID

For a leaf SVID: v3; short lifetime; empty Subject is allowed; exactly one URI SAN containing the SPIFFE ID; SAN critical if Subject is empty; Basic Constraints `cA=false`; critical KU with `digitalSignature`; EKU should contain both Server Authentication and Client Authentication. `keyEncipherment` or `keyAgreement` is optional only where the chosen TLS/key algorithm needs it. CA/signing SVIDs use `cA=true`, critical `keyCertSign`, optional `cRLSign`, and must not be used as workload authentication leaves.

### 7.2 Sigstore/Fulcio leaf

Fulcio's profile uses an empty Subject, exactly one identity SAN, critical KU containing only `digitalSignature`, EKU containing only Code Signing, SKI, AKI, a short lifetime, and CT proof/SCT. OIDC issuer and CI provenance use Sigstore's private extension arc `1.3.6.1.4.1.57264.1.*`; for example issuer v2 is `.1.8`. These fields are generated from a validated OIDC token, never typed by the certificate subject. Do not add Sigstore extensions to ordinary Authenticode certificates.

### 7.3 IKE/IPsec

Match the IKE identity to SAN: FQDN as `dNSName`, address as `iPAddress`, user FQDN as `rfc822Name`, or DN as Subject. KU, when present, must permit signature (`digitalSignature` or `contentCommitment`). RFC 4945 deprecates the old IPsec end-system (`1.3.6.1.5.5.7.3.5`), tunnel (`.6`), and user (`.7`) EKUs for IKE. Pure IKE certificates generally omit EKU; Microsoft and particular VPN products may require `1.3.6.1.5.5.8.2.2`. Make the VPN product/profile an explicit selection.

## 8. Deprecated, unsafe, or misleading choices

| Choice | Disposition |
|---|---|
| X.509 v1/v2 leaf or CA certificates | Do not generate. Modern profiles require v3 extensions. |
| `issuerUniqueID` / `subjectUniqueID` | Omit. Public profiles forbid them and modern identity belongs in Subject/SAN/SKI. |
| CN-only TLS identity | Reject. Generate the correct DNS/IP SAN. |
| SHA-1, MD5, MD2 signatures | Reject for new certificates. Current public profiles have sunset SHA-1. |
| RSA below 2048 bits, DSA, obsolete curves | Reject by default. Permit only in a separately named forensic/legacy inspection mode that cannot issue production certificates. |
| `Any Purpose` EKU or Microsoft Any Application Policy | Do not offer in the normal wizard. Use narrowly scoped EKUs. |
| No EKU on a general Windows leaf | Do not use as a shortcut: Windows can interpret absence broadly. Omit only when the selected protocol explicitly calls for it, such as a tested IKE profile. |
| Multipurpose server+client+code+email certificate | Reject. It increases cross-protocol risk and conflicts with public profiles. A domain-controller profile is a documented Microsoft exception with a narrow set of authentication EKUs. |
| Self-signed operational leaf copied into Root/TrustedPublisher | Do not default. A self-signed certificate conveys no identity trust on its own and has poor revocation/renewal properties. Use a managed CA or explicit pinning for a controlled test. |
| Weak AD mappings by Subject, Issuer+Subject, UPN, or email | Do not recommend. Use the AD SID extension/Intune SID URI or a strong explicit mapping. |
| `StrongCertificateBindingEnforcement` compatibility/disabled modes | Historical only. The registry value is unsupported after the September 2025 Windows update. |
| Netscape certificate type/comment extensions | Omit. Use KU, EKU, SAN, and standard extensions. |
| Requester-supplied SAN on a broadly enrollable AD CS template | High-risk. Derive from AD DS or tightly restrict enrollment, approval, and permitted names. |

## 9. Scenario minimums and defaults

This compact check ensures that the field catalog can reconstruct each covered profile. `+` means add the listed fields to the universal core fields.

| Scenario | Minimum profile assembled from this catalog |
|---|---|
| Public TLS server | SAN DNS/IP; Server Authentication EKU; AKI; Certificate Policies; normally critical KU with `digitalSignature`; optional RSA `keyEncipherment` only for justified legacy compatibility; AIA/CDP per current BR; CT workflow; Basic Constraints absent or critical `cA=false`; validity at most 200 days at cutoff. |
| Private TLS/IIS/SQL/internal API | DNS/IP SAN; Server Authentication EKU; critical KU `digitalSignature`; RSA fallback as needed; AKI/SKI; reachable AIA/CDP when CA-issued. |
| LDAPS/DC/KDC | DNS SAN for DC FQDN/domain; Server Auth + Client Auth + KDC Auth EKUs for Kerberos Authentication profile; KU Digital Signature + Key Encipherment; valid CRL or OCSP; RSA-2048/SHA-256 where Microsoft's strict WHfB profile requires it; Local Computer store. |
| General mTLS client | Identity SAN appropriate to application; Client Authentication EKU; KU `digitalSignature`; short validity and revocation or automated renewal; never reuse a public server certificate. |
| EAP-TLS user/device | Client Authentication EKU; `digitalSignature`; user UPN SAN for user auth or policy-approved device identity; CA chain trusted by NPS; current strong AD mapping if KDC mapping is involved. Server side uses Server Authentication and FQDN SAN. |
| Smart card / AD logon | Smart Card Logon and usually Client Authentication EKUs; `digitalSignature`; UPN SAN; AD SID extension or supported Intune SID URI/strong mapping; hardware-backed non-exportable key; issuing CA in NTAuth where required. |
| Intune SCEP/PKCS | User or device identity SAN; Client Authentication for common auth scenarios; KU dictated by purpose; for AD KDC strong mapping use the `{{OnPremisesSecurityIdentifier}}` URI in SCEP or the SID security extension through the current PKCS connector; supported key size/provider per target OS. |
| S/MIME signing | Mailbox SAN; Email Protection EKU; critical/recommended KU `digitalSignature`, optional `contentCommitment`; public profile policy, AKI, CDP/AIA; prefer separate signing key. |
| S/MIME encryption | Mailbox SAN; Email Protection EKU; RSA `keyEncipherment` or EC `keyAgreement`; escrow/recovery policy where lawful and required; prefer a separate encryption certificate. |
| Code signing | Code Signing EKU; critical KU `digitalSignature`; identity Subject; AKI, AIA, CDP, policy OID for public trust; hardware-protected key under current public rules; timestamp signatures. |
| Document signing | KU `digitalSignature`, optionally `contentCommitment`; RFC 9336 Document Signing EKU or Microsoft's Office OID depending on consumer; verified signer Subject. Do not repurpose email/code certificates by default. |
| Timestamp authority | Sole, critical Timestamping EKU; critical KU `digitalSignature`; dedicated protected key; public profile policy/AIA/CDP/AKI; key-use window separate from certificate lifetime. |
| Delegated OCSP responder | OCSP Signing EKU; critical KU `digitalSignature`; AKI; OCSP No Check where profile requires it; short lifetime; no SAN; not a CA. |
| Root CA | Self-issued; `cA=true`; critical KU `keyCertSign,cRLSign`; SKI; optional matching AKI; no EKU; offline/hardware-protected key and explicit long-term algorithm policy. |
| Issuing/subordinate CA | Issuer/Subject; `cA=true` and chosen path length; critical KU `keyCertSign,cRLSign`; SKI/AKI; AIA/CDP; policies and optional constraints; EKU only where a deliberately constrained CA profile requires it. |
| IKE/IPsec VPN | SAN matching IKE identity; signature KU; EKU absent under generic RFC profile or product-required IKE EKU; AIA/CDP appropriate to connectivity. |
| SPIFFE workload | Exactly one SPIFFE URI SAN; short lifetime; critical `digitalSignature`; both server/client EKUs; `cA=false`; empty Subject permitted with critical SAN. |
| Sigstore/Fulcio | Empty Subject; one identity SAN; critical KU `digitalSignature`; only Code Signing EKU; SKI/AKI; OIDC-derived extensions; very short validity; CT proof/SCT. |
| Windows EFS/recovery | EFS or EFS Recovery EKU; encryption-capable algorithm/KU; distinct user and recovery keys; archival and access policy. |
| Remote Desktop | DNS SAN; Server Authentication EKU for TLS; optionally product-specific Remote Desktop Authentication EKU only when the deployment requires it. |
| AD CS enrollment/key recovery | Dedicated Certificate Request Agent, Key Recovery Agent, or CA Exchange EKU as applicable; `digitalSignature` or encryption KU consistent with the role; narrowly scoped template permissions; protected, nonmultipurpose key. |

## 10. Creation controls not encoded as certificate fields

A PowerShell implementation should model these separately:

| Control | Recommended prompt/default |
|---|---|
| Key storage provider | Prefer a CNG Key Storage Provider. Use legacy CSP only for a documented consumer requirement. The current script's `Microsoft RSA SChannel Cryptographic Provider` is legacy-oriented. |
| User/computer/service context | Ask which runtime identity must access the key. Do not equate administrator elevation with the correct certificate store. |
| Exportability | Default non-exportable. Permit export only for an explicit backup/migration workflow; code-signing public keys and privileged identity keys may require hardware protection. |
| Hardware/TPM/HSM/smart card | Prefer hardware-backed keys for smart-card logon, privileged authentication, CA, public code-signing, and TSA. Verify supported algorithms and sizes. Intune notes that Windows TPM and Windows Hello do not store RSA-4096 keys. |
| Key reuse on renewal | Default new key for ordinary leaves; use same-key renewal only when a documented protocol/template requires it. |
| Trust installation | Never automatically place an arbitrary self-signed leaf in Root. Trust anchors require a separate, privileged, explicit action and policy. |
| Friendly name | Store metadata only; it is not an X.509 identity field and is not portable in a DER `.cer`. |
| Output format | DER/PEM certificate contains public data only; PFX/PKCS#12 contains private key and needs strong protection. Make the distinction explicit. |
| Revocation and renewal | A certificate with CDP/AIA still needs operated endpoints. Short-lived certificates need reliable automated renewal. Test failure behavior while offline. |

## 11. Cross-check against `Tools/New-X509v3Certificate.ps1`

The implementation was updated from this cross-check. Its external data model is `Tools/New-X509v3Certificate.Data.psd1`; the script consumes that data rather than embedding scenario/OID tables.

| Previous behavior | Implemented result |
|---|---|
| RSA-2048 and a legacy SChannel CSP only | RSA-2048/3072/4096 and ECDSA P-256/P-384/P-521 profiles use .NET/CNG. EdDSA and ML-DSA remain explicit, unsupported capabilities and never downgrade silently. |
| Fixed SHA-256 | Hash, key size, curve, and validity are scenario-derived and validated. |
| Subject CN and legacy DN email only | The request function accepts the modeled Subject attributes and SAN DNS, IP, URI, email, and Microsoft UPN forms. Empty Subject requires critical SAN. |
| Small unrestricted EKU menu, including Any Purpose | The wizard requires one of 25 frequency-sorted scenario profiles. Any Purpose is recognition-only; Microsoft smart-card, KDC, Office, IKE, EFS, RDS, and AD CS roles are modeled. |
| KU, constraints, identifiers, and PKI service extensions absent | Profiles add critical least-privilege KU, EKU, Basic Constraints, SKI, issuer/self AKI, OCSP No Check, and optional AIA, CDP, policy, TLS Feature, or caller-supplied typed extensions. |
| One-year self-signed only | `New-X509Certificate` supports purpose-specific validity, self-signed roots/test leaves, and direct issuer signing for subordinate/responder/specialized profiles. |
| Exportable key by default | Installed private keys default to non-exportable; the wizard makes exportability an explicit opt-in. |
| Self-signed code signer automatically inserted in Root and TrustedPublisher | Removed. Trust distribution stays a separate explicit administrative operation. |
| `.cer` export treated as the output workflow | DER/Base64 public export remains explicit. Protected PFX export and hardware-provider selection are intentionally left as separate future workflows rather than weakening defaults. |

## 12. Primary sources

- [RFC 5280 — Internet X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html) and its [current update index](https://www.rfc-editor.org/info/rfc5280/)
- [RFC 9525 — Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html)
- [RFC 9336 — General-Purpose Document Signing EKU](https://www.rfc-editor.org/rfc/rfc9336.html)
- [RFC 8550 — S/MIME 4.0 Certificate Handling](https://www.rfc-editor.org/rfc/rfc8550.html)
- [RFC 3161 — Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html)
- [RFC 6960 — Online Certificate Status Protocol](https://www.rfc-editor.org/rfc/rfc6960.html)
- [RFC 4945 — IKE/IPsec PKI Profile](https://www.rfc-editor.org/rfc/rfc4945.html)
- [CA/Browser Forum TLS Baseline Requirements, v2.3.0](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)
- [CA/Browser Forum S/MIME Baseline Requirements, v1.0.16](https://cabforum.org/working-groups/smime/requirements/)
- [CA/Browser Forum Code Signing Baseline Requirements, v3.11.0](https://cabforum.org/working-groups/code-signing/requirements/)
- [Microsoft SDL cryptographic recommendations](https://learn.microsoft.com/en-us/security/engineering/Cryptographic-Recommendations)
- [Microsoft AD CS certificate-template management](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates)
- [Microsoft Certificate Enrollment API extensions](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/extensions)
- [Microsoft EKU/Application Policy OIDs](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionmsapplicationpolicies)
- [Microsoft Intune SCEP certificate profiles](https://learn.microsoft.com/en-us/intune/device-configuration/certificates/scep-profiles)
- [Microsoft Intune PKCS certificate profiles](https://learn.microsoft.com/en-us/intune/device-configuration/certificates/pkcs-profiles)
- [Microsoft KB5014754 strong certificate mapping](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)
- [Microsoft AD SID security extension specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71)
- [Microsoft EAP-TLS certificate requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/certificate-requirements-eap-tls-peap)
- [Microsoft Kerberos/domain-controller certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/on-premises-key-trust)
- [Microsoft smart-card certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [Microsoft AD CS post-quantum cryptography](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/post-quantum-cryptography-overview)
- [OpenSSL X.509 v3 configuration reference](https://docs.openssl.org/4.0/man5/x509v3_config/)
- [SPIFFE X.509-SVID specification](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
- [Sigstore Fulcio certificate profile](https://github.com/sigstore/architecture-docs/blob/main/fulcio-spec.md)

## 13. Implementation-ready record shape

A future PowerShell implementation can normalize each catalog item to the following conceptual record:

```powershell
@{
    Name               = 'Server Authentication'
    Category           = 'ExtendedKeyUsage'
    Oid                = '1.3.6.1.5.5.7.3.1'
    FrequencyTier      = 'Common'
    Prompt             = 'Authenticate a TLS server'
    InputMode          = 'ScenarioDerived' # Prompt, Generated, Derived, Hidden
    AllowedValues      = @($true, $false)
    RecommendedDefault = $false
    Criticality        = 'NonCritical'
    Scenarios          = @{ 'TLS-PUB' = 'Mandatory'; 'TLS-PRV' = 'Mandatory'; 'CODE' = 'Forbidden' }
    Conflicts          = @('CodeSigningOnly', 'TimestampAuthorityOnly')
    Authority          = @('CA/B TLS BR 7.1.2.7.10', 'Microsoft product profile')
    Warning            = $null
}
```

Scenario selection should populate and constrain fields first; expert overrides should be validated against the same rules. This is safer and clearer than prompting independently for every extension and discovering contradictions only after issuance.
