# Modern X.509 v3 Certificate Field Reference Research Plan

**Research cutoff:** 16 October 2026  
**Implementation target:** A field catalog suitable for a future PowerShell certificate-creation and prompting tool.

## Summary

Produce a field-centric Markdown reference covering modern public and private TLS, mutual TLS, Microsoft and non-Microsoft identity and device authentication, Intune, IIS, NPS/EAP-TLS/Wi-Fi/VPN, smart cards and Kerberos, S/MIME, code and document signing, CA certificates, OCSP, timestamping, IPsec/IKE, and modern workload identities.

Use standards and vendor documentation current through the research cutoff. Public-trust requirements remain authoritative for publicly trusted certificates. Microsoft guidance takes precedence for private Windows scenarios when interoperable recommendations conflict; relevant Linux and OpenSSL differences are called out.

## Reference Structure

- Sort fields and selectable options into qualitative frequency bands: ubiquitous, common, scenario-specific, specialized/emerging, and deprecated/avoid. Do not invent numeric deployment percentages.
- Give each field or option:
  - its exact OID, or `N/A` for structural fields without an OID;
  - a friendly PowerShell prompt and whether it should be prompted, derived, or generated automatically;
  - allowed values and validation rules;
  - a recommended Microsoft-oriented default;
  - its critical/non-critical setting;
  - scenario applicability as Mandatory, Conditional, Optional, Forbidden, or Not applicable;
  - the basis for the requirement: RFC/X.509, CA/B Forum, Microsoft product requirement, or operational best practice;
  - Windows versus Linux/OpenSSL differences;
  - compatibility and workaround warnings;
  - primary-source links.
- Treat compound extensions as configurable child options: each Key Usage bit, relevant EKU OID, SAN name form, Subject DN attribute, AIA method, policy option, and CA constraint receives an actionable entry.
- Separate encoded certificate fields from adjacent creation-time controls such as private-key provider, hardware protection, exportability, Windows certificate store, enrollment method, and trust installation.

## Fields and Scenarios

- Structural fields: version, serial number, signature algorithm, issuer, validity, subject, Subject Public Key Info, and outer signature.
- Common extensions: SAN, Key Usage, EKU, Basic Constraints, SKI, AKI, AIA/OCSP/CA Issuers, CRL Distribution Points, Certificate Policies, Certificate Transparency SCTs, and TLS Feature.
- Specialized extensions: Name Constraints, Policy Constraints and Mapping, Inhibit anyPolicy, Freshest CRL, OCSP No Check, Issuer Alternative Name, Microsoft certificate-template identifiers, the AD object SID security extension, and applicable workload-identity identifiers.
- SAN choices: DNS, IP, RFC822 email, URI, UPN `otherName`, Intune SID URI, directory name, and modern service/workload identities.
- EKUs: server/client authentication, S/MIME, code/document signing, timestamping, OCSP signing, smart-card logon, KDC authentication, EFS/recovery, IKE, Remote Desktop, and documented Microsoft-specific usages. Discourage `Any Purpose` and unnecessary multipurpose certificates.
- Algorithms and validity: RSA, ECDSA, EdDSA where supported, emerging Windows Server 2025 ML-DSA/PQC support, SHA-2 choices, key sizes, validity limits, and algorithm-specific Key Usage restrictions.
- Low-frequency modern profiles: SPIFFE service identity and Sigstore/Fulcio supply-chain signing where they introduce distinct certificate fields.

## Compatibility and Workarounds

- Document current Windows strong certificate mapping: the AD SID security extension, Intune `OnPremisesSecurityIdentifier` URI SAN, and strong `altSecurityIdentities` mappings.
- Mark pre-September-2025 KDC compatibility registry settings as historical and unsupported, not actionable recommendations.
- Cover CN duplication for older clients, RSA compatibility fallback, parallel RSA/ECDSA certificates, separate S/MIME signing/encryption keys, HTTP versus LDAP revocation endpoints, absent-EKU interpretation, OCSP Must-Staple limitations, and short-lived certificates where revocation is unavailable.
- Identify deprecated or unsafe choices explicitly: CN-only TLS identity, SHA-1/MD5, weak keys, unrestricted `Any Purpose`, weak name-based AD mappings, Netscape extensions, inappropriate self-signed leaf trust, and obsolete X.509 unique identifiers.

## Sources and Acceptance Checks

- Base normative findings on RFC 5280 and applicable updates, RFC 9525 TLS service identity guidance, the relevant OCSP/timestamping RFCs, and the current CA/B Forum TLS, S/MIME, and Code Signing Baseline Requirements.
- Use current Microsoft Learn and Support documentation for AD CS, CertEnroll, Intune SCEP/PKCS, IIS, NPS/EAP-TLS, smart cards, Kerberos/Windows Hello for Business, strong mapping, cryptographic guidance, and PQC support. Use official OpenSSL documentation for Linux differences.
- Verify that every covered scenario can be reconstructed from the field catalog.
- Cross-check the catalog against `Tools/New-X509v3Certificate.ps1`, covering its existing EKUs while identifying missing SAN, Key Usage, Basic Constraints, identifier, algorithm, and validation controls. Do not modify the script.
- Ensure every recommendation is labeled by authority and every unsafe or obsolete workaround carries an explicit warning.
