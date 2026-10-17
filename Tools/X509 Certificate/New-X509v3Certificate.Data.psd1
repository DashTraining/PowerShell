@{
    SchemaVersion = '2.0'; ResearchCutoff = '2026-10-16'
    Defaults = @{ Context='User'; Algorithm='RSA'; RsaKeySize=3072; Curve='P256'; HashAlgorithm='SHA256'; ValidityDays=365; Exportable=$false }

    SubjectAttributes = @(
        @{ Name='CommonName'; ShortName='CN'; Oid='2.5.4.3'; Allowed='UTF-8 string'; Recommended='Human/device identity where the profile uses a nonempty Subject.'; Frequency=1 }
        @{ Name='Organization'; ShortName='O'; Oid='2.5.4.10'; Allowed='UTF-8 string'; Recommended='Verified legal/organizational identity when required.'; Frequency=2 }
        @{ Name='OrganizationalUnit'; ShortName='OU'; Oid='2.5.4.11'; Allowed='UTF-8 string'; Recommended='Optional; do not use as an authorization boundary.'; Frequency=3 }
        @{ Name='Country'; ShortName='C'; Oid='2.5.4.6'; Allowed='Two-letter ISO country code'; Recommended='Only when the issuing profile verifies it.'; Frequency=4 }
        @{ Name='Locality'; ShortName='L'; Oid='2.5.4.7'; Allowed='UTF-8 string'; Recommended='Optional verified identity.'; Frequency=5 }
        @{ Name='StateOrProvince'; ShortName='S'; Oid='2.5.4.8'; Allowed='UTF-8 string'; Recommended='Optional verified identity.'; Frequency=6 }
        @{ Name='EmailAddress'; ShortName='E'; Oid='1.2.840.113549.1.9.1'; Allowed='Mailbox'; Recommended='Prefer an rfc822Name SAN for modern mail identity.'; Frequency=7 }
    )

    SanTypes = @(
        @{ Name='DNS'; GeneralName='dNSName'; Tag=2; Input='DNS host name'; Recommended='Primary TLS server identity; no wildcard unless justified.'; Frequency=1 }
        @{ Name='IP'; GeneralName='iPAddress'; Tag=7; Input='IPv4 or IPv6 literal'; Recommended='Only when clients connect and validate by IP.'; Frequency=2 }
        @{ Name='Email'; GeneralName='rfc822Name'; Tag=1; Input='Mailbox'; Recommended='S/MIME identity.'; Frequency=3 }
        @{ Name='URI'; GeneralName='uniformResourceIdentifier'; Tag=6; Input='Absolute URI'; Recommended='Application/workload identity, including SPIFFE and Intune SID tag URI.'; Frequency=4 }
        @{ Name='UPN'; GeneralName='otherName'; Tag=0; Oid='1.3.6.1.4.1.311.20.2.3'; Input='user@realm'; Recommended='Microsoft AD user identity where the product profile requires it.'; Frequency=5 }
    )

    CreationControls = @{
        KeyStorageProvider='Prefer a CNG provider; a hardware/TPM/HSM/smart-card provider is scenario-dependent.'
        Exportability='Default non-exportable; enable only for an explicit backup or migration workflow.'
        KeyReuse='Default to a new key on renewal.'
        TrustInstallation='Never insert an arbitrary self-signed leaf into Root automatically.'
        Revocation='AIA/CDP values require operated, reachable services; short-lived profiles require reliable renewal.'
        Output='DER/PEM is public-only; PKCS#12/PFX contains a private key and needs separate protection.'
    }

    CompatibilityWorkarounds = @(
        @{ Name='RSA keyEncipherment'; Status='CompatibilityOnly'; AppliesTo=@('EAP-S','DC-KDC','RDS'); Note='Retained for Microsoft/product profiles that still require it; TLS 1.3 does not use RSA key transport.' }
        @{ Name='Microsoft IKE intermediate EKU'; Status='MicrosoftPreferred'; AppliesTo=@('IKE'); Alternative='RFC id-kp-ipsecIKE or absent EKU'; Note='Test the actual VPN peer.' }
        @{ Name='Microsoft Office document-signing EKU'; Status='MicrosoftPreferred'; AppliesTo=@('DOC'); Alternative='RFC 9336 id-kp-documentSigning'; Note='Choose for the validating application.' }
        @{ Name='Intune SCEP SID tag URI'; Status='SupportedDerivedWorkaround'; AppliesTo=@('INTUNE'); Note='Use tag:microsoft.com,2022-09-14:sid:<SID> through the Intune variable; PKCS uses the SID security extension.' }
        @{ Name='StrongCertificateBindingEnforcement compatibility mode'; Status='Unsupported'; AppliesTo=@('AD-USR','INTUNE'); Note='Historical workaround; unsupported after the September 2025 Windows update.' }
        @{ Name='Any Purpose EKU'; Status='Unsafe'; AppliesTo=@(); Note='Recorded for recognition only and never selected by a scenario.' }
    )

    Algorithms = @(
        @{ Name='RSA'; Oid='1.2.840.113549.1.1.1'; Implemented=$true; KeySizes=@(2048,3072,4096); DefaultKeySize=3072; Hashes=@('SHA256','SHA384','SHA512'); Frequency=1; Note='Microsoft-compatible default; 2048 is the compatibility minimum.' }
        @{ Name='ECDSA'; Oid='1.2.840.10045.2.1'; Implemented=$true; Curves=@('P256','P384','P521'); DefaultCurve='P256'; Hashes=@('SHA256','SHA384','SHA512'); Frequency=2; Note='Prefer P-256/P-384 only where all relying products support ECDSA.' }
        @{ Name='Ed25519'; Oid='1.3.101.112'; Implemented=$false; Frequency=3; Note='Not consistently supported by Windows PowerShell CertificateRequest.' }
        @{ Name='Ed448'; Oid='1.3.101.113'; Implemented=$false; Frequency=4; Note='Not implemented; no silent fallback.' }
        @{ Name='ML-DSA-44'; Oid='2.16.840.1.101.3.4.3.17'; Implemented=$false; Frequency=5; Note='Emerging; not implemented.' }
        @{ Name='ML-DSA-65'; Oid='2.16.840.1.101.3.4.3.18'; Implemented=$false; Frequency=6; Note='Emerging; not implemented.' }
        @{ Name='ML-DSA-87'; Oid='2.16.840.1.101.3.4.3.19'; Implemented=$false; Frequency=7; Note='Emerging; not implemented.' }
    )

    Oids = @{
        Extensions = @{ SubjectKeyIdentifier='2.5.29.14'; KeyUsage='2.5.29.15'; SubjectAlternativeName='2.5.29.17'; BasicConstraints='2.5.29.19'; CrlDistributionPoints='2.5.29.31'; CertificatePolicies='2.5.29.32'; AuthorityKeyIdentifier='2.5.29.35'; ExtendedKeyUsage='2.5.29.37'; FreshestCrl='2.5.29.46'; AuthorityInfoAccess='1.3.6.1.5.5.7.1.1'; TlsFeature='1.3.6.1.5.5.7.1.24'; OcspNoCheck='1.3.6.1.5.5.7.48.1.5'; AdSid='1.3.6.1.4.1.311.25.2'; CertificateTemplateName='1.3.6.1.4.1.311.20.2'; CertificateTemplateInfo='1.3.6.1.4.1.311.21.7' }
        Eku = @{ ServerAuthentication='1.3.6.1.5.5.7.3.1'; ClientAuthentication='1.3.6.1.5.5.7.3.2'; CodeSigning='1.3.6.1.5.5.7.3.3'; EmailProtection='1.3.6.1.5.5.7.3.4'; TimeStamping='1.3.6.1.5.5.7.3.8'; OcspSigning='1.3.6.1.5.5.7.3.9'; IpsecIke='1.3.6.1.5.5.7.3.17'; DocumentSigning='1.3.6.1.5.5.7.3.36'; KerberosKdc='1.3.6.1.5.2.3.5'; SmartCardLogon='1.3.6.1.4.1.311.20.2.2'; MicrosoftIke='1.3.6.1.5.5.8.2.2'; MicrosoftDocumentSigning='1.3.6.1.4.1.311.10.3.12'; Efs='1.3.6.1.4.1.311.10.3.4'; EfsRecovery='1.3.6.1.4.1.311.10.3.4.1'; RemoteDesktop='1.3.6.1.4.1.311.54.1.2'; EnrollmentAgent='1.3.6.1.4.1.311.20.2.1'; KeyRecoveryAgent='1.3.6.1.4.1.311.21.6'; CaExchange='1.3.6.1.4.1.311.21.5'; LifetimeSigning='1.3.6.1.4.1.311.10.3.13'; AnyPurpose='2.5.29.37.0' }
        AccessMethod = @{ Ocsp='1.3.6.1.5.5.7.48.1'; CaIssuers='1.3.6.1.5.5.7.48.2' }
        SanOtherName = @{ UserPrincipalName='1.3.6.1.4.1.311.20.2.3' }
    }

    KeyUsages = @(
        @{ Name='DigitalSignature'; Value=128; Frequency=1 }, @{ Name='KeyEncipherment'; Value=32; Frequency=2 },
        @{ Name='KeyCertSign'; Value=4; Frequency=3 }, @{ Name='CrlSign'; Value=2; Frequency=4 },
        @{ Name='DataEncipherment'; Value=16; Frequency=5 }, @{ Name='KeyAgreement'; Value=8; Frequency=6 },
        @{ Name='NonRepudiation'; Value=64; Frequency=7; Note='contentCommitment' },
        @{ Name='EncipherOnly'; Value=1; Frequency=8; Note='Only with KeyAgreement' },
        @{ Name='DecipherOnly'; Value=32768; Frequency=9; Note='Only with KeyAgreement' }
    )

    Fields = @(
        @{ Name='Subject'; Category='Core'; Oid=$null; Frequency=1; Criticality='N/A'; InputMode='ScenarioDerived'; Recommended='Stable identity DN; empty only with critical SAN.' }
        @{ Name='Subject Alternative Name'; Category='Extension'; Oid='2.5.29.17'; Frequency=2; Criticality='Noncritical, or critical with empty Subject'; InputMode='Prompt'; Recommended='Identity consumed by the relying product.' }
        @{ Name='Key Usage'; Category='Extension'; Oid='2.5.29.15'; Frequency=3; Criticality='Critical'; InputMode='ScenarioDerived'; Recommended='Least privilege.' }
        @{ Name='Extended Key Usage'; Category='Extension'; Oid='2.5.29.37'; Frequency=4; Criticality='Normally noncritical'; InputMode='ScenarioDerived'; Recommended='Only required purposes; never Any Purpose by default.' }
        @{ Name='Basic Constraints'; Category='Extension'; Oid='2.5.29.19'; Frequency=5; Criticality='Critical for CA'; InputMode='ScenarioDerived'; Recommended='cA=true only for CA profiles.' }
        @{ Name='Subject Key Identifier'; Category='Extension'; Oid='2.5.29.14'; Frequency=6; Criticality='Noncritical'; InputMode='Generated'; Recommended='Generate for CAs and normally for leaves.' }
        @{ Name='Authority Key Identifier'; Category='Extension'; Oid='2.5.29.35'; Frequency=7; Criticality='Noncritical'; InputMode='Generated'; Recommended='Derive from issuer SKI/public key.' }
        @{ Name='AIA'; Category='Extension'; Oid='1.3.6.1.5.5.7.1.1'; Frequency=8; Criticality='Noncritical'; InputMode='Prompt'; Recommended='Reachable HTTP OCSP/CA issuer URLs when operated.' }
        @{ Name='CRL Distribution Points'; Category='Extension'; Oid='2.5.29.31'; Frequency=9; Criticality='Noncritical'; InputMode='Prompt'; Recommended='Reachable HTTP CRL URL when operated.' }
        @{ Name='Certificate Policies'; Category='Extension'; Oid='2.5.29.32'; Frequency=10; Criticality='Normally noncritical'; InputMode='Prompt'; Recommended='Only an OID the issuer governs.' }
        @{ Name='OCSP No Check'; Category='Extension'; Oid='1.3.6.1.5.5.7.48.1.5'; Frequency=11; Criticality='Noncritical'; InputMode='ScenarioDerived'; Recommended='Delegated responder only.' }
        @{ Name='TLS Feature'; Category='Extension'; Oid='1.3.6.1.5.5.7.1.24'; Frequency=12; Criticality='Noncritical'; InputMode='ExpertPrompt'; Recommended='Must-Staple only after testing.' }
        @{ Name='AD SID security extension'; Category='MicrosoftExtension'; Oid='1.3.6.1.4.1.311.25.2'; Frequency=13; Criticality='Noncritical'; InputMode='IssuerDerived'; Recommended='Use AD CS/Intune PKCS; do not hand-encode.' }
        @{ Name='AD CS template information'; Category='MicrosoftExtension'; Oid='1.3.6.1.4.1.311.21.7'; Frequency=14; Criticality='Noncritical'; InputMode='IssuerDerived'; Recommended='Let AD CS issue from its template.' }
    )

    # Profiles are sorted by qualitative modern frequency. The code expands EKU names through Oids.Eku.
    Scenarios = @(
        @{Key='TLS-PRV';MenuKey='1';Name='Secure an internal TLS server (IIS, SQL Server, LDAPS, or private API)';Frequency=1;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ServerAuthentication');AddSki=$true;Warning='This profile omits RSA keyEncipherment. Add it only when the target Microsoft product or legacy TLS stack explicitly requires RSA key transport.'}
        @{Key='TLS-PUB';MenuKey='2';Name='Secure a public website or Internet-facing TLS service';Frequency=2;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=200;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ServerAuthentication');AddSki=$true;Warning='A locally self-signed certificate is not publicly trusted. Obtain the production certificate from a public CA. At the research cutoff, public TLS validity must not exceed 200 days.'}
        @{Key='mTLS';MenuKey='3';Name='Authenticate an application, service, or user with a TLS client certificate';Frequency=3;Context='User';SubjectMode='CommonName';SanTypes=@('URI');Algorithm='ECDSA';Curve='P256';Hash='SHA256';ValidityDays=90;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ClientAuthentication');AddSki=$true}
        @{Key='EAP-C';MenuKey='4';Name='Authenticate a user or device to Wi-Fi or VPN with EAP-TLS';Frequency=4;Context='User';SubjectMode='CommonName';SanTypes=@('UPN');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ClientAuthentication');AddSki=$true;Warning='If AD or Kerberos maps this certificate to an account, configure a currently supported strong mapping; a UPN alone may not be sufficient.'}
        @{Key='EAP-S';MenuKey='5';Name='Authenticate an NPS, RADIUS, Wi-Fi, or VPN server to EAP-TLS clients';Frequency=5;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature','KeyEncipherment');Eku=@('ServerAuthentication');AddSki=$true}
        @{Key='AD-USR';MenuKey='6';Name='Sign in to Active Directory with a smart card or certificate';Frequency=6;Context='User';SubjectMode='CommonName';SanTypes=@('UPN');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('SmartCardLogon','ClientAuthentication');AddSki=$true;Warning='Production logon keys should be hardware-backed and non-exportable. Have AD CS or Intune derive SID strong-mapping data; do not enter it manually.'}
        @{Key='DC-KDC';MenuKey='7';Name='Authenticate a domain controller for Kerberos, PKINIT, and LDAPS';Frequency=7;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature','KeyEncipherment');Eku=@('ServerAuthentication','ClientAuthentication','KerberosKdc');AddSki=$true}
        @{Key='INTUNE';MenuKey='8';Name='Provision an Intune-managed user or device authentication certificate';Frequency=8;Context='User';SubjectMode='CommonName';SanTypes=@('UPN');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ClientAuthentication');AddSki=$true;Warning='For strong AD mapping, Intune SCEP uses the Microsoft SID tag URI while Intune PKCS uses the SID security extension. Derive either through Intune and AD CS; do not enter a SID manually.'}
        @{Key='SMIME-SIGN';MenuKey='9';Name='Sign and verify S/MIME email messages';Frequency=9;Context='User';SubjectMode='CommonName';SanTypes=@('Email');Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature','NonRepudiation');Eku=@('EmailProtection');AddSki=$true}
        @{Key='SMIME-ENC';MenuKey='10';Name='Encrypt and decrypt S/MIME email messages';Frequency=10;Context='User';SubjectMode='CommonName';SanTypes=@('Email');Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('KeyEncipherment');Eku=@('EmailProtection');AddSki=$true;Warning='Losing this private key can make archived mail unreadable. Establish backup, escrow, or recovery policy and use a separate certificate for signing.'}
        @{Key='CODE';MenuKey='11';Name='Sign PowerShell scripts, executables, and software packages with Authenticode';Frequency=11;Context='User';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('CodeSigning');AddSki=$true;Warning='Public code-signing keys require current hardware protection. Timestamp every release. Never make a self-signed leaf trusted by inserting it into the Root store.'}
        @{Key='RDS';MenuKey='12';Name='Secure Remote Desktop connections with TLS';Frequency=12;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=2048;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature','KeyEncipherment');Eku=@('ServerAuthentication','RemoteDesktop');AddSki=$true;Warning='This profile includes the Microsoft Remote Desktop Authentication EKU. Some deployments expect Server Authentication only; confirm the target RDS policy before retaining both.'}
        @{Key='DOC';MenuKey='13';Name='Sign Microsoft Office and other human-readable documents';Frequency=13;Context='User';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature','NonRepudiation');Eku=@('MicrosoftDocumentSigning');AddSki=$true;Warning='This Microsoft-first profile uses the Office document-signing EKU. Non-Microsoft validators may instead require the RFC 9336 Document Signing EKU.'}
        @{Key='IKE';MenuKey='14';Name='Authenticate an IKEv2 or IPsec VPN peer';Frequency=14;Context='Computer';SubjectMode='CommonName';SanTypes=@('DNS');Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('MicrosoftIke');AddSki=$true;Warning='This Microsoft-first profile uses the IKE intermediate EKU. Other VPN products may require id-kp-ipsecIKE or no EKU; verify both peers before issuance.'}
        @{Key='WORKLOAD';MenuKey='15';Name='Authenticate a SPIFFE or short-lived workload with mutual TLS';Frequency=15;Context='Computer';SubjectMode='Empty';SanTypes=@('URI');Algorithm='ECDSA';Curve='P256';Hash='SHA256';ValidityDays=1;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('ServerAuthentication','ClientAuthentication');AddSki=$true;SanCritical=$true;Warning='Enter exactly one spiffe:// URI. This one-day certificate requires automated issuance and rotation; manual renewal is not an operational solution.'}
        @{Key='EFS';MenuKey='16';Name='Encrypt user files with Windows EFS';Frequency=16;Context='User';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('KeyEncipherment','DataEncipherment');Eku=@('Efs');AddSki=$true;Warning='Losing this private key can permanently lose access to encrypted files. Configure recovery and archival before using the certificate.'}
        @{Key='ROOT';MenuKey='17';Name='Create an offline trust anchor for a private PKI (root CA)';Frequency=17;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=4096;Hash='SHA384';ValidityDays=3650;IsCA=$true;KeyUsage=@('KeyCertSign','CrlSign');Eku=@();AddSki=$true;AddSelfAki=$true;Warning='Use local generation only for a lab or a controlled private PKI. A production root requires an offline ceremony, protected hardware, documented policy, backups, and audited key handling.'}
        @{Key='SUBCA';MenuKey='18';Name='Issue certificates from an issuing or constrained subordinate CA';Frequency=18;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=4096;Hash='SHA384';ValidityDays=1825;IsCA=$true;PathLength=0;KeyUsage=@('KeyCertSign','CrlSign');Eku=@();AddSki=$true;RequiresIssuer=$true;Warning='Select an existing CA issuer. Before issuing production certificates, configure and operate the AIA, CRL distribution, policy, and constraint values used by this CA.'}
        @{Key='TSA';MenuKey='19';Name='Timestamp digital signatures with an RFC 3161 authority';Frequency=19;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('TimeStamping');EkuCritical=$true;AddSki=$true;Warning='Timestamping must be the certificate''s only EKU. Protect the dedicated key and define its allowed signing period separately from certificate validity.'}
        @{Key='OCSP';MenuKey='20';Name='Sign certificate-status responses from a delegated OCSP responder';Frequency=20;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=30;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('OcspSigning');OcspNoCheck=$true;AddSki=$true;RequiresIssuer=$true;Warning='The CA whose status is reported must issue this responder certificate directly. Keep its lifetime short and protect the signing key.'}
        @{Key='SIGSTORE';MenuKey='21';Name='Create a short-lived Sigstore or Fulcio-style code-signing identity';Frequency=21;Context='User';SubjectMode='Empty';SanTypes=@('Email');Algorithm='ECDSA';Curve='P256';Hash='SHA256';ValidityDays=1;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('CodeSigning');AddSki=$true;SanCritical=$true;RequiresIssuer=$true;Warning='This local profile cannot reproduce Fulcio trust. Real issuance requires verified OIDC claims, Fulcio-specific extensions, and certificate-transparency integration; use the Fulcio service for production.'}
        @{Key='EFS-RECOVERY';MenuKey='22';Name='Recover files encrypted with Windows EFS';Frequency=22;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=4096;Hash='SHA256';ValidityDays=730;IsCA=$false;KeyUsage=@('KeyEncipherment','DataEncipherment');Eku=@('EfsRecovery');AddSki=$true;Warning='This key can decrypt other users'' files. Isolate its operator, template, storage, and audit trail, and test recovery before relying on it.'}
        @{Key='PKI-ENROLL';MenuKey='23';Name='Enroll certificates for another AD CS user or device';Frequency=23;Context='User';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=365;IsCA=$false;KeyUsage=@('DigitalSignature');Eku=@('EnrollmentAgent');AddSki=$true;Warning='An enrollment agent can request certificates for other identities. Restrict eligible templates, target identities, operators, and enrollment permissions.'}
        @{Key='PKI-KRA';MenuKey='24';Name='Recover archived private keys from Active Directory Certificate Services';Frequency=24;Context='User';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=4096;Hash='SHA256';ValidityDays=730;IsCA=$false;KeyUsage=@('KeyEncipherment');Eku=@('KeyRecoveryAgent');AddSki=$true;Warning='This key can unlock archived private keys. Require strong operator authentication, protected storage, separation of duties, and audited recovery procedures.'}
        @{Key='PKI-CAEX';MenuKey='25';Name='Protect AD CS certificate and key exchange operations';Frequency=25;Context='Computer';SubjectMode='CommonName';SanTypes=@();Algorithm='RSA';KeySize=3072;Hash='SHA256';ValidityDays=30;IsCA=$false;KeyUsage=@('KeyEncipherment');Eku=@('CaExchange');AddSki=$true;Warning='Use this short-lived certificate only for the AD CS CA Exchange role. It is not a general TLS, user, or data-encryption certificate.'}
    )
}
