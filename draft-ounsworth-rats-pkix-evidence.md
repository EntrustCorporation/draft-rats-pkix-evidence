---
title: PKI-based Attestation Evidence
abbrev: PKI-based Attestation Evidence
docname: draft-ounsworth-rats-pkix-evidence-latest
category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: Security
workgroup: RATS
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: yes
  consensus: false

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: R. Kettlewell
    name: Richard Kettlewell
    org: Entrust Limited
    abbrev: Entrust
    country: United Kingdom
    email: Richard.Kettlewell@entrust.com
  -
    ins: JPF
    name: Jean-Pierre Fiset
    organization: Crypto4A Technologies Inc.
    abbrev: Crypto4A
    street: 1550A Laperriere Ave
    city: Ottawa, Ontario
    country: Canada
    code: K1Z 7T2
    email: jp@crypto4a.com
  -
    name: Hannes Tschofenig
    organization: Siemens
    email: Hannes.Tschofenig@gmx.net
  -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
  -
    ins: M. Wiseman
    name: Monty Wiseman
    org: Beyond Identity
    country: USA
    email: monty.wiseman@beyondidentity.com

normative:
  RFC2119:
  RFC9334:
  RFC5280:
  I-D.ietf-rats-eat:

informative:
  RFC2986:
  RFC4211:
  RFC5912:
  RFC9344:
  RFC6268:
  I-D.ietf-lamps-csr-attestation:
  X.680:
     title: "Information technology -- Abstract Syntax Notation One (ASN.1): Specification of basic notation"
     author:
        org: ITU-T
        date: false
     target: https://www.itu.int/rec/T-REC-X.680

--- abstract

This document specifies ASN.1 structures produced by an Attester as part
of the remote attestation procedures and constitute Evidence.

This document follows the Remote ATtestation procedureS (RATS)
architecture where Evidence is sent by an Attester and processed by
a Verifier.

--- middle

# Introduction

Trusted execution environments, like secure elements and hardware security
modules (HSMs), are now widely used, which provide a safe environment to place
cryptographic key material and security sensitive code which uses it,
such as signing and decryption services, secure boot, secure storage,
and other essential security functions.  These security functions are
typically exposed through a narrow and well-defined interface, and can be
used by operating system libraries and applications.

Increasingly, parties that rely on these secure elements want evidence
that the security sensitive operations are in fact being performed within
a secure element. This evidence can pertain to the secure element platform
itself, or to the storage and protection properties of the cryptographic keys,
or both. This is generally referred to as remote attestation, and is covered by
the Remote ATtestation procedureS (RATS) architecture {{RFC9344}}. This document
species an evidence data format specified in ASN.1 and re-using many data
structures from the PKIX ASN.1 modules {{RFC5912}} so to be a convenient format
for secure elements and verifiers that are designed primarily for use within
X.509 Public Key Infrastructures.

When a Certificate Signing Request (CSR) library is requesting a certificate
from a Certification Authority (CA), a PKI end entity may wish to provide
Evidence of the security properties of the trusted execution environment
in which the private key is stored. This Evidence is to be verified by a
Relying Party, such as the Registration Authority or the Certification
Authority as part of validating an incoming CSR against a given certificate
policy. {{I-D.ietf-lamps-csr-attestation}} defines how to carry Evidence in
either PKCS#10 {{RFC2986}} or Certificate Request Message Format (CRMF)
{{RFC4211}}.

{{I-D.ietf-lamps-csr-attestation}} is agnostic to the content and the encoding
of Evidence. To offer interoperability it is necessary to define a format
that is utilized in a specific deployment environment.
Hardware security modules and other trusted execution environments, which
have been using ASN.1-based encodings for a long time prefer the use of
the same format throughout their software ecosystem. For those use cases
this specification has been developed.

This specification re-uses the claims defined in {{I-D.ietf-rats-eat}}.
While the encoding of the claims is different to what is defined in
{{I-D.ietf-rats-eat}}, the semantics of the claims is retained. This
specification is not an EAP profile, as defined in Section 6 of
{{I-D.ietf-rats-eat}}

This specification was designed to meet the requirements published by the
CA Browser Forum to convey properties about hardware security models, such
as non-exportability, which must be enabled for storing publicly-trusted
code-signing keys. Hence, this specification is supposed to be used with
the attestation extension for Certificate Signing Requests (CSRs), see
{{I-D.ietf-lamps-csr-attestation}}. 

There are, however, other use cases where remote attestation may also be
used, such as

-  A Certification Authority receives a certificate signing request and wishes to verify that the subject public key was generated in an HSM (for example to satisfy CA/B Forum subscriber private key verification requirement). They may also wish to verify that the operations the HSM will allow for the corresponding private key are consistent with the purpose of the requested certificate.

- A user of a Cloud Service Provider's 'Bring Your Own Key' service wishes to transfer their locally-generated key securely to the CSP's service by encrypting it under the CSP's public key. As part of their due diligence on the CSP's key they wish to verify (1) that it was generated by an HSM and (2) may only be used to unwrap the key into an HSM (i.e. unwrap permission but not decrypt permission).

- An auditor of an identity provision service (or a competent end user) may wish to verify that keys representing end-user identities are held in an HSM and have permissions that are in line with the applicable regulations. For example, they may wish verify that the protection arrangements for assigned keys cannot be changed.

- A manufacturer needs to provision configuration info, software, and credentials to a device from remote. With the help of remote attestation the manufacturer is provided enough information to verify that information is only sent to devices it has built.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in {{RFC9334}} related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms: Evidence, Claim, Attestation Result, Attester,
Verifier, and Relying Party.

# Attestation Evidence

This specification defines the following Evidence format, which contains
a set of claims. To protect Evidence against modification, it is protected
with a digital signature.

~~~ asn.1
PkixEvidenceStatement ::= SEQUENCE {
  tbsEvidence TBSEvidenceStatement
  signatureValues SEQUENCE SIZE (1..MAX) OF BIT STRING,
  relatedCertificates [0] IMPLICIT SEQUENCE of Certificate OPTIONAL
  -- As defined in RFC 5280
}

TBSEvidenceStatement ::= SEQUENCE {
  version INTEGER,
  claims SEQUENCE SIZE (1..MAX) OF EVIDENCE-CLAIM,
  signatureInfos SEQUENCE SIZE (1..MAX) OF SignatureInfo
}

EVIDENCE-CLAIM ::= TYPE-IDENTIFIER

-- TYPE-IDENTIFIER definition from X.681
TYPE-IDENTIFIER ::= CLASS
{
    &id OBJECT IDENTIFIER UNIQUE,
    &Type
}
WITH SYNTAX {&Type IDENTIFIED BY &id}

SignatureInfo ::= SEQUENCE {
   signatureAlgorithm AlgorithmIdentifier,
   sid [0] SignerIdentifier OPTIONAL
}

SignerIdentifier ::= SEQUENCE {
   keyId [0] EXPLICIT OCTET STRING OPTIONAL,
   subjectKeyIdentifier [1] EXPLICIT SubjectPublicKeyInfo OPTIONAL,
     -- As defined in RFC 5280
   certificate [2] EXPLICIT Certificate OPTIONAL,
     -- As defined in RFC 5280
   certHash [3] EXPLICIT CertHash OPTIONAL
}

CertHash ::= SEQUENCE {
    hash AlgorithmIdentifier,
    value OCTET STRING
}
-- There is bound to already exist an ASN.1 structure for this somewhere.

AlgorithmIdentifier ::= SEQUENCE {
   algorithm OBJECT IDENTIFIER,
   parameters ANY DEFINED BY algorithm OPTIONAL
}
~~~

`version` MUST be set to 1.

# Signing and Verification Procedure

EDNOTE: Can we start our versions at some number to avoid versions that
Crypto4A has already used?

## Signing Procedure

1. The message to be signed is the `TBSEvidenceStatement`, including the `SignatureInfo` for each of the signatures to be performed.

2. Each signature is computed in parallel and placed into index of the
`signatureValues` SEQUENCE that matches the position of the corresponding
`SignatureInfo` in the `signatureInfos` sequence.

The signer MUST produce one signature per `signatureInfo`, it MUST NOT
omit signatures and MUST NOT produce a subset of the signatures listed in `signatureInfos`.

## Verification Procedure

1. The message to be verified is the `TBSEvidenceStatement`.

2. For each `signatureInfo`, the corresponding verification public key
and signature algorithm is found according to the information contained
in the `SignatureInfo` for that signature and any accompanying
certificates or key material.

3. For each signature, the message is verified using the value from the
corresponding element of the `signatureValue` sequence.

4. The `PkixEvidenceStatement` SHOULD be considered valid if and only if
all signatures are valid; i.e. multiple signatures are to be treated as
an AND mode. This item is a recommendation and not a hard requirement
since verification policy is of course at the discretion of the Verifier.

EDNOTE: the major change here from the original Crypto4A QASM Attestation
is that the original only includes the claims in the signature, whereas
this includes everything, including the version, list of signature
algorithms. This prevents
possible attacks where those values are manipulated by attackers.
We should debate whether the certificates should be protected by the signature.
Pro: generally better for security to sign everything.
Con: in some contexts, it may be difficult to have the certificates prior to signing, but that's ok because most evidence carrier formats also allow you to attach the signatures externally.

# Claims

Since no claims are marked as MANDATORY, the sequence 'claims' may be constituted of
differing claims from one instance to the next. This is expected as each evidence statement
may be providing information to support different use cases.

Once an evidence statement is signed, the Attester is guaranteeing that all of the claims
carried by the evidence statement are true.

It is important to note that multiple claims in the sequence may have the same 'id'. Implementers
should ensure that this case is handled by verifying logic.

For ease of reading, claims have been separated into two lists:
"platform claims" and "key claims".

## Platform Claims

~~~
| Claim          | OID      | Value        | Section           | Status       |
| --------       | -------- | ------------ | ----------------- | ------------ |
| Oemid          | TBD      | UTF8String   | {{sect-deviceID}} | RECOMMENDED  |
| Hwmodel        | TBD      | UTF8String   | {{sect-deviceID}} | RECOMMENDED  |
| Hwversion      | TBD      | UTF8String   | {{sect-deviceID}} | RECOMMENDED  |
| Hwserial       | TBD      | UTF8String   | {{sect-deviceID}} | RECOMMENDED  |
| Ueid           | TBD      | UTF8String   | {{sect-ueid}    } | OPTIONAL     |
| Sueid          | TBD      | UTF8String   | {{sect-sueid}}    | OPTIONAL     |
| EnvID          | TBD      | UTF8String   | {{sect-envID}}    | OPTIONAL     |
| Swname         | TBD      | UTF8String   | {{sect-swID}}     | RECOMMENDED  |
| Swversion      | TBD      | UTF8String   | {{sect-swID}}     | RECOMMENDED  |
| Oemboot        | TBD      | BOOLEAN      | {{sect-oemboot}}  | RECOMMENDED  |
| Location       | TBD      | ???          | {{sect-location}} | OPTIONAL     |
| Dbgstat        | TBD      | CHOICE       | {{sect-dbgstat}}  | RECOMMENDED  |
| Uptime         | TBD      | INTEGER      | {{sect-uptime}}   | OPTIONAL     |
| Bootcount      | TBD      | INTEGER      | {{sect-bootcount}}| OPTIONAL     |
| Bootseed       | TBD      | BIT STRING   | {{sect-bootseed}} | OPTIONAL     |
| Dloas          | TBD      | SEQUENCE OF Dloa | {{sect-dloas}}    | OPTIONAL     |
| Endorsements   | TBD      | SEQUENCE of Endorsement | {{sect-endorsements}} | OPTIONAL |
| Manifests      | TBD      | ??           | {{sect-manifests}} | OPTIONAL    |
| Measurements   | TBD      | ??           | {{sect-measurements}} | OPTIONAL    |
| Measres        | TBD      | ??           | {{sect-measres}}   | OPTIONAL    |
| Submods        | TBD      | ??           | {{sect-submods}}   | OPTIONAL    |
| Iat            | TBD      | Time         | {{sect-iat}}       | RECOMMENDED |
| FipsMode       | TBD      | Boolean      | {{sect-fipsmode}}  | RECOMMENDED |
| VendorInfo     | TBD      | TYPE-IDENTIFIER | {{sect-vendorinfo}}| OPTIONAL    |
| NestedEvidences| TBD      | SEQUENCE OF PkixEvidenceStatement | {{sect-nestedevidences}} | OPTIONAL |
| Nonce          | TBD      | OCTET STRING | {{sect-nonce}}     | OPTIONAL    |
~~~

## Key Claims

~~~
| Claim          | OID      | Value        | Section           | Status       |
| --------       | -------- | ------------ | ----------------- | ------------ |
| KeyId          | TBD      | IA5String    | {{sect-keyid}}    | OPTIONAL     |
| PubKey         | TBD      | OCTET STRING | {{sect-pubkey}}   | RECOMMENDED  |
| Purpose        | TBD      | CHOICE       | {{sect-purpose}}  | RECOMMENDED  |
| NonExportable  | TBD      | BOOLEAN      | {{sect-nonexportable}} | RECOMMENDED |
| Imported       | TBD      | BOOLEAN      | {{sect-imported}} | RECOMMENDED  |
| KeyExpiry      | TBD      | Time         | {{sect-keyexpiry}}| OPTIONAL     |
~~~

Even though no specific claims are required, a Verifier or Relying Party MAY reject an
Evidence claim if it is missing information required by the appraisal
policy. For example, a Relying Party which requires a FIPS-certified device
SHOULD reject Evidence if it does not contain sufficient
information to determine the FIPS certification status of the device.

## Device Identifier {#sect-deviceID}

Devices assigned a Universal Entity ID compliant with RATS EAT SHOULD
provide this in the `Ueid` or `Sueid` claim. Devices with a traditional
human-readable serial number SHOULD provide this in the `Hwserial` claim.
Both MAY be provided.

The set `{OemID, Hwmodel, Hwversion, Hwserial}`, when provided, SHOULD
represent a universally unique identification of the device. Where
applicable, `{OemID, Hwmodel, Hwversion}` SHOULD match the way the
device is identified in relevant endorsements, such as published FIPS
or Common Criteria certificates.

###  ueid (Universal Entity ID) Claim {#sect-ueid}

The "ueid" claim conveys a UEID, which identifies an individual manufactured
entity. This identifier is a globally unique and permanent identifier. See
Section 4.2.1 of {{I-D.ietf-rats-eat}} for a description of this claim. Three
types of UEIDs are defined, which are distinguished via a type field.

The ueid claim is defined as follows:

~~~
   id-ce-evidence-ueid OBJECT IDENTIFIER ::=
         { id-ce TBD_evidence TBD_ueid }

   claim_ueid ::= SEQUENCE {
       type    INTEGER ( RAND(1), EUI(2), IMEI(3),...),
       value   OCTET STRING
   }
~~~

###  sueids (Semi-permanent UEIDs) Claim (SUEIDs) {#sect-sueid}

The "sueids" claim conveys one or more semi-permanent UEIDs (SUEIDs).
An SUEID has the same format, characteristics and requirements as a
UEID, but MAY change to a different value on entity life-cycle
events while the ueid claim is permanent. An entity MAY have both
a UEID and SUEIDs, neither, one or the other.

There MAY be multiple SUEIDs and each has a text string label the
purpose of which is to distinguish it from others.

See Section 4.2.2 of {{I-D.ietf-rats-eat}} for a description of this claim.

The sueids claim is defined as follows:

~~~
   id-ce-evidence-sueids OBJECT IDENTIFIER ::=
         { id-ce TBD_evidence TBD_sueids }

   claim_sueids ::= SEQUENCE {
       label   OCTET STRING,
       type    INTEGER ( RAND(1), EUI(2), IMEI(3),...),
       value   OCTET STRING
   }
~~~

### oemid (Hardware OEM Identification) Claim

The "oemid" claim identifies the Original Equipment Manufacturer (OEM) of
the hardware.

See Section 4.2.3 of {{I-D.ietf-rats-eat}} for a description of this claim.

The value of this claim depends on the type of OEMID and three types of IDs
are defined:

- OEMIDs using a 128-bit random number.
Section 4.2.3.1 of {{I-D.ietf-rats-eat}} defines this type.

- an IEEE based OEMID using a global registry for MAC addresses and company IDs.
Section 4.2.3.1 of {{I-D.ietf-rats-eat}} defines this type.

- OEMIDs using Private Enterprise Numbers maintained by IANA.
Section 4.2.3.3 of {{I-D.ietf-rats-eat}} defines this type.

The oemid claim is defined as follows:

~~~
   id-ce-evidence-oemid OBJECT IDENTIFIER ::=
         { id-ce TBD_evidence TBD_oemid }

   claim_oemid ::= SEQUENCE {
       type    INTEGER ( PEN(1), IEEE(2), RANDOM(3),...),
       value   OCTET STRING
   }
~~~

Editor's Note: The value for the PEN is numeric. For the other
two types it is a binary string.

### hwmodel (Hardware Model) Claim

The "hwmodel" claim differentiates hardware models, products and variants
manufactured by a particular OEM, the one identified by OEM ID.
It MUST be unique within a given OEM ID.  The concatenation of the OEM ID
and "hwmodel" give a global identifier of a particular product.
The "hwmodel" claim MUST only be present if an "oemid" claim is present.

See Section 4.2.4 of {{I-D.ietf-rats-eat}} for a description of this claim.

The hwmodel claim is defined as follows:

~~~
   id-ce-evidence-hwmodel OBJECT IDENTIFIER ::=
         { id-ce TBD_evidence TBD_hwmodel }

   claim_hwmodel ::= OCTET STRING
~~~

###  hwversion (Hardware Version) Claim

The "hwversion" claim is a text string the format of which is set by each
manufacturer. A "hwversion" claim MUST only be present if a "hwmodel" claim
is present.

See Section 4.2.5 of {{I-D.ietf-rats-eat}} for a description of this claim.

The hwversion claim is defined as follows:

~~~
   id-ce-evidence-hwversion OBJECT IDENTIFIER ::=
         { id-ce TBD_evidence TBD_hwwversion }

   hwversion ::= OCTET STRING
~~~


## Environment Identifier {#sect-envID}

~~~ asn.1
EnvID EVIDENCE-CLAIM ::= UTF8String IDENTIFIED BY TBD
~~~

This claim MAY be used to identify a partition within a cryptographic
device, or a logical environment that spans multiple cryptographic
devices such as a Security World or a cloud tenant. The format of
these identifiers will be vendor or environment specific.

## Software Identifier {#sect-swID}

~~~ asn.1
Swname EVIDENCE-CLAIM ::= UTF8String IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.6
Swversion EVIDENCE-CLAIM ::= UTF8String IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.7
~~~

`SwName` and `Swversion` together identify the device firmware and
SHOULD match the way the firmware is identified in relevant
endorsements, such as published FIPS or Common Criteria certificates.

## OEM Boot {#sect-oemboot}

~~~ asn.1
Oemboot EVIDENCE-CLAIM ::= BOOLEAN IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.8
~~~

## Dbgstat (Debug Status) {#sect-dbgstat}

The "dbgstat" claim applies to entity-wide or submodule-wide debug
facilities and diagnostic hardware built into chips. It applies to
any software debug facilities related to privileged software that
allows system-wide memory inspection, tracing or modification of
non-system software like user mode applications.

See Section 4.2.9 of {{I-D.ietf-rats-eat}} for a description of this
claim and the semantic of the values in the enumerated list.

The dbgstat claim is defined as follows:

~~~ asn.1
Dbgstat EVIDENCE-CLAIM ::= CHOICE {
    enabled                         [0] IMPLICIT NULL,
    disabled                        [1] IMPLICIT NULL,
    disabled-Since-Boot             [2] IMPLICIT NULL,
    disabled-Permanently            [3] IMPLICIT NULL,
    disabled-Fully-and-Permanently  [4] IMPLICIT NULL
}
  -- semantics defined in rats-eat-4.2.9
~~~

## Location {#sect-location}

~~~ asn.1
Location EVIDENCE-CLAIM ::= ???? IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.10
~~~

Most HSMs will likely not know their own physical location, but cryptographic modules on mobile devices may.

## Uptime {#sect-uptime}

The "uptime" claim contains the number of seconds that have elapsed
since the entity or submodule was last booted.

~~~ asn.1
Uptime EVIDENCE-CLAIM ::= INTEGER IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.11
~~~

## Bootcount {sect-bootcount}

The "bootcount" claim contains a count of the number times the entity
or submodule has been booted.  Support for this claim requires a
persistent storage on the device.

~~~ asn.1
Bootcount EVIDENCE-CLAIM ::= INTEGER IDENTIFIER BY TBD
  -- semantics defined in rats-eat-4.2.12
~~~

## Bootseed {#sect-bootseed}

The "bootseed" claim contains a value created at system boot time
that allows differentiation of attestation reports from different
boot sessions of a particular entity (e.g., a certain UEID).

This value is usually public.  It is not a secret and MUST NOT be
used for any purpose that a secret seed is needed, such as seeding
a random number generator.

~~~ asn.1
Bootseed EVIDENCE-CLAIM ::= BIT STRING IDENTIFIED BY TBD
  -- semantics defined in rats-eat-4.2.13
~~~

## dloas (Digital Letters of Approval) {#sect-dloas}

The "dloas" claim conveys one or more Digital Letters of Approval
(DLOAs).  A DLOA is a document that describes a certification
that an entity has received.  Examples of certifications represented
by a DLOA include those issued by Global Platform and those based on
Common Criteria.  The DLOA is unspecific to any particular
certification type or those issued by any particular organization.

~~~ asn.1
Dloas EVIDENCE-CLAIM ::= SEQUENCE SIZE (1..MAX) OF Dloa

Dloa ::= SEQUENCE IDENTIFIED BY TBD {
    dloaRegistrar IA5STRING,
    dloaPlatformLabel UTF8STRING,
    dloaApplicationLabal [0] IMPLICIT UTF8String OPTIONAL
}
  -- semantics defined in rats-eat-4.2.14
~~~

## Endorsements {#sect-endorsements}

This claim allows referencing third party endorsements; for example
from the device vendor or a certification such as FIPS or Common
Criteria. The content MAY be referenced by URI, or placed directly
inline, but either way, the endorsement content or its URI MUST be
known by the attester at the time that the evidence is generated.

~~~ asn.1
Endorsements EVIDENCE-CLAIM ::= SEQUENCE SIZE (1..MAX) OF Endorsement

Endorsement ::= CHOICE IDENTIFIED BY TBD {
    uri     [0] IMPLICIT IA5String,
    content [1] IMPLICIT OCTET STRING
}
~~~

EDNOTE: this needs a bit of thought about what types of endorsements
we will likely see, and whether OCTET STRING is the right format.

## Manifests {#sect-manifests}

TODO -- rats-eat-4.2.15

## Measurements {#sect-measurements}

TODO -- rats-eat-4.2.16

## Measres (Software Measurement Results) {#sect-measres}

TODO -- rats-eat-4.2.17

## Submods (Submodules) {#sect-submods}

TODO -- rats-eat-4.2.18

## iat (Issuance Time) {#sect-iat}

The time at which the evidence was created. Here we differ from
the `iat` claim in rats-eat-4.3.1 in that we use the PKIX time
format `Time` instead of the 64-bit CBOR time structure.

~~~ asn.1
Iat EVIDENCE-CLAIM ::= Time
~~~

It is recognized that many HSMs, especially if air-gapped, will
not have an accurate system clock. If the system is not anticipated
to have a reliable clock, then this claim SHOULD be omitted and
the `Nonce` claim used instead.

## intuse (Intended Use) {#sect-intuse}

~~~ asn.1
Intuse EVIDENCE-CLAIM ::= CHOICE IDENTIFIED BY TBD {
    generic              [1] IMPLICIT NULL,
    registration         [2] IMPLICIT NULL,
    provisioning         [3] IMPLICIT NULL,
    certificateIssuance  [4] IMPLICIT NULL,
    proofOfPossession    [5] IMPLICIT NULL
}
  -- semantics defined in rats-eat-4.3.3
~~~

Note: tags intentionally started at 1 to align with EAT. If the
IANA registry of intended use claims is extended, then the this
CHOICE MAY be extended using the same tag values as indicated
in the EAT registry.

## FipsMode {#sect-fipsmode}

The cryptographic module was booted in FIPS mode, including the
required self-tests and any other requiremnts of its FIPS certificate.

Note to verifiers and relying parties: "FIPS Mode" does not imply
"FIPS Certified". For example, a device may have a FIPS Mode even
if the device was never submitted for FIPS certification. This
claim SHOULD only be taken in conjunction with a valid FIPS
certification for this hardware and software version, and
appraising any other claims as required by the FIPS certification.

~~~ asn.1
FipsMode EVIDENCE-CLAIM ::= BOOLEAN IDENTIFIED BY TBD
~~~

## VendorInfo {#sect-vendorinfo}

This claim provides a place for vendor to place propriatary data;
i.e. any proprietary data that does not fit in any other claim.

~~~ asn.1
VendorInfo ::= TYPE-IDENTIFIER IDENTIFIED BY TBD
~~~

Vendors must specify an OID and data type for their VendorInfo,
and communicate this to verifiers who wish to parse this data.

## NestedEvidences {#sect-nestedevidences}

~~~ asn.1
NestedEvidences EVIDENCE-CLAIM ::= SEQUENCE OF PkixEvidenceStatement IDENTIFIED BY TBD
~~~

Composite devices may produce multiple signed evidence statements
that need to be signed in a hiearchical manner. PkixEvidenceStatements
MAY be nested.


## Nonce {#sect-nonce}

The "nonce" claim is used to provide freshness.

The Nonce claim is used to carry the challenge provided by the caller to
demonstrate freshness of the generated token. The following constraints
apply to the nonce-type:

- The length must be reasonable as it may be processed by end entities with limited resources.
  Therefore, it is RECOMMENDED that the length does not exceed 64 bytes.
- Only a single nonce value is conveyed.

The nonce claim is defined as follows:

~~~ asn.1
Nonce EVIDENCE-CLAIM ::= OCTET STRING IDENTIFIED BY TBD
~~~

See Section 4.1 of {{I-D.ietf-rats-eat}} for a description of this claim.

## KeyId {#sect-keyid}

An identifier for the subject key. The format MAY be vendor-specific,
but MUST be an ASCII value (IA5String).

~~~ asn.1
KeyId EVIDENCE-CLAIM ::= IA5String IDENTIFIED BY TBD
~~~

## PubKey {#sect-pubkey}

The subject public key being attested by this evidence.

~~~ asn.1
PubKey EVIDENCE-CLAIM ::= OCTET STRING IDENTIFIED BY TBD
~~~

## Purpose {#sect-purpose}

TODO: align with PKCS#11 Purposes

~~~ asn.1
Purpose EVIDENCE-CLAIM ::= CHOICE IDENTIFIED BY TBD {
   ... Sign, Decrypt, Unwrap, etc..

}
~~~


## NonExportable {#sect-nonexportable}

TODO align with PKCS#11

~~~ asn.1
NonExportable EVIDENCE-CLAIM ::= BOOLEAN IDENTIFIED BY TBD
~~~

## Imported {#sect-imported}

TODO align with PKCS#11

~~~ asn.1
Imported EVIDENCE-CLAIM ::= BOOLIAN IDENTIFIED BY TBD
~~~

## KeyExpiry {#sect-keyexpiry}

If the key has a known expiry time or "not after" date.

~~~ asn.1
KeyExpiry EVIDENCE-CLAIM ::= Time
~~~

## Unrecognized claims

This document does not define an exhaustive list of claims. New claims
may be added in the future, including proprietary ones. As such, parsers
SHOULD expect to encounter unrecognized claims, and to handle them gracefully.

In general, the correct behaviour for a verifier will be to start with an
appraisal policy of claims to look for, and where appropriate the expected
values (for example, FipsMode: true), and any additional claims that may be in the
evidence SHOULD be ignored.

# Evidence Claims Certificate Extension {#extclaims-extension}

This section specifies the syntax and semantics of the Evidence Claims certificate extension which
provides a list of claims associated with the certificate subject appraised by the CA.

The Evidence Claims certificate extension MAY be included in public key certificates [RFC5280].
The Evidence Claims certificate extension MUST be identified by the following object identifier:

~~~~
     id-pe-evidenceclaims OBJECT IDENTIFIER  ::=
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-pe(1) 34 }
~~~~

This extension MUST NOT be marked critical.

The Evidence Claims extension MUST have the following syntax:

~~~~
EvidenceClaims ::= SET SIZE (1..MAX) OF EVIDENCE-CLAIM
~~~~

The EvidenceClaims represents an unsigned version of the evidence claims appraised by the CA.
It MUST contain at least one claim.  For privacy reasons, the CA MAY include only a subset
of the EvidenceClaims that were presented to it, for example in an EvidenceBundle in a CSR.
The CA may include in their certificate profile a
list of verified evidence claims (identified by OID) that MAY be copied from the CSR to
the certificate, while any other claims MUST NOT be copied.
By removing the signature from the evidence, the CA is asserting that it has has verified
the Evidence to chain to a root that the CA trusts, but it is not required to disclose
in the final certificate what that root is.

See {{sec-priv-cons}} for a discussion of privacy concerns related to re-publishing
Evidence into a certificate.


## ASN.1 Module {#extclaims-asn}

This section provides an ASN.1 Module {{X.680}} for the Evidence Claims
certificate extension, and it follows the conventions established in
{{RFC5912}} and {{RFC6268}}.

~~~~
   <CODE BEGINS>
     EvidenceClaimsCertExtn
       { iso(1) identified-organization(3) dod(6) internet(1)
         security(5) mechanisms(5) pkix(7) id-mod(0)
         id-mod-evidenceclaims(TBD) }

     DEFINITIONS IMPLICIT TAGS ::=
     BEGIN

     IMPORTS
       EXTENSION
       FROM PKIX-CommonTypes-2009  -- RFC 5912
         { iso(1) identified-organization(3) dod(6) internet(1)
           security(5) mechanisms(5) pkix(7) id-mod(0)
           id-mod-pkixCommon-02(57) } ;

     -- Evidence Claims Certificate Extension

     ext-EvidenceClaims EXTENSION ::= {
       SYNTAX EvidenceClaims
       IDENTIFIED BY id-pe-evidenceclaims }

     -- EvidenceClaims Certificate Extension OID

     id-pe-evidenceclaims OBJECT IDENTIFIER ::=
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-pe(1) 34 }

     -- Evidence Claims Certificate Extension Syntax

     EvidenceClaims ::= SET SIZE (1..MAX) OF EVIDENCE-CLAIM

     END
   <CODE ENDS>
~~~~

# Implementation Considerations

## API for requesting evidence from an attesting device

While it is strictly outside the scope of this document to specify how a calling application
can request evidence from a cryptographic device, two modes are suggested.

### Request by ID and claim profile

In this mode, the calling application request evidence about a given entity
-- for example, a given EnvID or a given KeyID -- and the cryptographic device
assembles a `PkixEvidenceStatement` containing as many claims as it is able to
populate. Implementers may have named evidence profiles if it is desirable for
the cryptographic device to respond with multiple different sets of claims.

### Request by claim set

In this mode, the calling application pre-constructs a sequence of `EVIDENCE-CLAIM`
which is passed in to the attesting device. As a response, the attesting device returns
a structure of type `PkixEvidenceStatement` which includes all the expected signatures.

This mode is useful for attesting devices with more resources and used in situations where
the supported evidence profiles may not be known during implementation.

It is left to the implementer to choose the way that the desired claims are submitted to the
attesting device, including which types of claims are recognized and how much information is
provided by the caller.

However, when using this mode:
- an attesting device MUST reject the production of a `PkixEvidenceStatement` if any requested
  claim is not recognized; and,
- an attesting device MUST reject the production of a `PkixEvidenceStatement` if any requested
  claim is not supported by the observed state (claim is deemed false).

The use of this mode implies that the attesting device contains the logic necessary to interpret
and verify the submitted claims.

# Privacy Considerations {#sec-priv-cons}

## Publishing Evidence in a certificate

The extension MUST NOT publish in the certificate any privacy-sensitive information
that could compromise the end device. What counts as privacy-sensitive will vary by
use case. For example, consider a few scenarios:

First, consider a Hardware Security Module (HSM) backing a public code-signing service.
The model and firmware patch level could be considered sensitive as it could give an
attacker an advantage in exploiting known vulnerabilities against un-patched systems.

Second, consider a certificate issued to a end-user mobile computing device,
any sort of unique identifier could be used as a super-cookie for tracking
purposes.

Third, consider small IoT devices such as un-patchable wireless sensors.
Here there may be no privacy concerns and in fact knowing exact hardware
and firmware version information could help edge gateways to deny network
access to devices with known vulnerabilities.

Beyond that, a CA MUST have a configurable mechanism to control which information
is to be copied from the provided Evidence into the certificate, for example this
could be configured within a certificate profile or Certificate Practice Statement
(CPS) and this must be considered on a case-by-base basis.  To protect end-user
privacy, CA operators should err on the
side of caution and exclude information that is not clearly essential for security
verification by relying parties.  Avoiding unnecessary claims also mitigates the risk
of targeted attacks, where an
attacker could exploit knowledge of hardware versions, models, etc.


# Security Considerations {#sec-cons}

This specification re-uses the claims from the EAT specification and
relies on the security protection offered by digital signatures. This
digital signature is computed with the Attestation Key available
on the device, see Section 12.1 of {{RFC9334}} for considerations
regarding the generation, the use and the protection of these
Attestation Keys. Since the Attester located at the end entity creates
the Evidence with claims defined in this document. This document inherits
the remote attestation architecture described in {{RFC9334}}. With the
re-use of the claims from {{I-D.ietf-rats-eat}} the security and privacy
considerations apply also to this document even though the encoding
in this specification is different from the encoding of claims
discussed by {{I-D.ietf-rats-eat}}.

Evidence contains information that may be unique to a device
and may therefore allow to single out an individual device for
tracking purposes.  Deployments that have privacy requirements must
take appropriate measures to ensure that claim values can only
identify a group of devices and that the Attestation Keys are used
across a number of devices as well.

To verify the Evidence, the primary need is to check the signature and
the correct encoding of the claims. To produce the Attestation Result,
the Verifier will use Endorsements, Reference Values, and Appraisal
Policies. The policies may require that certain claims must be present
and that their values match registered reference values.  All claims
may be worthy of additional appraisal.

#  IANA Considerations

TBD: OIDs for all the claims listed in this document.

## OIDs for Evidence Claims Certificate Extension

For the EvidenceClaims certificate extension in {{extclaims-extension}},
IANA is requested to assign an object identifier (OID) for the certificate extension.
The OID for the certificate extension should be allocated in the "SMI
Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

For the ASN.1 Module in {{extclaims-asn}}, IANA is requested to assign an
object identifier (OID) for the module identifier.  The OID for the
module should be allocated in the "SMI Security for PKIX Module
Identifier" registry (1.3.6.1.5.5.7.0).

--- back

# Acknowledgements

This specification is the work of a design team created by the chairs
of the LAMPS working group. This specification has been developed
based on discussions in that design team.

The following persons, in no specific order, contributed to the work:
Richard Kettlewell, Chris Trufan, Bruno Couillard, Jean-Pierre Fiset,
Sander Temme, Jethro Beekman, Zsolt Rózsahegyi, Ferenc Pető, Mike Agrenius
Kushner, Tomas Gustavsson, Dieter Bong, Christopher Meyer, Michael StJohns,
Carl Wallace, Michael Ricardson, Tomofumi Okubo, Olivier Couillard, John
Gray, Eric Amador, Johnson Darren, Herman Slatman, Tiru Reddy, Thomas
Fossati, Corey Bonnell, Argenius Kushner, James Hagborg.

# ASN.1 Module {#asn1-mod}

TBD: Full ASN.1 goes in here.
