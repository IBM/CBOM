# Cryptography Bill of Materials

## Update 2024-04-09: Upstream to CycloneDX 1.6

CBOM based on this repository has been integrated and upstreamed to the CycloneDX 1.6 [specification](https://github.com/CycloneDX/specification/releases/tag/1.6). We thank the CycloneDX community for working with us integrating our CBOM specification. We recommend users to refer to the upstream specifciation of CycloneDX and the [CycloneDX CBOM guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf).

Open-source tooling developed at IBM Research related to CBOM is available here:
 - [CBOMkit](https://github.com/IBM/cbomkit): A toolset for dealing with Cryptography Bill of Materials (CBOM). 
 - [Sonar Cryptography Plugin (CBOMkit-hyperion)](https://github.com/IBM/sonar-cryptography): A SonarQube Plugin that detects cryptographic assets in source code and generates CBOM.
 - [CBOM Viewer (CBOMkit-coeus)](https://www.zurich.ibm.com/cbom/): Visualize a generated or uploaded CBOM and access comprehensive statistics.
 - [CBOMkit-theia](https://github.com/IBM/cbomkit-theia): A tool for detecting cryptographic assets in container images and directories, and generating CBOMs.

The [CycloneDX Tool Center](https://cyclonedx.org/tool-center/) lists more tooling related to the CycloneDX SBOM standard.

## Introduction

Cryptography Bill of Materials (CBOM) is an object model to describe cryptographic assets (short crypto-assets) and their dependencies.
CBOM is an extension of the [CycloneDX](https://cyclonedx.org) standard for Software Bill of Materials (SBOM), with notions to model crypto assets. CycloneDX was originally designed for use in application security and supply chain component analysis and is the SBOM format most aligned with the CBOM use case.

There is a need to discover, manage and report cryptography as the first step on the migration journey to quantum safe systems and applications. Cryptography is typically buried deep within components that are used to compose and build systems and applications. It makes sense to minimize this effort through alignment and reuse of concepts and components used to implement Software Supply Chain Security (SSCS).

## Contents

- [Cryptography Bill of Materials](#cryptography-bill-of-materials)
  - [Contents](#contents)
  - [Background: Software Bill of Materials](#background-software-bill-of-materials)
  - [CBOM Design](#cbom-design)
  - [CBOM Schema](#cbom-schema)
    - [crypto-asset](#crypto-asset)
    - [cryptoProperties](#cryptoproperties)
      - [Algorithm](#algorithm)
      - [Certificate](#certificate)
      - [RelatedCryptoMaterial](#relatedcryptomaterial)
      - [Protocol](#protocol)
      - [Classical Security Level](#classical-security-level)
      - [Quantum Security Level](#quantum-security-level)
      - [OID](#oid)
      - [Confidence levels](#confidence-levels)
      - [Scanner](#scanner)
      - [Detection Context](#detection-context)
      - [General considerations](#general-considerations)
    - [Dependencies](#dependencies)
  - [Examples](#examples)
  - [Schema Validation](#schema-validation)
  - [Notes for future releases](#notes-for-future-releases)

## Background: Software Bill of Materials

A Software Bill of Materials (SBOM) is a list of all the individual components that make up a piece of software and how its delivered. This can include not only the source code for the software, but also any libraries, frameworks, and other third-party components that are used in the software. An SBOM is based on a bill of materials (BOM) used in manufacturing, which lists all the components that are used to build a physical product.
An SBOM typically includes a set of metadata that detail licensing information, identification and version numbers together with the component details.
One of the main functions of SBOMs in a security context is to simplify the management of security events and automate remediation actions through adding sufficient context to an event. The benefits of standards based SBOM’s include:

- Facilitating the exchange of component composition in an industry.
- Visibility of components and dependencies in an application or system.
- Simpler Vulnerability Scanning through standardized identification of components.
- Better understanding of risk.
- Simpler management and remediation of vulnerabilities.

There are a number of common SBOM standards:

- [CycloneDX](https://cyclonedx.org)
- [Software Package Data Exchange (SPDX)](https://spdx.dev)
- [SWID: Software Identification Tagging](https://csrc.nist.gov/projects/Software-Identification-SWID)

## CBOM Design

The overall design goal of CBOM is to provide an abstraction that allows modelling and representing crypto assets in a structured object format. This comprises the following points.

1. Modelling crypto assets

Crypto assets occur in several forms. Algorithms and protocols are most commonly implemented in specialized cryptographic libraries. They may however also be 'hardcoded' in software components. Certificates and related crypto material like keys, tokens, secrets or passwords are other crypto assets to be modelled.


2. Capturing crypto asset properties

Crypto assets have properties that uniquely define them and that make them actionable for further reasoning. As an example, it makes a difference if one knows the algorithm family (e.g. AES) or the specific variant or instantiation (e.g. AES-128-GCM). This is because the security level and the algorithm primitive (authenticated encryption) is only defined by the definition of the algorithm variant. The presence of a weak cryptographic algorithm like SHA1 vs. HMAC-SHA1 also makes a difference. Therefore, the goal of CBOM is to capture relevant crypto asset properties.

3. Capturing crypto asset dependencies

To understand the impact of a crypto asset, it is important to capture its dependencies. Crypto libraries 'implement' certain algorithms and protocols, but their implementation alone does not reflect their usage by applications. CBOM therefore differentiates between 'implements' and 'uses' dependencies. It is possible to model algorithms or protocols that use other algorithms (e.g. TLS 1.3 uses ECDH/secp256r1), libraries that implement algorithms and applications that 'use' algorithms from a library.

4.  Applicability to various software components

CycloneDX supports various software components: applications, frameworks, libraries, containers, operating-systems, devices, firmware and files. CBOM allows to use these components and represent their dependency to crypto assets.

5. High compatibility to CycloneDX SBOM and related tooling

CBOM is an extension of the CycloneDX SBOM standard. It integrates crypto assets as an additional 'component' in the CycloneDX schema and further extends dependencies with the notion of 'dependencyType' to model 'uses' and 'implements' relationships. Besides these extensions, the CBOM schema is fully compatible to CycloneDX and allows access to the related tooling the ecosystem provides.

6. Enable automatic reasoning

CBOM enables tooling to automatically reason about crypto assets and their dependencies. This allows checking for compliance with policies that apply to cryptographic use and implementation.

## CBOM Schema

The CBOM schema is available as a JSON schema.

File: [bom-1.4-cbom-1.0.schema.json](bom-1.4-cbom-1.0.schema.json).

CBOM extends the CycloneDX standard (version 1.4) with the following properties that will be described in more detail:

- Component: `crypto-asset`
- Properties: `cryptoProperties`
- Dependencies: `dependencyType`

### crypto-asset

Crypto-asset is a representation of a [component type](https://cyclonedx.org/specification/overview/#components). The type and the name are required component properties.

```
"component": {
      "type": "object",
      "title": "Component Object",
      "required": [
        "type",
        "name"
      ],
      "additionalProperties": false,
      "properties": {
        "type": {
          "type": "string",
          "enum": [
            "application",
            "framework",
            "library",
            "container",
            "operating-system",
            "device",
            "firmware",
            "file",
            "crypto-asset"
          ],
...
```

### cryptoProperties

The `cryptoProperties` object describes the following `assetTypes`:

- `algorithm`
- `certificate`
- `relatedCryptoMaterial`
- `protocol`

#### Algorithm

Describes a cryptographic algorithm. If `algorithm` is selected, the object `algorithmProperties` shall be used to define further properties:

- `primitive`: an enum defining the cryptographic primitive (e.g. drbg, blockcipher).
- `variant`: defines the variant of an algorithm (e.g. `AES-128-GCM`).
- `implementationPlatform`: an enum defining the platform where the algorithm is implemented (e.g. `x86_64`), if known or applicable.
- `certificationLevel`: an enum defining the certification level in which the algorithm has been implemented (e.g. `fips140-3-l1`), if known or applicable.
- `mode`: the mode of operation of an algorithm of primitive blockcipher (e.g. `cbc`), if known or applicable.
- `padding`: the padding scheme used for the cryptographic algorithm (e.g. `pkcs7` padding), if known or applicable.
- `cryptoFunction`: the associated crypto functions used or implemented for an algorithm (e.g. `keygen`), if known or applicable.

Note that some `algorithmProperties` fields may be redundant. For example, the `variant` description `AES-128-GCM` also contains information about the `mode` of operation `gcm`. Explicitly recording the `mode` properties will simplify the reasoning on the CBOM.

#### Certificate

Describes a cryptographic certificate. If `certificate` is selected, the object `certificateProperties` shall be used to define further properties:

- `subjectName`: subjectName property of a certificate, if known or applicable.
- `issuerName`: issuerName property of a certificate, if known or applicable.
- `notValidBefore`: not valid before property of a certificate, if known or applicable.
- `certificateAlgorithm`: certificate public key algorithm of a certificate, if known or applicable.
- `certificateFormat`: certificate format, e.g. X.509, PEM, DER, CVC, if known or applicable.
- `certificateExtensions`: certificate extensions of a certificate, if known or applicable.


#### RelatedCryptoMaterial

Describes related cryptographic material. The `relatedCryptoMaterial` assetType corresponds to cryptographic material inventoried in the CBOM. If `relatedCryptoMaterial` is selected, the object `relatedCryptoMaterialProperties` shall be used to define further properties:

- `relatedCryptoMaterialType`: an enum defining the type of cryptographic material (e.g. `privateKey`, `publicKey`).
- `size`: size in bits of the related crypto material, if known or applicable.
- `format`: format of the related crypto material (e.g. P8, PEM, DER), if known or applicable.
- `secured`: indicates if the related crypto material is secured or not, if known or applicable.

#### Protocol

Describes cryptographic protocols. If `protocol` is selected, the object `protocolProperties` shall be used to define further properties:

- `tlsCipherSuites`: for TLS protocols - defines the TLS cipher suites supported by a TLS protocol instantiation.
- `ikev2TransformTypes`: for IPsec protocols - defines the IKEv2 transform types supported by the IPsec instantiation. This property is defined in an array containing entries for (1) transform type 1, (2) transform type 2, (3) transform type 3, and (4) transform type 4.

#### Classical Security Level

Defines the classical security level in bits in property `classicalSecurityLevel`.

#### Quantum Security Level

The property `nistQuantumSecurityLevel` defines the quantum security level of the crypto asset. The security level corresponds to the [security strength categories](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)) defined by NIST for the PQC standardization process. The value is an integer ranging from 0 to 6, while 0 is chosen if none of the NIST categories are met.

#### OID

Defines the Object Identifier (OID) of the crypto asset in property `oid`, if available and applicable.

#### Confidence levels

If probabilistic methods are used to generate a CBOM with crypto assets, the properties can be assigned with a corresponding confidence level (a number from 0.0 to 1.0). The property is named `confidenceLevels` and contains the following object values:

- `assetType`
- `primitive`
- `relatedCryptoMaterialType`
- `variant`
- `mode`
- `padding`
- `cryptoFunctions`
- `subjectName`
- `issuerName`
- `notValidBefore`
- `notValidAfter`
- `certificateAlgorithm`
- `certificateSignatureAlgorithm`
- `certificateFormat`
- `certificateExtensions`
- `tlsCipherSuites`
- `ikev2TransformTypes`

#### Scanner

Defines the name of the identification method (scanner) used to generate the CBOM. The property is named `scanner`.

#### Detection Context

Defines additional context metadata related to the detected crypto asset. The object is named `detectionContext` and it is an array of objects with the following properties (multiple entries in the array may be used if the crypto asset is detected in multiple files):

- `filePath`: file path of the detected crypto asset, if known or applicable.
- `lineNumbers`: line numbers (array) of the detected crypto asset, if known or applicable.
- `offsets`: offsets (array) in which the crypto asset have been detected, if known or applicable.
- `symbols`: symbol names (array) of the detected crypto asset, if known or applicable.
- `keywords`: keywords (array) used to detect the crypto asset, if known or applicable.
- `additionalContext`: additional context of the detected crypto asset (e.g. code snippet).

#### General considerations

Some of the CBOM property enums allow to specify "other" and "unknown". The value "other" refers to types not defined by the enum (e.g. a new cryptographic `primitive`). The value "unknown" refers to entries not known to the tool that built the CBOM (e.g. if the `implementationPlatform` is unknown).

### Dependencies

CBOM uses the CycloneDX `dependency` object and extends it with a property `dependencyType`:

```
"dependencyType": {
    "type": "string",
    "enum": [
      "implements",
      "uses"
    ],
    "title": "Type to characterize a dependency"
}
```

The two dependency types are:

- `implements`: refers to crypto assets implemented, or statically available in a component. Examples are the algorithms provided by crypto libraries. A crypto asset 'implemented' by a component does not imply that it is in use.
- `uses`: refers to crypto assets in use, or being referenced by other components. The referencing can be done by explicit function calls or by configuration at run time. Usage may change over time, so CBOMs always represent a snapshot at a given point in time.

A component can have a dependencies of both types `implements` and `uses`. A crypto asset A is considered as 'used' by component C if there is a `uses` dependency path from C to A.

## Examples

The file [EXAMPLES.md](EXAMPLES.md) contains examples for creating CBOMs.

## Schema Validation

To validate CBOMs against the schema with `ajv`:

```
$ ajv validate --spec=draft7 --validate-formats=false -r spdx.schema.json -r jsf-0.82.schema.json --strict=false -s bom-1.4-cbom-1.0.schema.json -d <cbom.json>
<cbom.json> valid
```

## Notes for future releases

To converge the CBOM schema with CycloneDX, a future version of CBOM may use the `externalReference` property of CycloneDX that links to an external CBOM schema with its `cryptoProperties`. This would enable a path for upstreaming the CBOM extension to CycloneDX.
