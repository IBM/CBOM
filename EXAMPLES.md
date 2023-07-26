# Cryptography Bill of Materials - Examples

This document provides examples for using Cryptography Bills of Materials (CBOMs).

- [Cryptography Bill of Materials - Examples](#cryptography-bill-of-materials---examples)
- [Components](#components)
  - [Algorithm](#algorithm)
  - [Key](#key)
  - [Protocol](#protocol)
  - [Library](#library)
  - [Application](#application)
  - [Certificate](#certificate)
  - [CBOM Project Metadata](#cbom-project-metadata)
- [Dependencies](#dependencies)
  - [Dependencies viewed from an application](#dependencies-viewed-from-an-application)
  - [Dependencies viewed from a library](#dependencies-viewed-from-a-library)

# Components

## Algorithm

A crypto algorithm is added in the `components` array of the BOM. The examples below lists the algorithm `AES-128-GCM` and `SHA512withRSA`.

```json
"components": [
    {
        "name": "AES-128-GCM",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6",
        "purl": "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "aes128-gcm",
                "primitive": "ae",
                "mode": "gcm",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "keygen", 
                    "encrypt", 
                    "decrypt", 
                    "tag"
                ],
                "classicalSecurityLevel": 128,
                "nistQuantumSecurityLevel": 1
            },
            "oid": "2.16.840.1.101.3.4.1.6"
        }
    },
    {
        "name": "SHA512withRSA",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/sha512-rsa@1.2.840.113549.1.1.13",
        "purl": "pkg:crypto/algorithm/sha512-rsa@1.2.840.113549.1.1.13",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "sha512-rsa",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "digest"
                ],
                "nistQuantumSecurityLevel": 0
            },
            "oid": "1.2.840.113549.1.1.13"
        }
    }
]
```

An example with the QSC Signature algorithm `Dilithium-5` is listed below.

```json
"components": [
    {
        "name": "Dilithium-5",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/dilithium5@1.3.6.1.4.1.2.267.7.8.7",
        "purl": "pkg:crypto/algorithm/dilithium5@1.3.6.1.4.1.2.267.7.8.7",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "dilithium5",
                "primitive": "signature",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": ["keygen", "sign", "verify"],
                "nistQuantumSecurityLevel": 5
            },
            "oid": "1.3.6.1.4.1.2.267.7.8.7"
        }
    }
]
```

## Key

A cryptographic key is added in the `components` array of the BOM. The example below lists an `RSA-2048` public key.

```json
"components": [
    {
        "name": "RSA-2048",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/key/rsa2048@1.2.840.113549.1.1.1",
        "purl": "pkg:crypto/key/rsa2048@1.2.840.113549.1.1.1",
        "cryptoProperties": {
            "assetType": "key",
            "keyProperties": {
                "type": "publicKey",
                "id": "2e9ef09e-dfac-4526-96b4-d02f31af1b22",
                "state": "active",
                "size": 2048,
                "keyAlgorithmRef": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
                "securedBy": {
                    "mechanism": "Software",
                    "algorithmRef": "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6"
                },
                "creationDate": "2016-11-21T08:00:00Z",
                "activationDate": "2016-11-21T08:20:00Z",
            },
            "oid": "1.2.840.113549.1.1.1"
        }
    },
    {
        "name": "RSA-2048",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "purl": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "rsa2048",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "encapsulate",
                    "decapsulate"
                ],
            },
            "oid": "1.2.840.113549.1.1.1"
        }
    },
    {
        "name": "AES-128-GCM",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6",
        "purl": "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "aes128-gcm",
                "primitive": "ae",
                "mode": "gcm",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "keygen", 
                    "encrypt", 
                    "decrypt"
                ],
                "classicalSecurityLevel": 128,
                "nistQuantumSecurityLevel": 1
            },
            "oid": "2.16.840.1.101.3.4.1.6"
        }
    }
]
```


## Protocol

A cryptographic protocol is added to the `components` array of the BOM. The example below lists an instance of the protocol `TLS v1.2` with a number of TLS cipher suites.

```json
"components": [
    {
        "name": "TLSv1.2",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/protocol/tls@1.2",
        "purl": "pkg:crypto/protocol/tls@1.2",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "tls",
                "version": "1.2",
                "cipherSuites": [
                    {
                        "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "algorithms": [
                            "pkg:crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
                            "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
                            "pkg:crypto/algorithm/aes128-gcm@2.16.840.1.101.3.4.1.6",
                            "pkg:crypto/algorithm/sha384@2.16.840.1.101.3.4.2.9"
                        ],
                        "identifiers": [
                            "0xC0",
                            "0x30"
                        ]
                    }
                ]
            },
            "oid": "1.3.18.0.2.32.104"
        }
    },
    {
        "name": "ECDH",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
        "purl": "pkg:crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "ecdh-curve25519",
                "curve": "curve25519",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "keygen",
                ],
            },
            "oid": "1.3.132.1.12"
        }
    },
    {
        "name": "RSA-2048",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "purl": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "rsa2048",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "encapsulate",
                    "decapsulate"
                ],
            },
            "oid": "1.2.840.113549.1.1.1"
        }
    },
    {
        "name": "AES-256-GCM",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/aes256-gcm@2.16.840.1.101.3.4.1.46",
        "purl": "pkg:crypto/algorithm/aes256-gcm@2.16.840.1.101.3.4.1.46",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "aes256-gcm",
                "primitive": "ae",
                "mode": "gcm",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [ 
                    "encrypt", 
                    "decrypt"
                ],
                "classicalSecurityLevel": 128,
                "nistQuantumSecurityLevel": 1
            },
            "oid": "2.16.840.1.101.3.4.1.46"
        }
    },
    {
        "name": "SHA384",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/sha384@2.16.840.1.101.3.4.2.9",
        "purl": "pkg:crypto/algorithm/sha384@2.16.840.1.101.3.4.2.9",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "sha384",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "digest", 
                ],
                "nistQuantumSecurityLevel": 2
            },
            "oid": "2.16.840.1.101.3.4.2.9"
        }
    }
]
```

## Library

Crypto libraries use the standard CycloneDX type `library`. A way to declare the bom-ref is to use [CPE](https://nvd.nist.gov/products/cpe). The example below lists the OpenSSL 1.1.1q library:

```json
"components": [
    {
        "type": "library",
        "bom-ref": "cpe:2.3:a:openssl:openssl:1.1.1q:*:*:*:*:*:*:*",
        "name": "openssl",
        "version": "1.1.1q"
    }
]      
```

## Application

Applications use the standard CycloneDX type `application`. A way to declare the bom-ref is to use [CPE](https://nvd.nist.gov/products/cpe). The example below lists the nginx 1.23.2 application:

```json
"components": [
    {
        "type": "application",
        "bom-ref": "cpe:2.3:a:f5:nginx:1.23.2:*:*:*:*:*:*:*",
        "name": "nginx",
        "version": "1.23.2"
    }
]
```

## Certificate

A crypto algorithm is added in the `components` array of the BOM. The example below lists a X.509 certificate.

```json
"components": [
    {
        "name": "google.com",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/certificate/google.com@sha256:1e15e0fbd3ce95bde5945633ae96add551341b11e5bae7bba12e98ad84a5beb4",
        "purl": "pkg:crypto/certificate/google.com@sha256:1e15e0fbd3ce95bde5945633ae96add551341b11e5bae7bba12e98ad84a5beb4",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": "CN = www.google.com",
                "issuerName": "C = US, O = Google Trust Services LLC, CN = GTS CA 1C3",
                "notValidBefore": "2016-11-21T08:00:00Z",
                "notValidAfter": "2017-11-22T07:59:59Z",
                "signatureAlgorithm": "pkg:crypto/algorithm/sha512-rsa@1.2.840.113549.1.1.13",
                "subjectPublicKeyAlgorithm": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
                "subjectPublicKey": "pkg:crypto/key/rsa2048@1.2.840.113549.1.1.1",
                "certificateFormat": "X.509",
                "certificateExtension": "crt"
            }
        }
    },
    {
        "name": "SHA512withRSA",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/sha512-rsa@1.2.840.113549.1.1.13",
        "purl": "pkg:crypto/algorithm/sha512-rsa@1.2.840.113549.1.1.13",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "sha512-rsa",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "digest"
                ],
                "nistQuantumSecurityLevel": 0
            },
            "oid": "1.2.840.113549.1.1.13"
        }
    },
    {
        "name": "RSA-2048",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/key/rsa2048@1.2.840.113549.1.1.1",
        "purl": "pkg:crypto/key/rsa2048@1.2.840.113549.1.1.1",
        "cryptoProperties": {
            "assetType": "key",
            "keyProperties": {
                "type": "publicKey",
                "id": "2e9ef09e-dfac-4526-96b4-d02f31af1b22",
                "state": "active",
                "size": 2048,
                "keyAlgorithmRef": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
                "securedBy": {
                    "mechanism": "None"
                },
                "creationDate": "2016-11-21T08:00:00Z",
                "activationDate": "2016-11-21T08:20:00Z",
            },
            "oid": "1.2.840.113549.1.1.1"
        }
    },
    {
        "name": "RSA-2048",
        "type": "crypto-asset",
        "bom-ref": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "purl": "pkg:crypto/algorithm/rsa2048@1.2.840.113549.1.1.1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "variant": "rsa2048",
                "implementationLevel": "softwarePlainRam",
                "implementationPlatform": "x86_64",
                "certificationLevel": "none",
                "cryptoFunctions": [
                    "encapsulate",
                    "decapsulate"
                ],
            },
            "oid": "1.2.840.113549.1.1.1"
        }
    }
]
```

## CBOM Project Metadata

The `metadata` property of CBOM is used to describe the main project component.

```json
{
    "bomFormat": "CBOM",
    "specVersion": "1.5-cbom-1.1",
    "serialNumber": "urn:uuid:63304c0b-0d43-43cb-b0a7-f75b4b7ecf98",
    "version": 1,
    "metadata": {
        "timestamp": "2022-11-30T10:22:42.812881+00:00",
        "component": {
            "type": "application",
            "bom-ref": "cpe:2.3:a:f5:nginx:1.23.2:*:*:*:*:*:*:*",
            "name": "nginx",
            "version": "1.23.2"
        }
    },
    "components": [
      ...
    ]
}
```

# Dependencies

Dependencies between components in the `components` array are added to the `dependencies` array.

The two dependency types are:

- `implements`: refers to crypto assets implemented, or statically available in a component. Examples are the algorithms provided by crypto libraries. A crypto asset 'implemented' by a component does not imply that it is in use.
- `uses`: refers to crypto assets in use, or being referenced by other components. The referencing can be done by explicit function calls or by configuration at run time. Usage may change over time, so CBOMs always represent a snapshot at a given point in time.

A component can have a dependencies of both types `implements` and `uses`. A crypto asset A is considered as 'used' by component C if there is a `used` dependency path from C to A.

## Dependencies viewed from an application

The chart below shows a partial dependency graph from a CBOM of the application `nginx`. Dependency types `uses` are marked with `u` and dependency types `implements` are marked with `i`.

![Dependency graph of an application](img/app-cbom.png "Dependency graph of an application")

Key conclusions from the dependency graph:
- A `uses` path exists from nginx to TLS v1.3, AES-128-GCM, SHA256 and HMAC-DRBG. These crypto assets can be considered used by nginx.
- No `uses` paths from nginx to TLS v1.2, SSL v3 and MD5 exists. These crypto assets can be considered implemented by libraries (libssl.so, libcrypto.so) but not used by nginx.

Note: Suppose that SSL v3 uses MD5. The dependency graph will still show no `uses` dependency from libcrypto.so to MD5 since there is no `uses` dependency from any component to SSL v3.

The dependency array of the CBOM will look as follows (for simplicity, we use the crypto asset names as the `bom-ref` property. In practice, one use CPE, purl and OID identifiers):

```
    "dependencies": [
        {
            "ref": "nginx",
            "dependsOn": [
                "libssl"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "libssl.so",
            "dependsOn": [
                "TLS v1.3", "TLS v1.2", "SSL v3"
            ],
            "dependencyType": "implements"
        },
        {
            "ref": "libssl.so",
            "dependsOn": [
                "TLS v1.3"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "TLS v1.3",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "TLS v1.2",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "SSL v3",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "libcrypto.so",
            "dependsOn": [
                "MD5", "AES-128-GCM", "SHA256", "HMAC-DRBG"
            ],
            "dependencyType": "implements"
        },
        {
            "ref": "libcrypto.so",
            "dependsOn": [
                "AES-128-GCM", "SHA256", "HMAC-DRBG"
            ],
            "dependencyType": "uses"
        }
    ]
```

## Dependencies viewed from a library

The chart below shows a partial dependency graph from a CBOM of crypto library `libssl.so`.

![Dependency graph of a library](img/lib-cbom.png "Dependency graph of a library")

Key conclusions from the dependency graph:
- libssl.so implements TLS protocol versions TLS v1.3, TLS v1.2 and SSL v3
- The TLS protocols versions TLS v1.3, TLS v1.2 and SSL v3 use libcrypto.so

Note that, in contrast to the dependencies viewed from the application, there are no `uses` dependencies from libcrypto.so to any algorithm. This is because there is no `uses` dependency to any of the TLS protocol versions. If, for example, SSL v3 is the top level component, `uses` dependencies to the algorithms used by SSL v3 are added.

The dependency array of the CBOM will look as follows (for simplicity, we use the crypto asset names as the `bom-ref` property. In practice, one use CPE, purl and OID identifiers):

```
    "dependencies": [
        {
            "ref": "libssl.so",
            "dependsOn": [
                "TLS v1.3", "TLS v1.2", "SSL v3"
            ],
            "dependencyType": "implements"
        },
        {
            "ref": "TLS v1.3",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "TLS v1.2",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "SSL v3",
            "dependsOn": [
                "libcrypto.so"
            ],
            "dependencyType": "uses"
        },
        {
            "ref": "libcrypto.so",
            "dependsOn": [
                "MD5", "AES-128-GCM", "SHA256", "HMAC-DRBG"
            ],
            "dependencyType": "implements"
        }
    ]
```
