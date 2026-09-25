<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# oan-did-oan

`did:oan` parsing, generation, and validation utilities.

The canonical identifier form is:

```text
did:oan:<routing-code>:<suffix-code>
```

`routing-code` is exactly 5 case-sensitive Base58 characters and records the
direct upstream identifier prefix used when the DID was created. `suffix-code`
is exactly 32 case-sensitive Base58 characters and provides the stable
identifier material. Neither field encodes key material, cryptographic suite,
service endpoint, package version, resource metadata, resource type, trust
state, or authorization domain.
