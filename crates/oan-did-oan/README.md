<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# oan-did-oan

`did:oan` parsing, generation, and validation utilities.

The canonical identifier form is:

```text
did:oan:<semantic-code>:<32-char-base58-suffix>
```

The suffix is stable identifier material. It does not encode key material,
cryptographic suite, service endpoint, package version, or resource metadata.
