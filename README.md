# kmip-php

[![CI](https://github.com/cyphera-labs/kmip-php/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-php/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-php/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-php/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for PHP -- connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```
composer require cyphera/kmip
```

## Quick Start

```php
<?php

use Cyphera\Kmip\KmipClient;

$client = new KmipClient([
    'host' => 'kmip-server.corp.internal',
    'clientCert' => '/path/to/client.pem',
    'clientKey' => '/path/to/client-key.pem',
    'caCert' => '/path/to/ca.pem',
]);

// Fetch a key by name (locate + get in one call)
$key = $client->fetchKey('my-encryption-key');
// $key is a binary string of raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
$ids = $client->locate('my-key');
$result = $client->get($ids[0]);
echo bin2hex($result['key_material']);

// Create a new AES-256 key on the server
$created = $client->create('new-key-name', 'AES', 256);
echo $created['unique_identifier'];

$client->close();
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `$client->locate($name)` | Find keys by name, returns unique IDs |
| Get | `$client->get($id)` | Fetch key material by unique ID |
| Create | `$client->create($name, $algo, $length)` | Create a new symmetric key |
| Fetch | `$client->fetchKey($name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** -- identifies your application to the KMS
- **Client private key** -- proves ownership of the certificate
- **CA certificate** -- validates the KMS server's certificate

```php
$client = new KmipClient([
    'host' => 'kmip.corp.internal',
    'port' => 5696,                          // default KMIP port
    'clientCert' => '/etc/kmip/client.pem',
    'clientKey' => '/etc/kmip/client-key.pem',
    'caCert' => '/etc/kmip/ca.pem',
    'timeout' => 10,                         // connection timeout (seconds)
]);
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also available for advanced use:

```php
use Cyphera\Kmip\Ttlv;
use Cyphera\Kmip\Tag;

// Build custom KMIP messages
$msg = Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, [...]);

// Parse raw KMIP responses
$parsed = Ttlv::decode($responseBytes);
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only PHP standard library (`pack`/`unpack`, `stream_socket_client`, `ssl`). No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 -- Copyright 2026 Horizon Digital Engineering LLC
