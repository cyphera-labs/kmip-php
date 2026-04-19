<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * KMIP client -- connects to any KMIP 1.4 server via mTLS.
 *
 * Supports all 27 KMIP 1.4 operations:
 *   Create, CreateKeyPair, Register, ReKey, DeriveKey,
 *   Locate, Check, Get, GetAttributes, GetAttributeList,
 *   AddAttribute, ModifyAttribute, DeleteAttribute,
 *   ObtainLease, Activate, Revoke, Destroy,
 *   Archive, Recover, Query, Poll, DiscoverVersions,
 *   Encrypt, Decrypt, Sign, SignatureVerify, MAC.
 *
 * Usage:
 *   $client = new KmipClient([
 *       'host' => 'kmip-server.corp.internal',
 *       'clientCert' => '/path/to/client.pem',
 *       'clientKey' => '/path/to/client-key.pem',
 *       'caCert' => '/path/to/ca.pem',
 *   ]);
 *
 *   $key = $client->fetchKey('my-key-name');
 *   $client->close();
 */
final class KmipClient
{
    private string $host;
    private int $port;
    private int $timeout;
    private string $clientCert;
    private string $clientKey;
    private ?string $caCert;

    /** @var resource|null */
    private $socket = null;

    /**
     * @param array{
     *     host: string,
     *     port?: int,
     *     clientCert: string,
     *     clientKey: string,
     *     caCert?: string,
     *     timeout?: int
     * } $options
     */
    public function __construct(array $options)
    {
        $this->host = $options['host'];
        $this->port = $options['port'] ?? 5696;
        $this->timeout = $options['timeout'] ?? 10;
        $this->clientCert = $options['clientCert'];
        $this->clientKey = $options['clientKey'];
        $this->caCert = $options['caCert'] ?? null;
    }

    // -----------------------------------------------------------------------
    // 1. Create
    // -----------------------------------------------------------------------

    /**
     * Create a new symmetric key on the server.
     *
     * @return array{object_type: ?int, unique_identifier: ?string}
     */
    public function create(string $name, int $algorithm = Algorithm::AES, int $length = 256): array
    {
        $request = Operations::buildCreateRequest($name, $algorithm, $length);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseCreatePayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 2. CreateKeyPair
    // -----------------------------------------------------------------------

    /**
     * Create a new asymmetric key pair on the server.
     *
     * @return array{private_key_uid: ?string, public_key_uid: ?string}
     */
    public function createKeyPair(string $name, int $algorithm, int $length): array
    {
        $request = Operations::buildCreateKeyPairRequest($name, $algorithm, $length);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseCreateKeyPairPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 3. Register
    // -----------------------------------------------------------------------

    /**
     * Register existing key material on the server.
     *
     * @return array{object_type: ?int, unique_identifier: ?string}
     */
    public function register(int $objectType, string $material, string $name, int $algorithm, int $length): array
    {
        $request = Operations::buildRegisterRequest($objectType, $material, $name, $algorithm, $length);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseCreatePayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 4. ReKey
    // -----------------------------------------------------------------------

    /**
     * Re-key an existing key on the server.
     *
     * @return array{unique_identifier: ?string}
     */
    public function reKey(string $uniqueId): array
    {
        $request = Operations::buildReKeyRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseReKeyPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 5. DeriveKey
    // -----------------------------------------------------------------------

    /**
     * Derive a new key from an existing key.
     *
     * @return array{unique_identifier: ?string}
     */
    public function deriveKey(string $uniqueId, string $derivationData, string $name, int $length): array
    {
        $request = Operations::buildDeriveKeyRequest($uniqueId, $derivationData, $name, $length);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseDeriveKeyPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 6. Locate
    // -----------------------------------------------------------------------

    /**
     * Locate keys by name.
     *
     * @return string[] Array of unique identifiers.
     */
    public function locate(string $name): array
    {
        $request = Operations::buildLocateRequest($name);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseLocatePayload($response['payload'])['unique_identifiers'];
    }

    // -----------------------------------------------------------------------
    // 7. Check
    // -----------------------------------------------------------------------

    /**
     * Check the status of a managed object.
     *
     * @return array{unique_identifier: ?string}
     */
    public function check(string $uniqueId): array
    {
        $request = Operations::buildCheckRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseCheckPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 8. Get
    // -----------------------------------------------------------------------

    /**
     * Get key material by unique ID.
     *
     * @return array{object_type: ?int, unique_identifier: ?string, key_material: ?string}
     */
    public function get(string $uniqueId): array
    {
        $request = Operations::buildGetRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseGetPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 9. GetAttributes
    // -----------------------------------------------------------------------

    /**
     * Fetch all attributes of a managed object.
     *
     * @return array{object_type: ?int, unique_identifier: ?string, key_material: ?string}
     */
    public function getAttributes(string $uniqueId): array
    {
        $request = Operations::buildGetAttributesRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseGetPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 10. GetAttributeList
    // -----------------------------------------------------------------------

    /**
     * Fetch the list of attribute names for a managed object.
     *
     * @return string[]
     */
    public function getAttributeList(string $uniqueId): array
    {
        $request = Operations::buildGetAttributeListRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        if ($response['payload'] === null) {
            return [];
        }
        return Operations::parseGetAttributeListPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 11. AddAttribute
    // -----------------------------------------------------------------------

    /**
     * Add an attribute to a managed object.
     */
    public function addAttribute(string $uniqueId, string $name, string $value): void
    {
        $request = Operations::buildAddAttributeRequest($uniqueId, $name, $value);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 12. ModifyAttribute
    // -----------------------------------------------------------------------

    /**
     * Modify an attribute of a managed object.
     */
    public function modifyAttribute(string $uniqueId, string $name, string $value): void
    {
        $request = Operations::buildModifyAttributeRequest($uniqueId, $name, $value);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 13. DeleteAttribute
    // -----------------------------------------------------------------------

    /**
     * Delete an attribute from a managed object.
     */
    public function deleteAttribute(string $uniqueId, string $name): void
    {
        $request = Operations::buildDeleteAttributeRequest($uniqueId, $name);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 14. ObtainLease
    // -----------------------------------------------------------------------

    /**
     * Obtain a lease for a managed object. Returns lease time in seconds.
     */
    public function obtainLease(string $uniqueId): int
    {
        $request = Operations::buildObtainLeaseRequest($uniqueId);
        $response = Operations::parseResponse($this->send($request));
        if ($response['payload'] === null) {
            return 0;
        }
        $result = Operations::parseObtainLeasePayload($response['payload']);
        return $result['lease_time'] ?? 0;
    }

    // -----------------------------------------------------------------------
    // 15. Activate
    // -----------------------------------------------------------------------

    /**
     * Set a key's state to Active.
     */
    public function activate(string $uniqueId): void
    {
        $request = Operations::buildActivateRequest($uniqueId);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 16. Revoke
    // -----------------------------------------------------------------------

    /**
     * Revoke a managed object with the given reason code.
     */
    public function revoke(string $uniqueId, int $reason): void
    {
        $request = Operations::buildRevokeRequest($uniqueId, $reason);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 17. Destroy
    // -----------------------------------------------------------------------

    /**
     * Destroy a key by unique ID.
     */
    public function destroy(string $uniqueId): void
    {
        $request = Operations::buildDestroyRequest($uniqueId);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 18. Archive
    // -----------------------------------------------------------------------

    /**
     * Archive a managed object.
     */
    public function archive(string $uniqueId): void
    {
        $request = Operations::buildArchiveRequest($uniqueId);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 19. Recover
    // -----------------------------------------------------------------------

    /**
     * Recover an archived managed object.
     */
    public function recover(string $uniqueId): void
    {
        $request = Operations::buildRecoverRequest($uniqueId);
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 20. Query
    // -----------------------------------------------------------------------

    /**
     * Query the server for supported operations and object types.
     *
     * @return array{operations: int[], object_types: int[]}
     */
    public function query(): array
    {
        $request = Operations::buildQueryRequest();
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseQueryPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 21. Poll
    // -----------------------------------------------------------------------

    /**
     * Poll the server.
     */
    public function poll(): void
    {
        $request = Operations::buildPollRequest();
        Operations::parseResponse($this->send($request));
    }

    // -----------------------------------------------------------------------
    // 22. DiscoverVersions
    // -----------------------------------------------------------------------

    /**
     * Discover the KMIP versions supported by the server.
     *
     * @return array{versions: array<array{major: int, minor: int}>}
     */
    public function discoverVersions(): array
    {
        $request = Operations::buildDiscoverVersionsRequest();
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseDiscoverVersionsPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 23. Encrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypt data using a managed key.
     *
     * @return array{data: ?string, nonce: ?string}
     */
    public function encrypt(string $uniqueId, string $data): array
    {
        $request = Operations::buildEncryptRequest($uniqueId, $data);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseEncryptPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 24. Decrypt
    // -----------------------------------------------------------------------

    /**
     * Decrypt data using a managed key.
     *
     * @return array{data: ?string}
     */
    public function decrypt(string $uniqueId, string $data, string $nonce = ''): array
    {
        $request = Operations::buildDecryptRequest($uniqueId, $data, $nonce);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseDecryptPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 25. Sign
    // -----------------------------------------------------------------------

    /**
     * Sign data using a managed key.
     *
     * @return array{signature_data: ?string}
     */
    public function sign(string $uniqueId, string $data): array
    {
        $request = Operations::buildSignRequest($uniqueId, $data);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseSignPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 26. SignatureVerify
    // -----------------------------------------------------------------------

    /**
     * Verify a signature using a managed key.
     *
     * @return array{valid: bool}
     */
    public function signatureVerify(string $uniqueId, string $data, string $signature): array
    {
        $request = Operations::buildSignatureVerifyRequest($uniqueId, $data, $signature);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseSignatureVerifyPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // 27. MAC
    // -----------------------------------------------------------------------

    /**
     * Compute a MAC using a managed key.
     *
     * @return array{mac_data: ?string}
     */
    public function mac(string $uniqueId, string $data): array
    {
        $request = Operations::buildMacRequest($uniqueId, $data);
        $response = Operations::parseResponse($this->send($request));
        return Operations::parseMacPayload($response['payload']);
    }

    // -----------------------------------------------------------------------
    // Convenience methods
    // -----------------------------------------------------------------------

    /**
     * Convenience: locate by name + get material in one call.
     *
     * @return string Raw key bytes.
     */
    public function fetchKey(string $name): string
    {
        $ids = $this->locate($name);
        if (empty($ids)) {
            throw new \RuntimeException(sprintf('KMIP: no key found with name "%s"', $name));
        }
        $result = $this->get($ids[0]);
        if ($result['key_material'] === null) {
            throw new \RuntimeException(sprintf(
                'KMIP: key "%s" (%s) has no extractable material',
                $name,
                $ids[0]
            ));
        }
        return $result['key_material'];
    }

    /**
     * Resolve an algorithm name string to its KMIP enum value.
     * Returns Algorithm::AES for unknown names.
     */
    public static function resolveAlgorithm(string $name): int
    {
        return match (strtoupper($name)) {
            'AES' => Algorithm::AES,
            'DES' => Algorithm::DES,
            'TRIPLEDES', '3DES' => Algorithm::TRIPLE_DES,
            'RSA' => Algorithm::RSA,
            'DSA' => Algorithm::DSA,
            'ECDSA' => Algorithm::ECDSA,
            'HMACSHA1' => Algorithm::HMAC_SHA1,
            'HMACSHA256' => Algorithm::HMAC_SHA256,
            'HMACSHA384' => Algorithm::HMAC_SHA384,
            'HMACSHA512' => Algorithm::HMAC_SHA512,
            default => 0,
        };
    }

    // -----------------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------------

    /**
     * Close the TLS connection.
     */
    public function close(): void
    {
        if ($this->socket !== null) {
            fclose($this->socket);
            $this->socket = null;
        }
    }

    /**
     * Send a KMIP request and receive the response.
     */
    private function send(string $request): string
    {
        $socket = $this->connect();
        fwrite($socket, $request);

        // Read TTLV header (8 bytes) to determine total length
        $header = $this->recvExact($socket, 8);
        $unpacked = unpack('N', substr($header, 4, 4));
        $valueLength = $unpacked[1];
        $body = $this->recvExact($socket, $valueLength);
        return $header . $body;
    }

    /**
     * Receive exactly $n bytes from the socket.
     *
     * @param resource $socket
     */
    private function recvExact($socket, int $n): string
    {
        $data = '';
        while (strlen($data) < $n) {
            $chunk = fread($socket, $n - strlen($data));
            if ($chunk === false || $chunk === '') {
                throw new \RuntimeException('KMIP connection closed unexpectedly');
            }
            $data .= $chunk;
        }
        return $data;
    }

    /**
     * Establish or reuse the mTLS connection.
     *
     * @return resource
     */
    private function connect()
    {
        if ($this->socket !== null) {
            return $this->socket;
        }

        $context = stream_context_create([
            'ssl' => array_filter([
                'local_cert' => $this->clientCert,
                'local_pk' => $this->clientKey,
                'cafile' => $this->caCert,
                'verify_peer' => $this->caCert !== null,
                'verify_peer_name' => $this->caCert !== null,
                'allow_self_signed' => $this->caCert === null,
            ], fn($v) => $v !== null),
        ]);

        $address = sprintf('ssl://%s:%d', $this->host, $this->port);
        $socket = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            throw new \RuntimeException(sprintf('KMIP connection failed: %s (%d)', $errstr, $errno));
        }

        stream_set_timeout($socket, $this->timeout);
        $this->socket = $socket;
        return $socket;
    }
}
