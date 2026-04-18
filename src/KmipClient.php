<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * KMIP client -- connects to any KMIP 1.4 server via mTLS.
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
 *   // $key is a binary string of raw key bytes
 *
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

    /**
     * Locate keys by name.
     *
     * @return string[] Array of unique identifiers.
     */
    public function locate(string $name): array
    {
        $request = Operations::buildLocateRequest($name);
        $responseData = $this->send($request);
        $response = Operations::parseResponse($responseData);
        return Operations::parseLocatePayload($response['payload'])['unique_identifiers'];
    }

    /**
     * Get key material by unique ID.
     *
     * @return array{object_type: ?int, unique_identifier: ?string, key_material: ?string}
     */
    public function get(string $uniqueId): array
    {
        $request = Operations::buildGetRequest($uniqueId);
        $responseData = $this->send($request);
        $response = Operations::parseResponse($responseData);
        return Operations::parseGetPayload($response['payload']);
    }

    /**
     * Create a new symmetric key on the server.
     *
     * @return array{object_type: ?int, unique_identifier: ?string}
     */
    public function create(string $name, ?string $algorithm = null, int $length = 256): array
    {
        $algoMap = [
            'AES' => Algorithm::AES,
            'DES' => Algorithm::DES,
            'TripleDES' => Algorithm::TRIPLE_DES,
            'RSA' => Algorithm::RSA,
        ];
        $algoEnum = Algorithm::AES;
        if ($algorithm !== null) {
            $algoEnum = $algoMap[$algorithm] ?? $algoMap[strtoupper($algorithm)] ?? Algorithm::AES;
        }

        $request = Operations::buildCreateRequest($name, $algoEnum, $length);
        $responseData = $this->send($request);
        $response = Operations::parseResponse($responseData);
        return Operations::parseCreatePayload($response['payload']);
    }

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
