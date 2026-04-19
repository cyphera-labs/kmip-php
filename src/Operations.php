<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * KMIP request/response builders and parsers for all 27 KMIP 1.4 operations.
 */
final class Operations
{
    // Protocol version: KMIP 1.4
    public const PROTOCOL_MAJOR = 1;
    public const PROTOCOL_MINOR = 4;

    // -----------------------------------------------------------------------
    // Request header (shared by every request)
    // -----------------------------------------------------------------------

    private static function buildRequestHeader(int $batchCount = 1): string
    {
        return Ttlv::encodeStructure(Tag::REQUEST_HEADER, [
            Ttlv::encodeStructure(Tag::PROTOCOL_VERSION, [
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MAJOR, self::PROTOCOL_MAJOR),
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MINOR, self::PROTOCOL_MINOR),
            ]),
            Ttlv::encodeInteger(Tag::BATCH_COUNT, $batchCount),
        ]);
    }

    /**
     * Wrap a payload in a full request message with the given operation enum.
     */
    private static function wrapRequest(int $operation, string $payload): string
    {
        $batchItem = Ttlv::encodeStructure(Tag::BATCH_ITEM, [
            Ttlv::encodeEnum(Tag::OPERATION, $operation),
            $payload,
        ]);

        return Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, [
            self::buildRequestHeader(),
            $batchItem,
        ]);
    }

    /**
     * Build a UID-only request (used by Activate, Destroy, Check, etc.).
     */
    private static function buildUidOnlyRequest(int $operation, string $uniqueId): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
        ]);
        return self::wrapRequest($operation, $payload);
    }

    /**
     * Build an empty-payload request (used by Query, Poll, DiscoverVersions).
     */
    private static function buildEmptyPayloadRequest(int $operation): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, []);
        return self::wrapRequest($operation, $payload);
    }

    // -----------------------------------------------------------------------
    // 1. Create
    // -----------------------------------------------------------------------

    public static function buildCreateRequest(
        string $name,
        int $algorithm = Algorithm::AES,
        int $length = 256
    ): string {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
            Ttlv::encodeStructure(Tag::TEMPLATE_ATTRIBUTE, [
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Algorithm'),
                    Ttlv::encodeEnum(Tag::ATTRIBUTE_VALUE, $algorithm),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Length'),
                    Ttlv::encodeInteger(Tag::ATTRIBUTE_VALUE, $length),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Usage Mask'),
                    Ttlv::encodeInteger(Tag::ATTRIBUTE_VALUE, UsageMask::ENCRYPT | UsageMask::DECRYPT),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
                    Ttlv::encodeStructure(Tag::ATTRIBUTE_VALUE, [
                        Ttlv::encodeTextString(Tag::NAME_VALUE, $name),
                        Ttlv::encodeEnum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
                    ]),
                ]),
            ]),
        ]);

        return self::wrapRequest(Operation::CREATE, $payload);
    }

    /** @return array{object_type: ?int, unique_identifier: ?string} */
    public static function parseCreatePayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $objType = Ttlv::findChild($payload, Tag::OBJECT_TYPE);
        return [
            'object_type' => $objType ? $objType['value'] : null,
            'unique_identifier' => $uid ? $uid['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 2. CreateKeyPair
    // -----------------------------------------------------------------------

    public static function buildCreateKeyPairRequest(
        string $name,
        int $algorithm,
        int $length
    ): string {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeStructure(Tag::TEMPLATE_ATTRIBUTE, [
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Algorithm'),
                    Ttlv::encodeEnum(Tag::ATTRIBUTE_VALUE, $algorithm),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Length'),
                    Ttlv::encodeInteger(Tag::ATTRIBUTE_VALUE, $length),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Usage Mask'),
                    Ttlv::encodeInteger(Tag::ATTRIBUTE_VALUE, UsageMask::SIGN | UsageMask::VERIFY),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
                    Ttlv::encodeStructure(Tag::ATTRIBUTE_VALUE, [
                        Ttlv::encodeTextString(Tag::NAME_VALUE, $name),
                        Ttlv::encodeEnum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
                    ]),
                ]),
            ]),
        ]);

        return self::wrapRequest(Operation::CREATE_KEY_PAIR, $payload);
    }

    /** @return array{private_key_uid: ?string, public_key_uid: ?string} */
    public static function parseCreateKeyPairPayload(array $payload): array
    {
        $privUid = Ttlv::findChild($payload, Tag::PRIVATE_KEY_UNIQUE_IDENTIFIER);
        $pubUid = Ttlv::findChild($payload, Tag::PUBLIC_KEY_UNIQUE_IDENTIFIER);
        return [
            'private_key_uid' => $privUid ? $privUid['value'] : null,
            'public_key_uid' => $pubUid ? $pubUid['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 3. Register
    // -----------------------------------------------------------------------

    public static function buildRegisterRequest(
        int $objectType,
        string $material,
        string $name,
        int $algorithm,
        int $length
    ): string {
        $payloadChildren = [
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, $objectType),
            Ttlv::encodeStructure(Tag::SYMMETRIC_KEY, [
                Ttlv::encodeStructure(Tag::KEY_BLOCK, [
                    Ttlv::encodeEnum(Tag::KEY_FORMAT_TYPE, KeyFormatType::RAW),
                    Ttlv::encodeStructure(Tag::KEY_VALUE, [
                        Ttlv::encodeByteString(Tag::KEY_MATERIAL, $material),
                    ]),
                    Ttlv::encodeEnum(Tag::CRYPTOGRAPHIC_ALGORITHM, $algorithm),
                    Ttlv::encodeInteger(Tag::CRYPTOGRAPHIC_LENGTH, $length),
                ]),
            ]),
        ];
        if ($name !== '') {
            $payloadChildren[] = Ttlv::encodeStructure(Tag::TEMPLATE_ATTRIBUTE, [
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
                    Ttlv::encodeStructure(Tag::ATTRIBUTE_VALUE, [
                        Ttlv::encodeTextString(Tag::NAME_VALUE, $name),
                        Ttlv::encodeEnum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
                    ]),
                ]),
            ]);
        }
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, $payloadChildren);
        return self::wrapRequest(Operation::REGISTER, $payload);
    }

    // Register reuses parseCreatePayload (returns object_type + unique_identifier)

    // -----------------------------------------------------------------------
    // 4. ReKey
    // -----------------------------------------------------------------------

    public static function buildReKeyRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::RE_KEY, $uniqueId);
    }

    /** @return array{unique_identifier: ?string} */
    public static function parseReKeyPayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        return [
            'unique_identifier' => $uid ? $uid['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 5. DeriveKey
    // -----------------------------------------------------------------------

    public static function buildDeriveKeyRequest(
        string $uniqueId,
        string $derivationData,
        string $name,
        int $length
    ): string {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeStructure(Tag::DERIVATION_PARAMETERS, [
                Ttlv::encodeByteString(Tag::DERIVATION_DATA, $derivationData),
            ]),
            Ttlv::encodeStructure(Tag::TEMPLATE_ATTRIBUTE, [
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Length'),
                    Ttlv::encodeInteger(Tag::ATTRIBUTE_VALUE, $length),
                ]),
                Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                    Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
                    Ttlv::encodeStructure(Tag::ATTRIBUTE_VALUE, [
                        Ttlv::encodeTextString(Tag::NAME_VALUE, $name),
                        Ttlv::encodeEnum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
                    ]),
                ]),
            ]),
        ]);

        return self::wrapRequest(Operation::DERIVE_KEY, $payload);
    }

    /** @return array{unique_identifier: ?string} */
    public static function parseDeriveKeyPayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        return [
            'unique_identifier' => $uid ? $uid['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 6. Locate
    // -----------------------------------------------------------------------

    public static function buildLocateRequest(string $name): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
                Ttlv::encodeStructure(Tag::ATTRIBUTE_VALUE, [
                    Ttlv::encodeTextString(Tag::NAME_VALUE, $name),
                    Ttlv::encodeEnum(Tag::NAME_TYPE, NameType::UNINTERPRETED_TEXT_STRING),
                ]),
            ]),
        ]);

        return self::wrapRequest(Operation::LOCATE, $payload);
    }

    /** @return array{unique_identifiers: string[]} */
    public static function parseLocatePayload(array $payload): array
    {
        $ids = Ttlv::findChildren($payload, Tag::UNIQUE_IDENTIFIER);
        return [
            'unique_identifiers' => array_map(fn($id) => $id['value'], $ids),
        ];
    }

    // -----------------------------------------------------------------------
    // 7. Check
    // -----------------------------------------------------------------------

    public static function buildCheckRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::CHECK, $uniqueId);
    }

    /** @return array{unique_identifier: ?string} */
    public static function parseCheckPayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        return [
            'unique_identifier' => $uid ? $uid['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 8. Get
    // -----------------------------------------------------------------------

    public static function buildGetRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::GET, $uniqueId);
    }

    /** @return array{object_type: ?int, unique_identifier: ?string, key_material: ?string} */
    public static function parseGetPayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $objType = Ttlv::findChild($payload, Tag::OBJECT_TYPE);

        // Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
        $keyMaterial = null;
        $symKey = Ttlv::findChild($payload, Tag::SYMMETRIC_KEY);
        if ($symKey !== null) {
            $keyBlock = Ttlv::findChild($symKey, Tag::KEY_BLOCK);
            if ($keyBlock !== null) {
                $keyValue = Ttlv::findChild($keyBlock, Tag::KEY_VALUE);
                if ($keyValue !== null) {
                    $material = Ttlv::findChild($keyValue, Tag::KEY_MATERIAL);
                    if ($material !== null) {
                        $keyMaterial = $material['value'];
                    }
                }
            }
        }

        return [
            'object_type' => $objType ? $objType['value'] : null,
            'unique_identifier' => $uid ? $uid['value'] : null,
            'key_material' => $keyMaterial,
        ];
    }

    // -----------------------------------------------------------------------
    // 9. GetAttributes
    // -----------------------------------------------------------------------

    public static function buildGetAttributesRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::GET_ATTRIBUTES, $uniqueId);
    }

    // GetAttributes reuses parseGetPayload

    // -----------------------------------------------------------------------
    // 10. GetAttributeList
    // -----------------------------------------------------------------------

    public static function buildGetAttributeListRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::GET_ATTRIBUTE_LIST, $uniqueId);
    }

    /** @return string[] */
    public static function parseGetAttributeListPayload(array $payload): array
    {
        $attrs = Ttlv::findChildren($payload, Tag::ATTRIBUTE_NAME);
        return array_map(fn($a) => $a['value'], $attrs);
    }

    // -----------------------------------------------------------------------
    // 11. AddAttribute
    // -----------------------------------------------------------------------

    public static function buildAddAttributeRequest(string $uniqueId, string $attrName, string $attrValue): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, $attrName),
                Ttlv::encodeTextString(Tag::ATTRIBUTE_VALUE, $attrValue),
            ]),
        ]);
        return self::wrapRequest(Operation::ADD_ATTRIBUTE, $payload);
    }

    // -----------------------------------------------------------------------
    // 12. ModifyAttribute
    // -----------------------------------------------------------------------

    public static function buildModifyAttributeRequest(string $uniqueId, string $attrName, string $attrValue): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, $attrName),
                Ttlv::encodeTextString(Tag::ATTRIBUTE_VALUE, $attrValue),
            ]),
        ]);
        return self::wrapRequest(Operation::MODIFY_ATTRIBUTE, $payload);
    }

    // -----------------------------------------------------------------------
    // 13. DeleteAttribute
    // -----------------------------------------------------------------------

    public static function buildDeleteAttributeRequest(string $uniqueId, string $attrName): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeStructure(Tag::ATTRIBUTE, [
                Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, $attrName),
            ]),
        ]);
        return self::wrapRequest(Operation::DELETE_ATTRIBUTE, $payload);
    }

    // -----------------------------------------------------------------------
    // 14. ObtainLease
    // -----------------------------------------------------------------------

    public static function buildObtainLeaseRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::OBTAIN_LEASE, $uniqueId);
    }

    /** @return array{unique_identifier: ?string, lease_time: ?int} */
    public static function parseObtainLeasePayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $lease = Ttlv::findChild($payload, Tag::LEASE_TIME);
        return [
            'unique_identifier' => $uid ? $uid['value'] : null,
            'lease_time' => $lease ? $lease['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 15. Activate
    // -----------------------------------------------------------------------

    public static function buildActivateRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::ACTIVATE, $uniqueId);
    }

    // -----------------------------------------------------------------------
    // 16. Revoke
    // -----------------------------------------------------------------------

    public static function buildRevokeRequest(string $uniqueId, int $reason): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeStructure(Tag::REVOCATION_REASON, [
                Ttlv::encodeEnum(Tag::REVOCATION_REASON_CODE, $reason),
            ]),
        ]);
        return self::wrapRequest(Operation::REVOKE, $payload);
    }

    // -----------------------------------------------------------------------
    // 17. Destroy
    // -----------------------------------------------------------------------

    public static function buildDestroyRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::DESTROY, $uniqueId);
    }

    // -----------------------------------------------------------------------
    // 18. Archive
    // -----------------------------------------------------------------------

    public static function buildArchiveRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::ARCHIVE, $uniqueId);
    }

    // -----------------------------------------------------------------------
    // 19. Recover
    // -----------------------------------------------------------------------

    public static function buildRecoverRequest(string $uniqueId): string
    {
        return self::buildUidOnlyRequest(Operation::RECOVER, $uniqueId);
    }

    // -----------------------------------------------------------------------
    // 20. Query
    // -----------------------------------------------------------------------

    public static function buildQueryRequest(): string
    {
        return self::buildEmptyPayloadRequest(Operation::QUERY);
    }

    /** @return array{operations: int[], object_types: int[]} */
    public static function parseQueryPayload(array $payload): array
    {
        $ops = Ttlv::findChildren($payload, Tag::OPERATION);
        $objTypes = Ttlv::findChildren($payload, Tag::OBJECT_TYPE);
        return [
            'operations' => array_map(fn($o) => $o['value'], $ops),
            'object_types' => array_map(fn($o) => $o['value'], $objTypes),
        ];
    }

    // -----------------------------------------------------------------------
    // 21. Poll
    // -----------------------------------------------------------------------

    public static function buildPollRequest(): string
    {
        return self::buildEmptyPayloadRequest(Operation::POLL);
    }

    // -----------------------------------------------------------------------
    // 22. DiscoverVersions
    // -----------------------------------------------------------------------

    public static function buildDiscoverVersionsRequest(): string
    {
        return self::buildEmptyPayloadRequest(Operation::DISCOVER_VERSIONS);
    }

    /** @return array{versions: array<array{major: int, minor: int}>} */
    public static function parseDiscoverVersionsPayload(array $payload): array
    {
        $versions = Ttlv::findChildren($payload, Tag::PROTOCOL_VERSION);
        $result = [];
        foreach ($versions as $v) {
            $major = Ttlv::findChild($v, Tag::PROTOCOL_VERSION_MAJOR);
            $minor = Ttlv::findChild($v, Tag::PROTOCOL_VERSION_MINOR);
            $result[] = [
                'major' => $major ? $major['value'] : 0,
                'minor' => $minor ? $minor['value'] : 0,
            ];
        }
        return ['versions' => $result];
    }

    // -----------------------------------------------------------------------
    // 23. Encrypt
    // -----------------------------------------------------------------------

    public static function buildEncryptRequest(string $uniqueId, string $data): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeByteString(Tag::DATA, $data),
        ]);
        return self::wrapRequest(Operation::ENCRYPT, $payload);
    }

    /** @return array{data: ?string, nonce: ?string} */
    public static function parseEncryptPayload(array $payload): array
    {
        $data = Ttlv::findChild($payload, Tag::DATA);
        $nonce = Ttlv::findChild($payload, Tag::IV_COUNTER_NONCE);
        return [
            'data' => $data ? $data['value'] : null,
            'nonce' => $nonce ? $nonce['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 24. Decrypt
    // -----------------------------------------------------------------------

    public static function buildDecryptRequest(string $uniqueId, string $data, string $nonce = ''): string
    {
        $payloadChildren = [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeByteString(Tag::DATA, $data),
        ];
        if ($nonce !== '') {
            $payloadChildren[] = Ttlv::encodeByteString(Tag::IV_COUNTER_NONCE, $nonce);
        }
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, $payloadChildren);
        return self::wrapRequest(Operation::DECRYPT, $payload);
    }

    /** @return array{data: ?string} */
    public static function parseDecryptPayload(array $payload): array
    {
        $data = Ttlv::findChild($payload, Tag::DATA);
        return [
            'data' => $data ? $data['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 25. Sign
    // -----------------------------------------------------------------------

    public static function buildSignRequest(string $uniqueId, string $data): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeByteString(Tag::DATA, $data),
        ]);
        return self::wrapRequest(Operation::SIGN, $payload);
    }

    /** @return array{signature_data: ?string} */
    public static function parseSignPayload(array $payload): array
    {
        $sig = Ttlv::findChild($payload, Tag::SIGNATURE_DATA);
        return [
            'signature_data' => $sig ? $sig['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // 26. SignatureVerify
    // -----------------------------------------------------------------------

    public static function buildSignatureVerifyRequest(string $uniqueId, string $data, string $signature): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeByteString(Tag::DATA, $data),
            Ttlv::encodeByteString(Tag::SIGNATURE_DATA, $signature),
        ]);
        return self::wrapRequest(Operation::SIGNATURE_VERIFY, $payload);
    }

    /** @return array{valid: bool} */
    public static function parseSignatureVerifyPayload(array $payload): array
    {
        $indicator = Ttlv::findChild($payload, Tag::VALIDITY_INDICATOR);
        // 0 = Valid, 1 = Invalid
        return [
            'valid' => $indicator !== null && $indicator['value'] === 0,
        ];
    }

    // -----------------------------------------------------------------------
    // 27. MAC
    // -----------------------------------------------------------------------

    public static function buildMacRequest(string $uniqueId, string $data): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
            Ttlv::encodeByteString(Tag::DATA, $data),
        ]);
        return self::wrapRequest(Operation::MAC, $payload);
    }

    /** @return array{mac_data: ?string} */
    public static function parseMacPayload(array $payload): array
    {
        $macData = Ttlv::findChild($payload, Tag::MAC_DATA);
        return [
            'mac_data' => $macData ? $macData['value'] : null,
        ];
    }

    // -----------------------------------------------------------------------
    // Response parser (shared by all operations)
    // -----------------------------------------------------------------------

    /**
     * Parse a KMIP response message.
     *
     * @return array{operation: ?int, result_status: ?int, result_reason: ?int, result_message: ?string, payload: ?array}
     * @throws \RuntimeException
     */
    public static function parseResponse(string $data): array
    {
        $msg = Ttlv::decode($data);
        if ($msg['tag'] !== Tag::RESPONSE_MESSAGE) {
            throw new \RuntimeException(sprintf(
                'Expected ResponseMessage (0x42007B), got 0x%06X',
                $msg['tag']
            ));
        }

        $batchItem = Ttlv::findChild($msg, Tag::BATCH_ITEM);
        if ($batchItem === null) {
            throw new \RuntimeException('No BatchItem in response');
        }

        $operationItem = Ttlv::findChild($batchItem, Tag::OPERATION);
        $statusItem = Ttlv::findChild($batchItem, Tag::RESULT_STATUS);
        $reasonItem = Ttlv::findChild($batchItem, Tag::RESULT_REASON);
        $messageItem = Ttlv::findChild($batchItem, Tag::RESULT_MESSAGE);
        $payloadItem = Ttlv::findChild($batchItem, Tag::RESPONSE_PAYLOAD);

        $result = [
            'operation' => $operationItem ? $operationItem['value'] : null,
            'result_status' => $statusItem ? $statusItem['value'] : null,
            'result_reason' => $reasonItem ? $reasonItem['value'] : null,
            'result_message' => $messageItem ? $messageItem['value'] : null,
            'payload' => $payloadItem,
        ];

        if ($result['result_status'] !== ResultStatus::SUCCESS) {
            $errorMsg = $result['result_message']
                ?? sprintf('KMIP operation failed (status=%d)', $result['result_status']);
            throw new \RuntimeException($errorMsg);
        }

        return $result;
    }
}
