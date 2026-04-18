<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * KMIP request/response builders for Locate, Get, Create operations.
 */
final class Operations
{
    // Protocol version: KMIP 1.4
    public const PROTOCOL_MAJOR = 1;
    public const PROTOCOL_MINOR = 4;

    /**
     * Build the request header (included in every request).
     */
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
     * Build a Locate request -- find keys by name.
     */
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

        $batchItem = Ttlv::encodeStructure(Tag::BATCH_ITEM, [
            Ttlv::encodeEnum(Tag::OPERATION, Operation::LOCATE),
            $payload,
        ]);

        return Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, [
            self::buildRequestHeader(),
            $batchItem,
        ]);
    }

    /**
     * Build a Get request -- fetch key material by unique ID.
     */
    public static function buildGetRequest(string $uniqueId): string
    {
        $payload = Ttlv::encodeStructure(Tag::REQUEST_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, $uniqueId),
        ]);

        $batchItem = Ttlv::encodeStructure(Tag::BATCH_ITEM, [
            Ttlv::encodeEnum(Tag::OPERATION, Operation::GET),
            $payload,
        ]);

        return Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, [
            self::buildRequestHeader(),
            $batchItem,
        ]);
    }

    /**
     * Build a Create request -- create a new symmetric key.
     */
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

        $batchItem = Ttlv::encodeStructure(Tag::BATCH_ITEM, [
            Ttlv::encodeEnum(Tag::OPERATION, Operation::CREATE),
            $payload,
        ]);

        return Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, [
            self::buildRequestHeader(),
            $batchItem,
        ]);
    }

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

    /**
     * Parse a Locate response payload.
     *
     * @return array{unique_identifiers: string[]}
     */
    public static function parseLocatePayload(array $payload): array
    {
        $ids = Ttlv::findChildren($payload, Tag::UNIQUE_IDENTIFIER);
        return [
            'unique_identifiers' => array_map(fn($id) => $id['value'], $ids),
        ];
    }

    /**
     * Parse a Get response payload.
     *
     * @return array{object_type: ?int, unique_identifier: ?string, key_material: ?string}
     */
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

    /**
     * Parse a Create response payload.
     *
     * @return array{object_type: ?int, unique_identifier: ?string}
     */
    public static function parseCreatePayload(array $payload): array
    {
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $objType = Ttlv::findChild($payload, Tag::OBJECT_TYPE);
        return [
            'object_type' => $objType ? $objType['value'] : null,
            'unique_identifier' => $uid ? $uid['value'] : null,
        ];
    }
}
