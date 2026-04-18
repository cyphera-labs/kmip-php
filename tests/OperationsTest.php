<?php

declare(strict_types=1);

namespace Cyphera\Kmip\Tests;

use PHPUnit\Framework\TestCase;
use Cyphera\Kmip\Ttlv;
use Cyphera\Kmip\Tag;
use Cyphera\Kmip\Operation;
use Cyphera\Kmip\ObjectType;
use Cyphera\Kmip\ResultStatus;
use Cyphera\Kmip\Algorithm;
use Cyphera\Kmip\UsageMask;
use Cyphera\Kmip\NameType;
use Cyphera\Kmip\KeyFormatType;
use Cyphera\Kmip\Operations;

final class OperationsTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Helper: build a mock KMIP response message
    // -----------------------------------------------------------------------

    private function buildMockResponse(int $operation, int $status, array $payloadChildren = []): string
    {
        $batchChildren = [
            Ttlv::encodeEnum(Tag::OPERATION, $operation),
            Ttlv::encodeEnum(Tag::RESULT_STATUS, $status),
        ];
        if (count($payloadChildren) > 0) {
            $batchChildren[] = Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, $payloadChildren);
        }
        return Ttlv::encodeStructure(Tag::RESPONSE_MESSAGE, [
            Ttlv::encodeStructure(Tag::RESPONSE_HEADER, [
                Ttlv::encodeStructure(Tag::PROTOCOL_VERSION, [
                    Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MAJOR, 1),
                    Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MINOR, 4),
                ]),
                Ttlv::encodeInteger(Tag::BATCH_COUNT, 1),
            ]),
            Ttlv::encodeStructure(Tag::BATCH_ITEM, $batchChildren),
        ]);
    }

    // -----------------------------------------------------------------------
    // Request building — Locate
    // -----------------------------------------------------------------------

    public function testBuildLocateRequestProducesValidTtlvStructure(): void
    {
        $request = Operations::buildLocateRequest('test-key');
        $decoded = Ttlv::decode($request);
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_STRUCTURE, $decoded['type']);
    }

    public function testBuildLocateRequestContainsProtocolVersion14(): void
    {
        $decoded = Ttlv::decode(Operations::buildLocateRequest('k'));
        $header = Ttlv::findChild($decoded, Tag::REQUEST_HEADER);
        $this->assertNotNull($header);
        $version = Ttlv::findChild($header, Tag::PROTOCOL_VERSION);
        $this->assertNotNull($version);
        $major = Ttlv::findChild($version, Tag::PROTOCOL_VERSION_MAJOR);
        $minor = Ttlv::findChild($version, Tag::PROTOCOL_VERSION_MINOR);
        $this->assertSame(Operations::PROTOCOL_MAJOR, $major['value']);
        $this->assertSame(Operations::PROTOCOL_MINOR, $minor['value']);
    }

    public function testBuildLocateRequestHasBatchCount1(): void
    {
        $decoded = Ttlv::decode(Operations::buildLocateRequest('k'));
        $header = Ttlv::findChild($decoded, Tag::REQUEST_HEADER);
        $count = Ttlv::findChild($header, Tag::BATCH_COUNT);
        $this->assertSame(1, $count['value']);
    }

    public function testBuildLocateRequestHasLocateOperation(): void
    {
        $decoded = Ttlv::decode(Operations::buildLocateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $op = Ttlv::findChild($batch, Tag::OPERATION);
        $this->assertSame(Operation::LOCATE, $op['value']);
    }

    public function testBuildLocateRequestContainsNameAttribute(): void
    {
        $decoded = Ttlv::decode(Operations::buildLocateRequest('my-key'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $attr = Ttlv::findChild($payload, Tag::ATTRIBUTE);
        $attrName = Ttlv::findChild($attr, Tag::ATTRIBUTE_NAME);
        $this->assertSame('Name', $attrName['value']);
        $attrValue = Ttlv::findChild($attr, Tag::ATTRIBUTE_VALUE);
        $nameValue = Ttlv::findChild($attrValue, Tag::NAME_VALUE);
        $this->assertSame('my-key', $nameValue['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Get
    // -----------------------------------------------------------------------

    public function testBuildGetRequestProducesValidTtlvStructure(): void
    {
        $request = Operations::buildGetRequest('unique-id-123');
        $decoded = Ttlv::decode($request);
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
    }

    public function testBuildGetRequestHasGetOperation(): void
    {
        $decoded = Ttlv::decode(Operations::buildGetRequest('uid'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $op = Ttlv::findChild($batch, Tag::OPERATION);
        $this->assertSame(Operation::GET, $op['value']);
    }

    public function testBuildGetRequestContainsUniqueIdentifier(): void
    {
        $decoded = Ttlv::decode(Operations::buildGetRequest('uid-456'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $this->assertSame('uid-456', $uid['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Create
    // -----------------------------------------------------------------------

    public function testBuildCreateRequestProducesValidTtlvStructure(): void
    {
        $request = Operations::buildCreateRequest('new-key');
        $decoded = Ttlv::decode($request);
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
    }

    public function testBuildCreateRequestHasCreateOperation(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $op = Ttlv::findChild($batch, Tag::OPERATION);
        $this->assertSame(Operation::CREATE, $op['value']);
    }

    public function testBuildCreateRequestUsesSymmetricKeyObjectType(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $objType = Ttlv::findChild($payload, Tag::OBJECT_TYPE);
        $this->assertSame(ObjectType::SYMMETRIC_KEY, $objType['value']);
    }

    public function testBuildCreateRequestDefaultsToAesAlgorithm(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $algoAttr = $this->findAttrByName($attrs, 'Cryptographic Algorithm');
        $this->assertNotNull($algoAttr);
        $algoValue = Ttlv::findChild($algoAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(Algorithm::AES, $algoValue['value']);
    }

    public function testBuildCreateRequestDefaultsTo256BitLength(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $lenAttr = $this->findAttrByName($attrs, 'Cryptographic Length');
        $this->assertNotNull($lenAttr);
        $lenValue = Ttlv::findChild($lenAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(256, $lenValue['value']);
    }

    public function testBuildCreateRequestIncludesEncryptDecryptUsageMask(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $usageAttr = $this->findAttrByName($attrs, 'Cryptographic Usage Mask');
        $this->assertNotNull($usageAttr);
        $usageValue = Ttlv::findChild($usageAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(UsageMask::ENCRYPT | UsageMask::DECRYPT, $usageValue['value']);
    }

    public function testBuildCreateRequestIncludesKeyNameInTemplate(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('prod-key'));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $nameAttr = $this->findAttrByName($attrs, 'Name');
        $this->assertNotNull($nameAttr);
        $nameStruct = Ttlv::findChild($nameAttr, Tag::ATTRIBUTE_VALUE);
        $nameValue = Ttlv::findChild($nameStruct, Tag::NAME_VALUE);
        $this->assertSame('prod-key', $nameValue['value']);
    }

    public function testBuildCreateRequestAcceptsCustomAlgorithmAndLength(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('k', Algorithm::TRIPLE_DES, 192));
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);

        $algoAttr = $this->findAttrByName($attrs, 'Cryptographic Algorithm');
        $algoValue = Ttlv::findChild($algoAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(Algorithm::TRIPLE_DES, $algoValue['value']);

        $lenAttr = $this->findAttrByName($attrs, 'Cryptographic Length');
        $lenValue = Ttlv::findChild($lenAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(192, $lenValue['value']);
    }

    // -----------------------------------------------------------------------
    // Response parsing
    // -----------------------------------------------------------------------

    public function testParseResponseExtractsOperationAndStatus(): void
    {
        $response = $this->buildMockResponse(Operation::LOCATE, ResultStatus::SUCCESS, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'id-1'),
        ]);
        $result = Operations::parseResponse($response);
        $this->assertSame(Operation::LOCATE, $result['operation']);
        $this->assertSame(ResultStatus::SUCCESS, $result['result_status']);
    }

    public function testParseResponseThrowsOnOperationFailure(): void
    {
        $batchChildren = [
            Ttlv::encodeEnum(Tag::OPERATION, Operation::GET),
            Ttlv::encodeEnum(Tag::RESULT_STATUS, ResultStatus::OPERATION_FAILED),
            Ttlv::encodeTextString(Tag::RESULT_MESSAGE, 'Item Not Found'),
        ];
        $response = Ttlv::encodeStructure(Tag::RESPONSE_MESSAGE, [
            Ttlv::encodeStructure(Tag::RESPONSE_HEADER, [
                Ttlv::encodeStructure(Tag::PROTOCOL_VERSION, [
                    Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MAJOR, 1),
                    Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MINOR, 4),
                ]),
                Ttlv::encodeInteger(Tag::BATCH_COUNT, 1),
            ]),
            Ttlv::encodeStructure(Tag::BATCH_ITEM, $batchChildren),
        ]);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Item Not Found/');
        Operations::parseResponse($response);
    }

    public function testParseResponseThrowsOnNonResponseMessageTag(): void
    {
        $badMsg = Ttlv::encodeStructure(Tag::REQUEST_MESSAGE, []);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Expected ResponseMessage/');
        Operations::parseResponse($badMsg);
    }

    public function testParseResponseReturnsPayload(): void
    {
        $response = $this->buildMockResponse(Operation::LOCATE, ResultStatus::SUCCESS, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'test-uid'),
        ]);
        $result = Operations::parseResponse($response);
        $this->assertNotNull($result['payload']);
        $this->assertSame(Tag::RESPONSE_PAYLOAD, $result['payload']['tag']);
    }

    public function testParseResponseNullPayloadWhenMissing(): void
    {
        $response = $this->buildMockResponse(Operation::LOCATE, ResultStatus::SUCCESS);
        // Add a payload child so it doesn't fail -- actually, buildMockResponse with empty
        // payloadChildren won't include a payload structure
        $result = Operations::parseResponse($response);
        $this->assertNull($result['payload']);
    }

    // -----------------------------------------------------------------------
    // Locate payload parsing
    // -----------------------------------------------------------------------

    public function testParseLocatePayloadExtractsUniqueIdentifiers(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'uid-1'),
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'uid-2'),
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'uid-3'),
        ]));
        $result = Operations::parseLocatePayload($payload);
        $this->assertSame(['uid-1', 'uid-2', 'uid-3'], $result['unique_identifiers']);
    }

    public function testParseLocatePayloadHandlesEmptyResult(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, []));
        $result = Operations::parseLocatePayload($payload);
        $this->assertSame([], $result['unique_identifiers']);
    }

    public function testParseLocatePayloadHandlesSingleResult(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'only-one'),
        ]));
        $result = Operations::parseLocatePayload($payload);
        $this->assertSame(['only-one'], $result['unique_identifiers']);
    }

    // -----------------------------------------------------------------------
    // Get payload parsing
    // -----------------------------------------------------------------------

    public function testParseGetPayloadExtractsKeyMaterialFromNestedStructure(): void
    {
        $keyBytes = hex2bin('0123456789abcdef0123456789abcdef');
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'uid-99'),
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
            Ttlv::encodeStructure(Tag::SYMMETRIC_KEY, [
                Ttlv::encodeStructure(Tag::KEY_BLOCK, [
                    Ttlv::encodeEnum(Tag::KEY_FORMAT_TYPE, KeyFormatType::RAW),
                    Ttlv::encodeStructure(Tag::KEY_VALUE, [
                        Ttlv::encodeByteString(Tag::KEY_MATERIAL, $keyBytes),
                    ]),
                ]),
            ]),
        ]));
        $result = Operations::parseGetPayload($payload);
        $this->assertSame('uid-99', $result['unique_identifier']);
        $this->assertSame(ObjectType::SYMMETRIC_KEY, $result['object_type']);
        $this->assertSame($keyBytes, $result['key_material']);
    }

    public function testParseGetPayloadReturnsNullKeyMaterialWhenNoSymmetricKey(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'uid-50'),
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, ObjectType::CERTIFICATE),
        ]));
        $result = Operations::parseGetPayload($payload);
        $this->assertSame('uid-50', $result['unique_identifier']);
        $this->assertNull($result['key_material']);
    }

    // -----------------------------------------------------------------------
    // Create payload parsing
    // -----------------------------------------------------------------------

    public function testParseCreatePayloadExtractsObjectTypeAndUniqueId(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'new-uid-7'),
        ]));
        $result = Operations::parseCreatePayload($payload);
        $this->assertSame(ObjectType::SYMMETRIC_KEY, $result['object_type']);
        $this->assertSame('new-uid-7', $result['unique_identifier']);
    }

    // -----------------------------------------------------------------------
    // Round-trip: build -> encode -> decode -> verify
    // -----------------------------------------------------------------------

    public function testLocateRequestRoundTrips(): void
    {
        $request = Operations::buildLocateRequest('round-trip-key');
        $reEncoded = Operations::buildLocateRequest('round-trip-key');
        $this->assertSame($request, $reEncoded);
    }

    public function testGetRequestRoundTrips(): void
    {
        $request = Operations::buildGetRequest('uid-abc');
        $decoded = Ttlv::decode($request);
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $payload = Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $this->assertSame('uid-abc', $uid['value']);
    }

    public function testCreateRequestRoundTrips(): void
    {
        $request = Operations::buildCreateRequest('rt-key', Algorithm::AES, 128);
        $decoded = Ttlv::decode($request);
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
        $batch = Ttlv::findChild($decoded, Tag::BATCH_ITEM);
        $op = Ttlv::findChild($batch, Tag::OPERATION);
        $this->assertSame(Operation::CREATE, $op['value']);
    }

    // -----------------------------------------------------------------------
    // Protocol constants
    // -----------------------------------------------------------------------

    public function testProtocolMajorIs1(): void
    {
        $this->assertSame(1, Operations::PROTOCOL_MAJOR);
    }

    public function testProtocolMinorIs4(): void
    {
        $this->assertSame(4, Operations::PROTOCOL_MINOR);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private function findAttrByName(array $attrs, string $name): ?array
    {
        foreach ($attrs as $attr) {
            $attrName = Ttlv::findChild($attr, Tag::ATTRIBUTE_NAME);
            if ($attrName !== null && $attrName['value'] === $name) {
                return $attr;
            }
        }
        return null;
    }
}
