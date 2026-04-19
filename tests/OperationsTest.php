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

    /**
     * Decode a request and extract the batch item.
     */
    private function decodeBatchItem(string $request): array
    {
        $decoded = Ttlv::decode($request);
        return Ttlv::findChild($decoded, Tag::BATCH_ITEM);
    }

    /**
     * Extract the operation enum from a request.
     */
    private function extractOperation(string $request): int
    {
        $batch = $this->decodeBatchItem($request);
        return Ttlv::findChild($batch, Tag::OPERATION)['value'];
    }

    /**
     * Extract the payload from a request.
     */
    private function extractPayload(string $request): array
    {
        $batch = $this->decodeBatchItem($request);
        return Ttlv::findChild($batch, Tag::REQUEST_PAYLOAD);
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
        $this->assertSame(Operation::LOCATE, $this->extractOperation(Operations::buildLocateRequest('k')));
    }

    public function testBuildLocateRequestContainsNameAttribute(): void
    {
        $payload = $this->extractPayload(Operations::buildLocateRequest('my-key'));
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
        $decoded = Ttlv::decode(Operations::buildGetRequest('unique-id-123'));
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
    }

    public function testBuildGetRequestHasGetOperation(): void
    {
        $this->assertSame(Operation::GET, $this->extractOperation(Operations::buildGetRequest('uid')));
    }

    public function testBuildGetRequestContainsUniqueIdentifier(): void
    {
        $payload = $this->extractPayload(Operations::buildGetRequest('uid-456'));
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $this->assertSame('uid-456', $uid['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Create
    // -----------------------------------------------------------------------

    public function testBuildCreateRequestProducesValidTtlvStructure(): void
    {
        $decoded = Ttlv::decode(Operations::buildCreateRequest('new-key'));
        $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag']);
    }

    public function testBuildCreateRequestHasCreateOperation(): void
    {
        $this->assertSame(Operation::CREATE, $this->extractOperation(Operations::buildCreateRequest('k')));
    }

    public function testBuildCreateRequestUsesSymmetricKeyObjectType(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateRequest('k'));
        $objType = Ttlv::findChild($payload, Tag::OBJECT_TYPE);
        $this->assertSame(ObjectType::SYMMETRIC_KEY, $objType['value']);
    }

    public function testBuildCreateRequestDefaultsToAesAlgorithm(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateRequest('k'));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $algoAttr = $this->findAttrByName($attrs, 'Cryptographic Algorithm');
        $this->assertNotNull($algoAttr);
        $algoValue = Ttlv::findChild($algoAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(Algorithm::AES, $algoValue['value']);
    }

    public function testBuildCreateRequestDefaultsTo256BitLength(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateRequest('k'));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $lenAttr = $this->findAttrByName($attrs, 'Cryptographic Length');
        $this->assertNotNull($lenAttr);
        $lenValue = Ttlv::findChild($lenAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(256, $lenValue['value']);
    }

    public function testBuildCreateRequestIncludesEncryptDecryptUsageMask(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateRequest('k'));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $usageAttr = $this->findAttrByName($attrs, 'Cryptographic Usage Mask');
        $this->assertNotNull($usageAttr);
        $usageValue = Ttlv::findChild($usageAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(UsageMask::ENCRYPT | UsageMask::DECRYPT, $usageValue['value']);
    }

    public function testBuildCreateRequestIncludesKeyNameInTemplate(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateRequest('prod-key'));
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
        $payload = $this->extractPayload(Operations::buildCreateRequest('k', Algorithm::TRIPLE_DES, 192));
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
    // Request building — CreateKeyPair
    // -----------------------------------------------------------------------

    public function testBuildCreateKeyPairRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::CREATE_KEY_PAIR,
            $this->extractOperation(Operations::buildCreateKeyPairRequest('kp', Algorithm::RSA, 2048))
        );
    }

    public function testBuildCreateKeyPairRequestIncludesSignVerifyUsageMask(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateKeyPairRequest('kp', Algorithm::RSA, 2048));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $usageAttr = $this->findAttrByName($attrs, 'Cryptographic Usage Mask');
        $usageValue = Ttlv::findChild($usageAttr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame(UsageMask::SIGN | UsageMask::VERIFY, $usageValue['value']);
    }

    public function testBuildCreateKeyPairRequestIncludesName(): void
    {
        $payload = $this->extractPayload(Operations::buildCreateKeyPairRequest('my-pair', Algorithm::RSA, 2048));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $attrs = Ttlv::findChildren($tmpl, Tag::ATTRIBUTE);
        $nameAttr = $this->findAttrByName($attrs, 'Name');
        $nameStruct = Ttlv::findChild($nameAttr, Tag::ATTRIBUTE_VALUE);
        $nameValue = Ttlv::findChild($nameStruct, Tag::NAME_VALUE);
        $this->assertSame('my-pair', $nameValue['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Register
    // -----------------------------------------------------------------------

    public function testBuildRegisterRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::REGISTER,
            $this->extractOperation(Operations::buildRegisterRequest(
                ObjectType::SYMMETRIC_KEY, hex2bin('aabb'), 'reg-key', Algorithm::AES, 128
            ))
        );
    }

    public function testBuildRegisterRequestContainsKeyMaterial(): void
    {
        $material = hex2bin('0123456789abcdef');
        $payload = $this->extractPayload(Operations::buildRegisterRequest(
            ObjectType::SYMMETRIC_KEY, $material, 'reg-key', Algorithm::AES, 128
        ));
        $symKey = Ttlv::findChild($payload, Tag::SYMMETRIC_KEY);
        $this->assertNotNull($symKey);
        $keyBlock = Ttlv::findChild($symKey, Tag::KEY_BLOCK);
        $this->assertNotNull($keyBlock);
        $keyValue = Ttlv::findChild($keyBlock, Tag::KEY_VALUE);
        $km = Ttlv::findChild($keyValue, Tag::KEY_MATERIAL);
        $this->assertSame($material, $km['value']);
    }

    public function testBuildRegisterRequestOmitsTemplateAttributeWhenNameEmpty(): void
    {
        $payload = $this->extractPayload(Operations::buildRegisterRequest(
            ObjectType::SYMMETRIC_KEY, hex2bin('aabb'), '', Algorithm::AES, 128
        ));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $this->assertNull($tmpl);
    }

    public function testBuildRegisterRequestIncludesTemplateAttributeWhenNameProvided(): void
    {
        $payload = $this->extractPayload(Operations::buildRegisterRequest(
            ObjectType::SYMMETRIC_KEY, hex2bin('aabb'), 'named', Algorithm::AES, 128
        ));
        $tmpl = Ttlv::findChild($payload, Tag::TEMPLATE_ATTRIBUTE);
        $this->assertNotNull($tmpl);
    }

    // -----------------------------------------------------------------------
    // Request building — ReKey
    // -----------------------------------------------------------------------

    public function testBuildReKeyRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::RE_KEY, $this->extractOperation(Operations::buildReKeyRequest('uid')));
    }

    public function testBuildReKeyRequestContainsUniqueIdentifier(): void
    {
        $payload = $this->extractPayload(Operations::buildReKeyRequest('uid-rk'));
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $this->assertSame('uid-rk', $uid['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — DeriveKey
    // -----------------------------------------------------------------------

    public function testBuildDeriveKeyRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::DERIVE_KEY,
            $this->extractOperation(Operations::buildDeriveKeyRequest('uid', 'salt', 'derived', 256))
        );
    }

    public function testBuildDeriveKeyRequestContainsDerivationParameters(): void
    {
        $payload = $this->extractPayload(Operations::buildDeriveKeyRequest('uid', 'deriv-data', 'dk', 128));
        $params = Ttlv::findChild($payload, Tag::DERIVATION_PARAMETERS);
        $this->assertNotNull($params);
        $data = Ttlv::findChild($params, Tag::DERIVATION_DATA);
        $this->assertSame('deriv-data', $data['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Check
    // -----------------------------------------------------------------------

    public function testBuildCheckRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::CHECK, $this->extractOperation(Operations::buildCheckRequest('uid')));
    }

    // -----------------------------------------------------------------------
    // Request building — Activate
    // -----------------------------------------------------------------------

    public function testBuildActivateRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::ACTIVATE, $this->extractOperation(Operations::buildActivateRequest('uid')));
    }

    // -----------------------------------------------------------------------
    // Request building — Destroy
    // -----------------------------------------------------------------------

    public function testBuildDestroyRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::DESTROY, $this->extractOperation(Operations::buildDestroyRequest('uid')));
    }

    // -----------------------------------------------------------------------
    // Request building — GetAttributes
    // -----------------------------------------------------------------------

    public function testBuildGetAttributesRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::GET_ATTRIBUTES,
            $this->extractOperation(Operations::buildGetAttributesRequest('uid'))
        );
    }

    // -----------------------------------------------------------------------
    // Request building — GetAttributeList
    // -----------------------------------------------------------------------

    public function testBuildGetAttributeListRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::GET_ATTRIBUTE_LIST,
            $this->extractOperation(Operations::buildGetAttributeListRequest('uid'))
        );
    }

    // -----------------------------------------------------------------------
    // Request building — AddAttribute
    // -----------------------------------------------------------------------

    public function testBuildAddAttributeRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::ADD_ATTRIBUTE,
            $this->extractOperation(Operations::buildAddAttributeRequest('uid', 'Contact', 'admin@x.com'))
        );
    }

    public function testBuildAddAttributeRequestContainsAttribute(): void
    {
        $payload = $this->extractPayload(Operations::buildAddAttributeRequest('uid', 'Contact', 'admin@x.com'));
        $attr = Ttlv::findChild($payload, Tag::ATTRIBUTE);
        $attrName = Ttlv::findChild($attr, Tag::ATTRIBUTE_NAME);
        $attrValue = Ttlv::findChild($attr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame('Contact', $attrName['value']);
        $this->assertSame('admin@x.com', $attrValue['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — ModifyAttribute
    // -----------------------------------------------------------------------

    public function testBuildModifyAttributeRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::MODIFY_ATTRIBUTE,
            $this->extractOperation(Operations::buildModifyAttributeRequest('uid', 'Contact', 'new@x.com'))
        );
    }

    // -----------------------------------------------------------------------
    // Request building — DeleteAttribute
    // -----------------------------------------------------------------------

    public function testBuildDeleteAttributeRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::DELETE_ATTRIBUTE,
            $this->extractOperation(Operations::buildDeleteAttributeRequest('uid', 'Contact'))
        );
    }

    public function testBuildDeleteAttributeRequestContainsAttributeNameOnly(): void
    {
        $payload = $this->extractPayload(Operations::buildDeleteAttributeRequest('uid', 'Contact'));
        $attr = Ttlv::findChild($payload, Tag::ATTRIBUTE);
        $attrName = Ttlv::findChild($attr, Tag::ATTRIBUTE_NAME);
        $attrValue = Ttlv::findChild($attr, Tag::ATTRIBUTE_VALUE);
        $this->assertSame('Contact', $attrName['value']);
        $this->assertNull($attrValue);
    }

    // -----------------------------------------------------------------------
    // Request building — ObtainLease
    // -----------------------------------------------------------------------

    public function testBuildObtainLeaseRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::OBTAIN_LEASE,
            $this->extractOperation(Operations::buildObtainLeaseRequest('uid'))
        );
    }

    // -----------------------------------------------------------------------
    // Request building — Revoke
    // -----------------------------------------------------------------------

    public function testBuildRevokeRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::REVOKE,
            $this->extractOperation(Operations::buildRevokeRequest('uid', 1))
        );
    }

    public function testBuildRevokeRequestContainsRevocationReason(): void
    {
        $payload = $this->extractPayload(Operations::buildRevokeRequest('uid', 5));
        $reason = Ttlv::findChild($payload, Tag::REVOCATION_REASON);
        $this->assertNotNull($reason);
        $code = Ttlv::findChild($reason, Tag::REVOCATION_REASON_CODE);
        $this->assertSame(5, $code['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Archive
    // -----------------------------------------------------------------------

    public function testBuildArchiveRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::ARCHIVE, $this->extractOperation(Operations::buildArchiveRequest('uid')));
    }

    // -----------------------------------------------------------------------
    // Request building — Recover
    // -----------------------------------------------------------------------

    public function testBuildRecoverRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::RECOVER, $this->extractOperation(Operations::buildRecoverRequest('uid')));
    }

    // -----------------------------------------------------------------------
    // Request building — Query
    // -----------------------------------------------------------------------

    public function testBuildQueryRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::QUERY, $this->extractOperation(Operations::buildQueryRequest()));
    }

    public function testBuildQueryRequestHasEmptyPayload(): void
    {
        $payload = $this->extractPayload(Operations::buildQueryRequest());
        $this->assertSame(Tag::REQUEST_PAYLOAD, $payload['tag']);
        $this->assertCount(0, $payload['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Poll
    // -----------------------------------------------------------------------

    public function testBuildPollRequestHasCorrectOperation(): void
    {
        $this->assertSame(Operation::POLL, $this->extractOperation(Operations::buildPollRequest()));
    }

    // -----------------------------------------------------------------------
    // Request building — DiscoverVersions
    // -----------------------------------------------------------------------

    public function testBuildDiscoverVersionsRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::DISCOVER_VERSIONS,
            $this->extractOperation(Operations::buildDiscoverVersionsRequest())
        );
    }

    // -----------------------------------------------------------------------
    // Request building — Encrypt
    // -----------------------------------------------------------------------

    public function testBuildEncryptRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::ENCRYPT,
            $this->extractOperation(Operations::buildEncryptRequest('uid', 'plaintext'))
        );
    }

    public function testBuildEncryptRequestContainsData(): void
    {
        $payload = $this->extractPayload(Operations::buildEncryptRequest('uid', 'plaintext'));
        $data = Ttlv::findChild($payload, Tag::DATA);
        $this->assertSame('plaintext', $data['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Decrypt
    // -----------------------------------------------------------------------

    public function testBuildDecryptRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::DECRYPT,
            $this->extractOperation(Operations::buildDecryptRequest('uid', 'ciphertext'))
        );
    }

    public function testBuildDecryptRequestContainsDataAndOptionalNonce(): void
    {
        // Without nonce
        $payload = $this->extractPayload(Operations::buildDecryptRequest('uid', 'ct'));
        $data = Ttlv::findChild($payload, Tag::DATA);
        $this->assertSame('ct', $data['value']);
        $nonce = Ttlv::findChild($payload, Tag::IV_COUNTER_NONCE);
        $this->assertNull($nonce);

        // With nonce
        $payload2 = $this->extractPayload(Operations::buildDecryptRequest('uid', 'ct', 'nonce123'));
        $nonce2 = Ttlv::findChild($payload2, Tag::IV_COUNTER_NONCE);
        $this->assertSame('nonce123', $nonce2['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — Sign
    // -----------------------------------------------------------------------

    public function testBuildSignRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::SIGN,
            $this->extractOperation(Operations::buildSignRequest('uid', 'data'))
        );
    }

    // -----------------------------------------------------------------------
    // Request building — SignatureVerify
    // -----------------------------------------------------------------------

    public function testBuildSignatureVerifyRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::SIGNATURE_VERIFY,
            $this->extractOperation(Operations::buildSignatureVerifyRequest('uid', 'data', 'sig'))
        );
    }

    public function testBuildSignatureVerifyRequestContainsDataAndSignature(): void
    {
        $payload = $this->extractPayload(Operations::buildSignatureVerifyRequest('uid', 'msg', 'sig'));
        $data = Ttlv::findChild($payload, Tag::DATA);
        $this->assertSame('msg', $data['value']);
        $sig = Ttlv::findChild($payload, Tag::SIGNATURE_DATA);
        $this->assertSame('sig', $sig['value']);
    }

    // -----------------------------------------------------------------------
    // Request building — MAC
    // -----------------------------------------------------------------------

    public function testBuildMacRequestHasCorrectOperation(): void
    {
        $this->assertSame(
            Operation::MAC,
            $this->extractOperation(Operations::buildMacRequest('uid', 'data'))
        );
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
    // CreateKeyPair payload parsing
    // -----------------------------------------------------------------------

    public function testParseCreateKeyPairPayloadExtractsBothUids(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::PRIVATE_KEY_UNIQUE_IDENTIFIER, 'priv-1'),
            Ttlv::encodeTextString(Tag::PUBLIC_KEY_UNIQUE_IDENTIFIER, 'pub-1'),
        ]));
        $result = Operations::parseCreateKeyPairPayload($payload);
        $this->assertSame('priv-1', $result['private_key_uid']);
        $this->assertSame('pub-1', $result['public_key_uid']);
    }

    // -----------------------------------------------------------------------
    // Check payload parsing
    // -----------------------------------------------------------------------

    public function testParseCheckPayloadExtractsUniqueIdentifier(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'check-uid'),
        ]));
        $result = Operations::parseCheckPayload($payload);
        $this->assertSame('check-uid', $result['unique_identifier']);
    }

    // -----------------------------------------------------------------------
    // ReKey payload parsing
    // -----------------------------------------------------------------------

    public function testParseReKeyPayloadExtractsUniqueIdentifier(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'rekey-uid'),
        ]));
        $result = Operations::parseReKeyPayload($payload);
        $this->assertSame('rekey-uid', $result['unique_identifier']);
    }

    // -----------------------------------------------------------------------
    // DeriveKey payload parsing
    // -----------------------------------------------------------------------

    public function testParseDeriveKeyPayloadExtractsUniqueIdentifier(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'derived-uid'),
        ]));
        $result = Operations::parseDeriveKeyPayload($payload);
        $this->assertSame('derived-uid', $result['unique_identifier']);
    }

    // -----------------------------------------------------------------------
    // ObtainLease payload parsing
    // -----------------------------------------------------------------------

    public function testParseObtainLeasePayloadExtractsLeaseTime(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::UNIQUE_IDENTIFIER, 'lease-uid'),
            Ttlv::encodeInteger(Tag::LEASE_TIME, 3600),
        ]));
        $result = Operations::parseObtainLeasePayload($payload);
        $this->assertSame('lease-uid', $result['unique_identifier']);
        $this->assertSame(3600, $result['lease_time']);
    }

    // -----------------------------------------------------------------------
    // GetAttributeList payload parsing
    // -----------------------------------------------------------------------

    public function testParseGetAttributeListPayloadExtractsNames(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Algorithm'),
            Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Cryptographic Length'),
            Ttlv::encodeTextString(Tag::ATTRIBUTE_NAME, 'Name'),
        ]));
        $result = Operations::parseGetAttributeListPayload($payload);
        $this->assertSame(['Cryptographic Algorithm', 'Cryptographic Length', 'Name'], $result);
    }

    // -----------------------------------------------------------------------
    // Query payload parsing
    // -----------------------------------------------------------------------

    public function testParseQueryPayloadExtractsOperationsAndObjectTypes(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeEnum(Tag::OPERATION, Operation::CREATE),
            Ttlv::encodeEnum(Tag::OPERATION, Operation::GET),
            Ttlv::encodeEnum(Tag::OBJECT_TYPE, ObjectType::SYMMETRIC_KEY),
        ]));
        $result = Operations::parseQueryPayload($payload);
        $this->assertSame([Operation::CREATE, Operation::GET], $result['operations']);
        $this->assertSame([ObjectType::SYMMETRIC_KEY], $result['object_types']);
    }

    public function testParseQueryPayloadHandlesEmptyResult(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, []));
        $result = Operations::parseQueryPayload($payload);
        $this->assertSame([], $result['operations']);
        $this->assertSame([], $result['object_types']);
    }

    // -----------------------------------------------------------------------
    // DiscoverVersions payload parsing
    // -----------------------------------------------------------------------

    public function testParseDiscoverVersionsPayloadExtractsVersions(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeStructure(Tag::PROTOCOL_VERSION, [
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MAJOR, 1),
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MINOR, 4),
            ]),
            Ttlv::encodeStructure(Tag::PROTOCOL_VERSION, [
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MAJOR, 1),
                Ttlv::encodeInteger(Tag::PROTOCOL_VERSION_MINOR, 2),
            ]),
        ]));
        $result = Operations::parseDiscoverVersionsPayload($payload);
        $this->assertCount(2, $result['versions']);
        $this->assertSame(['major' => 1, 'minor' => 4], $result['versions'][0]);
        $this->assertSame(['major' => 1, 'minor' => 2], $result['versions'][1]);
    }

    // -----------------------------------------------------------------------
    // Encrypt payload parsing
    // -----------------------------------------------------------------------

    public function testParseEncryptPayloadExtractsDataAndNonce(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeByteString(Tag::DATA, 'ciphertext'),
            Ttlv::encodeByteString(Tag::IV_COUNTER_NONCE, 'nonce-val'),
        ]));
        $result = Operations::parseEncryptPayload($payload);
        $this->assertSame('ciphertext', $result['data']);
        $this->assertSame('nonce-val', $result['nonce']);
    }

    public function testParseEncryptPayloadHandlesMissingNonce(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeByteString(Tag::DATA, 'ct'),
        ]));
        $result = Operations::parseEncryptPayload($payload);
        $this->assertSame('ct', $result['data']);
        $this->assertNull($result['nonce']);
    }

    // -----------------------------------------------------------------------
    // Decrypt payload parsing
    // -----------------------------------------------------------------------

    public function testParseDecryptPayloadExtractsData(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeByteString(Tag::DATA, 'plaintext'),
        ]));
        $result = Operations::parseDecryptPayload($payload);
        $this->assertSame('plaintext', $result['data']);
    }

    // -----------------------------------------------------------------------
    // Sign payload parsing
    // -----------------------------------------------------------------------

    public function testParseSignPayloadExtractsSignatureData(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeByteString(Tag::SIGNATURE_DATA, 'sig-bytes'),
        ]));
        $result = Operations::parseSignPayload($payload);
        $this->assertSame('sig-bytes', $result['signature_data']);
    }

    // -----------------------------------------------------------------------
    // SignatureVerify payload parsing
    // -----------------------------------------------------------------------

    public function testParseSignatureVerifyPayloadValid(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeEnum(Tag::VALIDITY_INDICATOR, 0), // 0 = valid
        ]));
        $result = Operations::parseSignatureVerifyPayload($payload);
        $this->assertTrue($result['valid']);
    }

    public function testParseSignatureVerifyPayloadInvalid(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeEnum(Tag::VALIDITY_INDICATOR, 1), // 1 = invalid
        ]));
        $result = Operations::parseSignatureVerifyPayload($payload);
        $this->assertFalse($result['valid']);
    }

    public function testParseSignatureVerifyPayloadMissingIndicator(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, []));
        $result = Operations::parseSignatureVerifyPayload($payload);
        $this->assertFalse($result['valid']);
    }

    // -----------------------------------------------------------------------
    // MAC payload parsing
    // -----------------------------------------------------------------------

    public function testParseMacPayloadExtractsMacData(): void
    {
        $payload = Ttlv::decode(Ttlv::encodeStructure(Tag::RESPONSE_PAYLOAD, [
            Ttlv::encodeByteString(Tag::MAC_DATA, 'mac-bytes'),
        ]));
        $result = Operations::parseMacPayload($payload);
        $this->assertSame('mac-bytes', $result['mac_data']);
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
        $payload = $this->extractPayload(Operations::buildGetRequest('uid-abc'));
        $uid = Ttlv::findChild($payload, Tag::UNIQUE_IDENTIFIER);
        $this->assertSame('uid-abc', $uid['value']);
    }

    public function testCreateRequestRoundTrips(): void
    {
        $this->assertSame(
            Operation::CREATE,
            $this->extractOperation(Operations::buildCreateRequest('rt-key', Algorithm::AES, 128))
        );
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
    // All 27 operations produce valid TTLV
    // -----------------------------------------------------------------------

    public function testAll27OperationsProduceValidTtlv(): void
    {
        $requests = [
            Operations::buildCreateRequest('k'),
            Operations::buildCreateKeyPairRequest('kp', Algorithm::RSA, 2048),
            Operations::buildRegisterRequest(ObjectType::SYMMETRIC_KEY, hex2bin('aa'), 'r', Algorithm::AES, 128),
            Operations::buildReKeyRequest('uid'),
            Operations::buildDeriveKeyRequest('uid', 'data', 'dk', 256),
            Operations::buildLocateRequest('k'),
            Operations::buildCheckRequest('uid'),
            Operations::buildGetRequest('uid'),
            Operations::buildGetAttributesRequest('uid'),
            Operations::buildGetAttributeListRequest('uid'),
            Operations::buildAddAttributeRequest('uid', 'a', 'v'),
            Operations::buildModifyAttributeRequest('uid', 'a', 'v'),
            Operations::buildDeleteAttributeRequest('uid', 'a'),
            Operations::buildObtainLeaseRequest('uid'),
            Operations::buildActivateRequest('uid'),
            Operations::buildRevokeRequest('uid', 1),
            Operations::buildDestroyRequest('uid'),
            Operations::buildArchiveRequest('uid'),
            Operations::buildRecoverRequest('uid'),
            Operations::buildQueryRequest(),
            Operations::buildPollRequest(),
            Operations::buildDiscoverVersionsRequest(),
            Operations::buildEncryptRequest('uid', 'data'),
            Operations::buildDecryptRequest('uid', 'data'),
            Operations::buildSignRequest('uid', 'data'),
            Operations::buildSignatureVerifyRequest('uid', 'data', 'sig'),
            Operations::buildMacRequest('uid', 'data'),
        ];

        $this->assertCount(27, $requests);
        foreach ($requests as $i => $request) {
            $decoded = Ttlv::decode($request);
            $this->assertSame(Tag::REQUEST_MESSAGE, $decoded['tag'], "Request $i is not a valid RequestMessage");
        }
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
