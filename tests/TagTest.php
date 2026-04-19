<?php

declare(strict_types=1);

namespace Cyphera\Kmip\Tests;

use PHPUnit\Framework\TestCase;
use Cyphera\Kmip\Tag;
use Cyphera\Kmip\Operation;
use Cyphera\Kmip\ObjectType;
use Cyphera\Kmip\ResultStatus;
use Cyphera\Kmip\Algorithm;
use Cyphera\Kmip\KeyFormatType;
use Cyphera\Kmip\NameType;
use Cyphera\Kmip\UsageMask;

final class TagTest extends TestCase
{
    // -----------------------------------------------------------------------
    // ObjectType values -- KMIP 1.4 Section 9.1.3.2.3
    // -----------------------------------------------------------------------

    public function testObjectTypeCertificate(): void
    {
        $this->assertSame(0x00000001, ObjectType::CERTIFICATE);
    }

    public function testObjectTypeSymmetricKey(): void
    {
        $this->assertSame(0x00000002, ObjectType::SYMMETRIC_KEY);
    }

    public function testObjectTypePublicKey(): void
    {
        $this->assertSame(0x00000003, ObjectType::PUBLIC_KEY);
    }

    public function testObjectTypePrivateKey(): void
    {
        $this->assertSame(0x00000004, ObjectType::PRIVATE_KEY);
    }

    public function testObjectTypeSplitKey(): void
    {
        $this->assertSame(0x00000005, ObjectType::SPLIT_KEY);
    }

    public function testObjectTypeTemplate(): void
    {
        $this->assertSame(0x00000006, ObjectType::TEMPLATE);
    }

    public function testObjectTypeSecretData(): void
    {
        $this->assertSame(0x00000007, ObjectType::SECRET_DATA);
    }

    public function testObjectTypeOpaqueData(): void
    {
        $this->assertSame(0x00000008, ObjectType::OPAQUE_DATA);
    }

    public function testObjectTypeNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(ObjectType::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    // -----------------------------------------------------------------------
    // Operation values -- KMIP 1.4 Section 9.1.3.2.2 (all 27)
    // -----------------------------------------------------------------------

    public function testOperationCreate(): void
    {
        $this->assertSame(0x00000001, Operation::CREATE);
    }

    public function testOperationCreateKeyPair(): void
    {
        $this->assertSame(0x00000002, Operation::CREATE_KEY_PAIR);
    }

    public function testOperationRegister(): void
    {
        $this->assertSame(0x00000003, Operation::REGISTER);
    }

    public function testOperationReKey(): void
    {
        $this->assertSame(0x00000004, Operation::RE_KEY);
    }

    public function testOperationDeriveKey(): void
    {
        $this->assertSame(0x00000005, Operation::DERIVE_KEY);
    }

    public function testOperationLocate(): void
    {
        $this->assertSame(0x00000008, Operation::LOCATE);
    }

    public function testOperationCheck(): void
    {
        $this->assertSame(0x00000009, Operation::CHECK);
    }

    public function testOperationGet(): void
    {
        $this->assertSame(0x0000000A, Operation::GET);
    }

    public function testOperationGetAttributes(): void
    {
        $this->assertSame(0x0000000B, Operation::GET_ATTRIBUTES);
    }

    public function testOperationGetAttributeList(): void
    {
        $this->assertSame(0x0000000C, Operation::GET_ATTRIBUTE_LIST);
    }

    public function testOperationAddAttribute(): void
    {
        $this->assertSame(0x0000000D, Operation::ADD_ATTRIBUTE);
    }

    public function testOperationModifyAttribute(): void
    {
        $this->assertSame(0x0000000E, Operation::MODIFY_ATTRIBUTE);
    }

    public function testOperationDeleteAttribute(): void
    {
        $this->assertSame(0x0000000F, Operation::DELETE_ATTRIBUTE);
    }

    public function testOperationObtainLease(): void
    {
        $this->assertSame(0x00000010, Operation::OBTAIN_LEASE);
    }

    public function testOperationActivate(): void
    {
        $this->assertSame(0x00000012, Operation::ACTIVATE);
    }

    public function testOperationRevoke(): void
    {
        $this->assertSame(0x00000013, Operation::REVOKE);
    }

    public function testOperationDestroy(): void
    {
        $this->assertSame(0x00000014, Operation::DESTROY);
    }

    public function testOperationArchive(): void
    {
        $this->assertSame(0x00000015, Operation::ARCHIVE);
    }

    public function testOperationRecover(): void
    {
        $this->assertSame(0x00000016, Operation::RECOVER);
    }

    public function testOperationQuery(): void
    {
        $this->assertSame(0x00000018, Operation::QUERY);
    }

    public function testOperationPoll(): void
    {
        $this->assertSame(0x0000001A, Operation::POLL);
    }

    public function testOperationDiscoverVersions(): void
    {
        $this->assertSame(0x0000001E, Operation::DISCOVER_VERSIONS);
    }

    public function testOperationEncrypt(): void
    {
        $this->assertSame(0x0000001F, Operation::ENCRYPT);
    }

    public function testOperationDecrypt(): void
    {
        $this->assertSame(0x00000020, Operation::DECRYPT);
    }

    public function testOperationSign(): void
    {
        $this->assertSame(0x00000021, Operation::SIGN);
    }

    public function testOperationSignatureVerify(): void
    {
        $this->assertSame(0x00000022, Operation::SIGNATURE_VERIFY);
    }

    public function testOperationMac(): void
    {
        $this->assertSame(0x00000023, Operation::MAC);
    }

    public function testOperationNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(Operation::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    public function testOperationHas27Constants(): void
    {
        $values = $this->getClassConstants(Operation::class);
        $this->assertCount(27, $values);
    }

    // -----------------------------------------------------------------------
    // ResultStatus
    // -----------------------------------------------------------------------

    public function testResultStatusSuccess(): void
    {
        $this->assertSame(0x00000000, ResultStatus::SUCCESS);
    }

    public function testResultStatusOperationFailed(): void
    {
        $this->assertSame(0x00000001, ResultStatus::OPERATION_FAILED);
    }

    public function testResultStatusOperationPending(): void
    {
        $this->assertSame(0x00000002, ResultStatus::OPERATION_PENDING);
    }

    public function testResultStatusOperationUndone(): void
    {
        $this->assertSame(0x00000003, ResultStatus::OPERATION_UNDONE);
    }

    public function testResultStatusNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(ResultStatus::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    // -----------------------------------------------------------------------
    // Algorithm values -- KMIP 1.4 Section 9.1.3.2.13
    // -----------------------------------------------------------------------

    public function testAlgorithmDes(): void
    {
        $this->assertSame(0x00000001, Algorithm::DES);
    }

    public function testAlgorithmTripleDes(): void
    {
        $this->assertSame(0x00000002, Algorithm::TRIPLE_DES);
    }

    public function testAlgorithmAes(): void
    {
        $this->assertSame(0x00000003, Algorithm::AES);
    }

    public function testAlgorithmRsa(): void
    {
        $this->assertSame(0x00000004, Algorithm::RSA);
    }

    public function testAlgorithmDsa(): void
    {
        $this->assertSame(0x00000005, Algorithm::DSA);
    }

    public function testAlgorithmEcdsa(): void
    {
        $this->assertSame(0x00000006, Algorithm::ECDSA);
    }

    public function testAlgorithmHmacSha1(): void
    {
        $this->assertSame(0x00000007, Algorithm::HMAC_SHA1);
    }

    public function testAlgorithmHmacSha256(): void
    {
        $this->assertSame(0x00000008, Algorithm::HMAC_SHA256);
    }

    public function testAlgorithmHmacSha384(): void
    {
        $this->assertSame(0x00000009, Algorithm::HMAC_SHA384);
    }

    public function testAlgorithmHmacSha512(): void
    {
        $this->assertSame(0x0000000A, Algorithm::HMAC_SHA512);
    }

    public function testAlgorithmNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(Algorithm::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    // -----------------------------------------------------------------------
    // KeyFormatType values
    // -----------------------------------------------------------------------

    public function testKeyFormatTypeRaw(): void
    {
        $this->assertSame(0x00000001, KeyFormatType::RAW);
    }

    public function testKeyFormatTypeOpaque(): void
    {
        $this->assertSame(0x00000002, KeyFormatType::OPAQUE);
    }

    public function testKeyFormatTypePkcs1(): void
    {
        $this->assertSame(0x00000003, KeyFormatType::PKCS1);
    }

    public function testKeyFormatTypePkcs8(): void
    {
        $this->assertSame(0x00000004, KeyFormatType::PKCS8);
    }

    public function testKeyFormatTypeX509(): void
    {
        $this->assertSame(0x00000005, KeyFormatType::X509);
    }

    public function testKeyFormatTypeEcPrivateKey(): void
    {
        $this->assertSame(0x00000006, KeyFormatType::EC_PRIVATE_KEY);
    }

    public function testKeyFormatTypeTransparentSymmetric(): void
    {
        $this->assertSame(0x00000007, KeyFormatType::TRANSPARENT_SYMMETRIC);
    }

    public function testKeyFormatTypeNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(KeyFormatType::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    // -----------------------------------------------------------------------
    // NameType values
    // -----------------------------------------------------------------------

    public function testNameTypeUninterpretedTextString(): void
    {
        $this->assertSame(0x00000001, NameType::UNINTERPRETED_TEXT_STRING);
    }

    public function testNameTypeUri(): void
    {
        $this->assertSame(0x00000002, NameType::URI);
    }

    // -----------------------------------------------------------------------
    // UsageMask -- bitmask values
    // -----------------------------------------------------------------------

    public function testUsageMaskSign(): void
    {
        $this->assertSame(0x00000001, UsageMask::SIGN);
    }

    public function testUsageMaskVerify(): void
    {
        $this->assertSame(0x00000002, UsageMask::VERIFY);
    }

    public function testUsageMaskEncrypt(): void
    {
        $this->assertSame(0x00000004, UsageMask::ENCRYPT);
    }

    public function testUsageMaskDecrypt(): void
    {
        $this->assertSame(0x00000008, UsageMask::DECRYPT);
    }

    public function testUsageMaskWrapKey(): void
    {
        $this->assertSame(0x00000010, UsageMask::WRAP_KEY);
    }

    public function testUsageMaskUnwrapKey(): void
    {
        $this->assertSame(0x00000020, UsageMask::UNWRAP_KEY);
    }

    public function testUsageMaskExport(): void
    {
        $this->assertSame(0x00000040, UsageMask::EXPORT);
    }

    public function testUsageMaskDeriveKey(): void
    {
        $this->assertSame(0x00000100, UsageMask::DERIVE_KEY);
    }

    public function testUsageMaskKeyAgreement(): void
    {
        $this->assertSame(0x00000800, UsageMask::KEY_AGREEMENT);
    }

    public function testUsageMaskEncryptDecryptCombinesCorrectly(): void
    {
        $this->assertSame(0x0000000C, UsageMask::ENCRYPT | UsageMask::DECRYPT);
    }

    public function testUsageMaskAllValuesAreDistinctPowersOf2(): void
    {
        $values = $this->getClassConstants(UsageMask::class);
        $combined = 0;
        foreach ($values as $name => $v) {
            $this->assertSame(
                0,
                $combined & $v,
                sprintf('UsageMask::%s (0x%x) overlaps with previous values', $name, $v)
            );
            $combined |= $v;
        }
    }

    // -----------------------------------------------------------------------
    // Tag values -- all should be in the 0x42XXXX range
    // -----------------------------------------------------------------------

    public function testAllTagValuesAreInKmipRange(): void
    {
        $constants = $this->getClassConstants(Tag::class);
        foreach ($constants as $name => $value) {
            $this->assertTrue(
                $value >= 0x420000 && $value <= 0x42FFFF,
                sprintf('Tag::%s = 0x%06X is outside 0x42XXXX range', $name, $value)
            );
        }
    }

    public function testTagNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(Tag::class);
        $this->assertSame(count($values), count(array_unique($values)));
    }

    // -----------------------------------------------------------------------
    // New tags -- key pair, certificate, crypto ops, revocation, etc.
    // -----------------------------------------------------------------------

    public function testTagPrivateKeyUniqueIdentifier(): void
    {
        $this->assertSame(0x420066, Tag::PRIVATE_KEY_UNIQUE_IDENTIFIER);
    }

    public function testTagPublicKeyUniqueIdentifier(): void
    {
        $this->assertSame(0x42006F, Tag::PUBLIC_KEY_UNIQUE_IDENTIFIER);
    }

    public function testTagPublicKey(): void
    {
        $this->assertSame(0x42004E, Tag::PUBLIC_KEY);
    }

    public function testTagPrivateKey(): void
    {
        $this->assertSame(0x42004D, Tag::PRIVATE_KEY);
    }

    public function testTagCertificate(): void
    {
        $this->assertSame(0x420021, Tag::CERTIFICATE);
    }

    public function testTagCertificateType(): void
    {
        $this->assertSame(0x42001D, Tag::CERTIFICATE_TYPE);
    }

    public function testTagCertificateValue(): void
    {
        $this->assertSame(0x42001E, Tag::CERTIFICATE_VALUE);
    }

    public function testTagData(): void
    {
        $this->assertSame(0x420033, Tag::DATA);
    }

    public function testTagIvCounterNonce(): void
    {
        $this->assertSame(0x420047, Tag::IV_COUNTER_NONCE);
    }

    public function testTagSignatureData(): void
    {
        $this->assertSame(0x42004F, Tag::SIGNATURE_DATA);
    }

    public function testTagMacData(): void
    {
        $this->assertSame(0x420051, Tag::MAC_DATA);
    }

    public function testTagValidityIndicator(): void
    {
        $this->assertSame(0x420098, Tag::VALIDITY_INDICATOR);
    }

    public function testTagRevocationReason(): void
    {
        $this->assertSame(0x420082, Tag::REVOCATION_REASON);
    }

    public function testTagRevocationReasonCode(): void
    {
        $this->assertSame(0x420083, Tag::REVOCATION_REASON_CODE);
    }

    public function testTagQueryFunction(): void
    {
        $this->assertSame(0x420074, Tag::QUERY_FUNCTION);
    }

    public function testTagState(): void
    {
        $this->assertSame(0x42008D, Tag::STATE);
    }

    public function testTagDerivationMethod(): void
    {
        $this->assertSame(0x420031, Tag::DERIVATION_METHOD);
    }

    public function testTagDerivationParameters(): void
    {
        $this->assertSame(0x420032, Tag::DERIVATION_PARAMETERS);
    }

    public function testTagDerivationData(): void
    {
        $this->assertSame(0x420030, Tag::DERIVATION_DATA);
    }

    public function testTagLeaseTime(): void
    {
        $this->assertSame(0x420049, Tag::LEASE_TIME);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    /**
     * @return array<string, int>
     */
    private function getClassConstants(string $class): array
    {
        $ref = new \ReflectionClass($class);
        return $ref->getConstants();
    }
}
