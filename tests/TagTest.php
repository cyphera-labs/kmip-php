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
    // Operation values -- KMIP 1.4 Section 9.1.3.2.2
    // -----------------------------------------------------------------------

    public function testOperationCreate(): void
    {
        $this->assertSame(0x00000001, Operation::CREATE);
    }

    public function testOperationLocate(): void
    {
        $this->assertSame(0x00000008, Operation::LOCATE);
    }

    public function testOperationGet(): void
    {
        $this->assertSame(0x0000000A, Operation::GET);
    }

    public function testOperationActivate(): void
    {
        $this->assertSame(0x00000012, Operation::ACTIVATE);
    }

    public function testOperationDestroy(): void
    {
        $this->assertSame(0x00000014, Operation::DESTROY);
    }

    public function testOperationCheck(): void
    {
        $this->assertSame(0x0000001C, Operation::CHECK);
    }

    public function testOperationNoDuplicateValues(): void
    {
        $values = $this->getClassConstants(Operation::class);
        $this->assertSame(count($values), count(array_unique($values)));
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
