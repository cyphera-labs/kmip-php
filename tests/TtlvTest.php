<?php

declare(strict_types=1);

namespace Cyphera\Kmip\Tests;

use PHPUnit\Framework\TestCase;
use Cyphera\Kmip\Ttlv;

final class TtlvTest extends TestCase
{
    public function testEncodeDecodeInteger(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 1);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x42006A, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_INTEGER, $decoded['type']);
        $this->assertSame(1, $decoded['value']);
    }

    public function testEncodeDecodeEnumeration(): void
    {
        $encoded = Ttlv::encodeEnum(0x42005C, 0x0000000A);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x42005C, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_ENUMERATION, $decoded['type']);
        $this->assertSame(0x0000000A, $decoded['value']);
    }

    public function testEncodeDecodeTextString(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, 'my-key');
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x420055, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_TEXT_STRING, $decoded['type']);
        $this->assertSame('my-key', $decoded['value']);
    }

    public function testEncodeDecodeByteString(): void
    {
        $key = hex2bin('aabbccdd');
        $encoded = Ttlv::encodeByteString(0x420043, $key);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x420043, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_BYTE_STRING, $decoded['type']);
        $this->assertSame($key, $decoded['value']);
    }

    public function testEncodeDecodeBoolean(): void
    {
        $encoded = Ttlv::encodeBoolean(0x420008, true);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(Ttlv::TYPE_BOOLEAN, $decoded['type']);
        $this->assertTrue($decoded['value']);
    }

    public function testEncodeDecodeStructure(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, [
            Ttlv::encodeInteger(0x42006A, 1),
            Ttlv::encodeInteger(0x42006B, 4),
        ]);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x420069, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_STRUCTURE, $decoded['type']);
        $this->assertCount(2, $decoded['value']);
        $this->assertSame(1, $decoded['value'][0]['value']);
        $this->assertSame(4, $decoded['value'][1]['value']);
    }

    public function testFindChild(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, [
            Ttlv::encodeInteger(0x42006A, 1),
            Ttlv::encodeInteger(0x42006B, 4),
        ]);
        $decoded = Ttlv::decode($encoded);
        $child = Ttlv::findChild($decoded, 0x42006B);
        $this->assertNotNull($child);
        $this->assertSame(4, $child['value']);
    }

    public function testTextStringPadding(): void
    {
        // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        $encoded = Ttlv::encodeTextString(0x420055, 'hello');
        $this->assertSame(16, strlen($encoded)); // 8 header + 8 padded value
    }

    public function testEmptyTextString(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, '');
        $decoded = Ttlv::decode($encoded);
        $this->assertSame('', $decoded['value']);
    }

    public function testNestedStructures(): void
    {
        $encoded = Ttlv::encodeStructure(0x420078, [
            Ttlv::encodeStructure(0x420077, [
                Ttlv::encodeStructure(0x420069, [
                    Ttlv::encodeInteger(0x42006A, 1),
                    Ttlv::encodeInteger(0x42006B, 4),
                ]),
                Ttlv::encodeInteger(0x42000D, 1),
            ]),
        ]);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x420078, $decoded['tag']);
        $header = Ttlv::findChild($decoded, 0x420077);
        $this->assertNotNull($header);
        $version = Ttlv::findChild($header, 0x420069);
        $this->assertNotNull($version);
        $major = Ttlv::findChild($version, 0x42006A);
        $this->assertSame(1, $major['value']);
    }
}
