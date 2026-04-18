<?php

declare(strict_types=1);

namespace Cyphera\Kmip\Tests;

use PHPUnit\Framework\TestCase;
use Cyphera\Kmip\Ttlv;
use Cyphera\Kmip\Tag;

final class TtlvTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Primitive encode / decode round-trips
    // -----------------------------------------------------------------------

    public function testEncodeDecodeInteger(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 1);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x42006A, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_INTEGER, $decoded['type']);
        $this->assertSame(1, $decoded['value']);
    }

    public function testEncodeDecodeNegativeInteger(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, -42);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(-42, $decoded['value']);
    }

    public function testEncodeDecodeMaxInt32(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 0x7FFFFFFF);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x7FFFFFFF, $decoded['value']);
    }

    public function testEncodeDecodeZeroInteger(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 0);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0, $decoded['value']);
    }

    public function testEncodeDecodeEnumeration(): void
    {
        $encoded = Ttlv::encodeEnum(0x42005C, 0x0000000A);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x42005C, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_ENUMERATION, $decoded['type']);
        $this->assertSame(0x0000000A, $decoded['value']);
    }

    public function testEncodeDecodeLongInteger(): void
    {
        $encoded = Ttlv::encodeLongInteger(0x42006A, 1234567890123);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0x42006A, $decoded['tag']);
        $this->assertSame(Ttlv::TYPE_LONG_INTEGER, $decoded['type']);
        $this->assertSame(1234567890123, $decoded['value']);
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

    public function testEncodeDecodeBooleanTrue(): void
    {
        $encoded = Ttlv::encodeBoolean(0x420008, true);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(Ttlv::TYPE_BOOLEAN, $decoded['type']);
        $this->assertTrue($decoded['value']);
    }

    public function testEncodeDecodeBooleanFalse(): void
    {
        $encoded = Ttlv::encodeBoolean(0x420008, false);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(Ttlv::TYPE_BOOLEAN, $decoded['type']);
        $this->assertFalse($decoded['value']);
    }

    public function testEncodeDecodeDateTime(): void
    {
        $ts = 1776556800; // 2026-04-18T12:00:00Z approx
        $encoded = Ttlv::encodeDateTime(0x420008, $ts);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(Ttlv::TYPE_DATE_TIME, $decoded['type']);
        $this->assertSame($ts, $decoded['value']);
    }

    public function testEncodeDecodeDateTimeEpochZero(): void
    {
        $encoded = Ttlv::encodeDateTime(0x420008, 0);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0, $decoded['value']);
    }

    // -----------------------------------------------------------------------
    // Padding and alignment
    // -----------------------------------------------------------------------

    public function testIntegerOccupies16BytesTotal(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 1);
        // 8 header + 8 padded value (4 value + 4 padding) = 16 bytes
        $this->assertSame(16, strlen($encoded));
        // Length field at offset 4 should say 4
        $this->assertSame(4, unpack('N', substr($encoded, 4, 4))[1]);
    }

    public function testEnumOccupies16BytesTotal(): void
    {
        $encoded = Ttlv::encodeEnum(0x42005C, 1);
        $this->assertSame(16, strlen($encoded));
        $this->assertSame(4, unpack('N', substr($encoded, 4, 4))[1]);
    }

    public function testBooleanUsesExactly8ByteValue(): void
    {
        $encoded = Ttlv::encodeBoolean(0x420008, true);
        $this->assertSame(16, strlen($encoded)); // 8 header + 8 value
        $this->assertSame(8, unpack('N', substr($encoded, 4, 4))[1]);
    }

    public function testLongIntegerUsesExactly8ByteValue(): void
    {
        $encoded = Ttlv::encodeLongInteger(0x42006A, 42);
        $this->assertSame(16, strlen($encoded));
        $this->assertSame(8, unpack('N', substr($encoded, 4, 4))[1]);
    }

    public function testTextStringPadding(): void
    {
        // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        $encoded = Ttlv::encodeTextString(0x420055, 'hello');
        $this->assertSame(16, strlen($encoded));
    }

    public function testTextStringExactly8BytesNoPadding(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, '12345678');
        $this->assertSame(16, strlen($encoded)); // 8 header + 8 value
    }

    public function testTextString9BytesPadsTo16(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, '123456789');
        $this->assertSame(24, strlen($encoded)); // 8 header + 16 padded
    }

    public function testEmptyTextString(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, '');
        $this->assertSame(8, strlen($encoded)); // header only
        $decoded = Ttlv::decode($encoded);
        $this->assertSame('', $decoded['value']);
    }

    public function testByteStringExact8ByteAlignment(): void
    {
        $data = str_repeat("\xAB", 16);
        $encoded = Ttlv::encodeByteString(0x420043, $data);
        $this->assertSame(24, strlen($encoded)); // 8 header + 16 value
    }

    public function testByteString1ExtraBytePadsToNext8(): void
    {
        $data = str_repeat("\xAB", 17);
        $encoded = Ttlv::encodeByteString(0x420043, $data);
        $this->assertSame(32, strlen($encoded)); // 8 header + 24 padded
    }

    public function testEmptyByteString(): void
    {
        $encoded = Ttlv::encodeByteString(0x420043, '');
        $this->assertSame(8, strlen($encoded));
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(0, strlen($decoded['value']));
    }

    public function test32ByteKeyMaterialRoundTripsAES256(): void
    {
        $key = hex2bin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
        $encoded = Ttlv::encodeByteString(0x420043, $key);
        $this->assertSame(40, strlen($encoded)); // 8 header + 32 value (exact alignment)
        $decoded = Ttlv::decode($encoded);
        $this->assertSame($key, $decoded['value']);
    }

    // -----------------------------------------------------------------------
    // Structures and tree navigation
    // -----------------------------------------------------------------------

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

    public function testEmptyStructure(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, []);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(Ttlv::TYPE_STRUCTURE, $decoded['type']);
        $this->assertCount(0, $decoded['value']);
    }

    public function testStructureWithMixedTypes(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, [
            Ttlv::encodeInteger(0x42006A, 42),
            Ttlv::encodeTextString(0x420055, 'hello'),
            Ttlv::encodeBoolean(0x420008, true),
            Ttlv::encodeByteString(0x420043, hex2bin('cafe')),
            Ttlv::encodeEnum(0x42005C, 0x0A),
        ]);
        $decoded = Ttlv::decode($encoded);
        $this->assertCount(5, $decoded['value']);
        $this->assertSame(42, $decoded['value'][0]['value']);
        $this->assertSame('hello', $decoded['value'][1]['value']);
        $this->assertTrue($decoded['value'][2]['value']);
        $this->assertSame(hex2bin('cafe'), $decoded['value'][3]['value']);
        $this->assertSame(0x0A, $decoded['value'][4]['value']);
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

    public function testFindChildReturnsNullForMissingTag(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, [
            Ttlv::encodeInteger(0x42006A, 1),
        ]);
        $decoded = Ttlv::decode($encoded);
        $this->assertNull(Ttlv::findChild($decoded, 0x42FFFF));
    }

    public function testFindChildReturnsNullForNonStructure(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 1);
        $decoded = Ttlv::decode($encoded);
        $this->assertNull(Ttlv::findChild($decoded, 0x42006A));
    }

    public function testFindChildrenReturnsAllMatching(): void
    {
        $encoded = Ttlv::encodeStructure(0x420069, [
            Ttlv::encodeTextString(0x420094, 'id-1'),
            Ttlv::encodeTextString(0x420094, 'id-2'),
            Ttlv::encodeTextString(0x420094, 'id-3'),
            Ttlv::encodeInteger(0x42006A, 99),
        ]);
        $decoded = Ttlv::decode($encoded);
        $ids = Ttlv::findChildren($decoded, 0x420094);
        $this->assertCount(3, $ids);
        $this->assertSame('id-1', $ids[0]['value']);
        $this->assertSame('id-2', $ids[1]['value']);
        $this->assertSame('id-3', $ids[2]['value']);
    }

    public function testFindChildrenReturnsEmptyForNonStructure(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 1);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame([], Ttlv::findChildren($decoded, 0x42006A));
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
        $minor = Ttlv::findChild($version, 0x42006B);
        $this->assertSame(4, $minor['value']);
    }

    public function testThreeLevelNestedStructures(): void
    {
        $encoded = Ttlv::encodeStructure(0x420001, [
            Ttlv::encodeStructure(0x420002, [
                Ttlv::encodeStructure(0x420003, [
                    Ttlv::encodeTextString(0x420055, 'deep'),
                ]),
            ]),
        ]);
        $decoded = Ttlv::decode($encoded);
        $lvl1 = Ttlv::findChild($decoded, 0x420002);
        $lvl2 = Ttlv::findChild($lvl1, 0x420003);
        $leaf = Ttlv::findChild($lvl2, 0x420055);
        $this->assertSame('deep', $leaf['value']);
    }

    // -----------------------------------------------------------------------
    // Wire format verification
    // -----------------------------------------------------------------------

    public function testTagEncodedAs3BytesBigEndian(): void
    {
        $encoded = Ttlv::encodeInteger(0x420069, 0);
        $this->assertSame(0x42, ord($encoded[0]));
        $this->assertSame(0x00, ord($encoded[1]));
        $this->assertSame(0x69, ord($encoded[2]));
    }

    public function testTypeByteIsCorrectForEachType(): void
    {
        $this->assertSame(Ttlv::TYPE_INTEGER, ord(Ttlv::encodeInteger(0x420001, 0)[3]));
        $this->assertSame(Ttlv::TYPE_LONG_INTEGER, ord(Ttlv::encodeLongInteger(0x420001, 0)[3]));
        $this->assertSame(Ttlv::TYPE_ENUMERATION, ord(Ttlv::encodeEnum(0x420001, 0)[3]));
        $this->assertSame(Ttlv::TYPE_BOOLEAN, ord(Ttlv::encodeBoolean(0x420001, true)[3]));
        $this->assertSame(Ttlv::TYPE_TEXT_STRING, ord(Ttlv::encodeTextString(0x420001, 'x')[3]));
        $this->assertSame(Ttlv::TYPE_BYTE_STRING, ord(Ttlv::encodeByteString(0x420001, "\x01")[3]));
        $this->assertSame(Ttlv::TYPE_STRUCTURE, ord(Ttlv::encodeStructure(0x420001, [])[3]));
        $this->assertSame(Ttlv::TYPE_DATE_TIME, ord(Ttlv::encodeDateTime(0x420001, 0)[3]));
    }

    public function testLengthFieldIs4BytesBigEndianAtOffset4(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, 'AB'); // 2 bytes
        $this->assertSame(2, unpack('N', substr($encoded, 4, 4))[1]);
    }

    public function testPaddingBytesAreZeroFilled(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, 'AB'); // 2 bytes -> padded to 8
        // Bytes 10-15 (value at offset 8, length 2, padding at 10-15)
        for ($i = 10; $i < 16; $i++) {
            $this->assertSame(0, ord($encoded[$i]), "padding byte at $i should be 0");
        }
    }

    // -----------------------------------------------------------------------
    // Error handling
    // -----------------------------------------------------------------------

    public function testThrowsOnBufferTooShortForHeader(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/too short/');
        Ttlv::decode(str_repeat("\x00", 4));
    }

    public function testThrowsOnEmptyBuffer(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/too short/');
        Ttlv::decode('');
    }

    // -----------------------------------------------------------------------
    // Unicode and special strings
    // -----------------------------------------------------------------------

    public function testUtf8MultiByteCharacters(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, 'cafe\xCC\x81'); // "café" NFD
        $decoded = Ttlv::decode($encoded);
        $this->assertSame('cafe\xCC\x81', $decoded['value']);
    }

    public function testUtf8Cafe(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, "caf\xC3\xA9");
        $decoded = Ttlv::decode($encoded);
        $this->assertSame("caf\xC3\xA9", $decoded['value']);
    }

    public function testEmojiString(): void
    {
        $str = "key-\xF0\x9F\x94\x91"; // key-🔑
        $encoded = Ttlv::encodeTextString(0x420055, $str);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame($str, $decoded['value']);
    }

    public function testLongTextStringCrossingMultiple8ByteBoundaries(): void
    {
        $longStr = str_repeat('a]', 100); // 200 bytes
        $encoded = Ttlv::encodeTextString(0x420055, $longStr);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame($longStr, $decoded['value']);
    }

    // -----------------------------------------------------------------------
    // Decoded array keys
    // -----------------------------------------------------------------------

    public function testDecodedArrayContainsExpectedKeys(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 5);
        $decoded = Ttlv::decode($encoded);
        $this->assertArrayHasKey('tag', $decoded);
        $this->assertArrayHasKey('type', $decoded);
        $this->assertArrayHasKey('value', $decoded);
        $this->assertArrayHasKey('length', $decoded);
        $this->assertArrayHasKey('total_length', $decoded);
    }

    public function testDecodedIntegerLengthIs4(): void
    {
        $encoded = Ttlv::encodeInteger(0x42006A, 99);
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(4, $decoded['length']);
        $this->assertSame(16, $decoded['total_length']);
    }

    public function testDecodedTextStringLengthMatchesContent(): void
    {
        $encoded = Ttlv::encodeTextString(0x420055, 'hello');
        $decoded = Ttlv::decode($encoded);
        $this->assertSame(5, $decoded['length']);
        $this->assertSame(16, $decoded['total_length']); // 8 header + 8 padded
    }
}
