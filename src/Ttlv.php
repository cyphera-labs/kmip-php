<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
 * Implements the OASIS KMIP 1.4 binary encoding.
 *
 * Each TTLV item:
 *   Tag:    3 bytes (identifies the field)
 *   Type:   1 byte  (data type)
 *   Length: 4 bytes  (value length in bytes)
 *   Value:  variable (padded to 8-byte alignment)
 */
final class Ttlv
{
    // KMIP data types
    public const TYPE_STRUCTURE   = 0x01;
    public const TYPE_INTEGER     = 0x02;
    public const TYPE_LONG_INTEGER = 0x03;
    public const TYPE_BIG_INTEGER = 0x04;
    public const TYPE_ENUMERATION = 0x05;
    public const TYPE_BOOLEAN     = 0x06;
    public const TYPE_TEXT_STRING = 0x07;
    public const TYPE_BYTE_STRING = 0x08;
    public const TYPE_DATE_TIME   = 0x09;
    public const TYPE_INTERVAL    = 0x0A;

    /**
     * Encode a TTLV item to a binary string.
     *
     * @param int    $tag   3-byte tag value (e.g., 0x420069)
     * @param int    $type  1-byte type value
     * @param string $value raw value bytes
     * @return string
     */
    public static function encode(int $tag, int $type, string $value): string
    {
        $valueLen = strlen($value);
        $padded = (int) ceil($valueLen / 8) * 8;

        // Tag: 3 bytes big-endian + Type: 1 byte
        $header = pack('C3C', ($tag >> 16) & 0xFF, ($tag >> 8) & 0xFF, $tag & 0xFF, $type);

        // Length: 4 bytes big-endian
        $header .= pack('N', $valueLen);

        // Value + padding
        $result = $header . $value;
        if ($padded > $valueLen) {
            $result .= str_repeat("\x00", $padded - $valueLen);
        }

        return $result;
    }

    /**
     * Encode a Structure (type 0x01) containing child TTLV items.
     */
    public static function encodeStructure(int $tag, array $children): string
    {
        $inner = implode('', $children);
        return self::encode($tag, self::TYPE_STRUCTURE, $inner);
    }

    /**
     * Encode a 32-bit integer.
     */
    public static function encodeInteger(int $tag, int $value): string
    {
        return self::encode($tag, self::TYPE_INTEGER, pack('N', $value & 0xFFFFFFFF));
    }

    /**
     * Encode a 64-bit long integer.
     */
    public static function encodeLongInteger(int $tag, int $value): string
    {
        return self::encode($tag, self::TYPE_LONG_INTEGER, pack('J', $value));
    }

    /**
     * Encode an enumeration (32-bit unsigned).
     */
    public static function encodeEnum(int $tag, int $value): string
    {
        return self::encode($tag, self::TYPE_ENUMERATION, pack('N', $value));
    }

    /**
     * Encode a boolean.
     */
    public static function encodeBoolean(int $tag, bool $value): string
    {
        return self::encode($tag, self::TYPE_BOOLEAN, pack('J', $value ? 1 : 0));
    }

    /**
     * Encode a text string (UTF-8).
     */
    public static function encodeTextString(int $tag, string $value): string
    {
        return self::encode($tag, self::TYPE_TEXT_STRING, $value);
    }

    /**
     * Encode a byte string (raw bytes).
     */
    public static function encodeByteString(int $tag, string $value): string
    {
        return self::encode($tag, self::TYPE_BYTE_STRING, $value);
    }

    /**
     * Encode a DateTime (64-bit POSIX timestamp).
     */
    public static function encodeDateTime(int $tag, int $value): string
    {
        return self::encode($tag, self::TYPE_DATE_TIME, pack('J', $value));
    }

    /**
     * Decode a TTLV buffer into a parsed tree.
     *
     * @param string $buf    Raw TTLV bytes.
     * @param int    $offset Starting offset.
     * @return array{tag: int, type: int, value: mixed, length: int, total_length: int}
     */
    public static function decode(string $buf, int $offset = 0): array
    {
        if (strlen($buf) - $offset < 8) {
            throw new \RuntimeException('TTLV buffer too short for header');
        }

        $bytes = unpack('C*', substr($buf, $offset, 8));
        $tag = ($bytes[1] << 16) | ($bytes[2] << 8) | $bytes[3];
        $type = $bytes[4];
        $length = ($bytes[5] << 24) | ($bytes[6] << 16) | ($bytes[7] << 8) | $bytes[8];
        $padded = (int) ceil($length / 8) * 8;
        $totalLength = 8 + $padded;
        $valueStart = $offset + 8;

        switch ($type) {
            case self::TYPE_STRUCTURE:
                $children = [];
                $pos = $valueStart;
                $end = $valueStart + $length;
                while ($pos < $end) {
                    $child = self::decode($buf, $pos);
                    $children[] = $child;
                    $pos += $child['total_length'];
                }
                $value = $children;
                break;

            case self::TYPE_INTEGER:
                $unpacked = unpack('N', substr($buf, $valueStart, 4));
                $val = $unpacked[1];
                // Handle signed 32-bit
                if ($val >= 0x80000000) {
                    $val -= 0x100000000;
                }
                $value = $val;
                break;

            case self::TYPE_LONG_INTEGER:
                $unpacked = unpack('J', substr($buf, $valueStart, 8));
                $value = $unpacked[1];
                break;

            case self::TYPE_ENUMERATION:
                $unpacked = unpack('N', substr($buf, $valueStart, 4));
                $value = $unpacked[1];
                break;

            case self::TYPE_BOOLEAN:
                $unpacked = unpack('J', substr($buf, $valueStart, 8));
                $value = $unpacked[1] !== 0;
                break;

            case self::TYPE_TEXT_STRING:
                $value = substr($buf, $valueStart, $length);
                break;

            case self::TYPE_BYTE_STRING:
                $value = substr($buf, $valueStart, $length);
                break;

            case self::TYPE_DATE_TIME:
                $unpacked = unpack('J', substr($buf, $valueStart, 8));
                $value = $unpacked[1];
                break;

            case self::TYPE_INTERVAL:
                $unpacked = unpack('N', substr($buf, $valueStart, 4));
                $value = $unpacked[1];
                break;

            default:
                $value = substr($buf, $valueStart, $length);
        }

        return [
            'tag' => $tag,
            'type' => $type,
            'value' => $value,
            'length' => $length,
            'total_length' => $totalLength,
        ];
    }

    /**
     * Find a child item by tag within a decoded structure.
     */
    public static function findChild(array $decoded, int $tag): ?array
    {
        if (!is_array($decoded['value'] ?? null)) {
            return null;
        }
        foreach ($decoded['value'] as $child) {
            if ($child['tag'] === $tag) {
                return $child;
            }
        }
        return null;
    }

    /**
     * Find all children by tag within a decoded structure.
     */
    public static function findChildren(array $decoded, int $tag): array
    {
        if (!is_array($decoded['value'] ?? null)) {
            return [];
        }
        return array_values(array_filter($decoded['value'], fn($c) => $c['tag'] === $tag));
    }
}
