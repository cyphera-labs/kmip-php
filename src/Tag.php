<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * KMIP 1.4 tag, type, and enum constants.
 *
 * Reference: OASIS KMIP Specification v1.4
 * https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
 */
final class Tag
{
    // Message structure
    public const REQUEST_MESSAGE        = 0x420078;
    public const RESPONSE_MESSAGE       = 0x42007B;
    public const REQUEST_HEADER         = 0x420077;
    public const RESPONSE_HEADER        = 0x42007A;
    public const PROTOCOL_VERSION       = 0x420069;
    public const PROTOCOL_VERSION_MAJOR = 0x42006A;
    public const PROTOCOL_VERSION_MINOR = 0x42006B;
    public const BATCH_COUNT            = 0x42000D;
    public const BATCH_ITEM             = 0x42000F;
    public const OPERATION              = 0x42005C;
    public const REQUEST_PAYLOAD        = 0x420079;
    public const RESPONSE_PAYLOAD       = 0x42007C;
    public const RESULT_STATUS          = 0x42007F;
    public const RESULT_REASON          = 0x420080;
    public const RESULT_MESSAGE         = 0x420081;

    // Object identification
    public const UNIQUE_IDENTIFIER = 0x420094;
    public const OBJECT_TYPE       = 0x420057;

    // Naming
    public const NAME       = 0x420053;
    public const NAME_VALUE = 0x420055;
    public const NAME_TYPE  = 0x420054;

    // Attributes (KMIP 1.x style)
    public const ATTRIBUTE       = 0x420008;
    public const ATTRIBUTE_NAME  = 0x42000A;
    public const ATTRIBUTE_VALUE = 0x42000B;

    // Key structure
    public const SYMMETRIC_KEY   = 0x42008F;
    public const KEY_BLOCK       = 0x420040;
    public const KEY_FORMAT_TYPE = 0x420042;
    public const KEY_VALUE       = 0x420045;
    public const KEY_MATERIAL    = 0x420043;

    // Crypto attributes
    public const CRYPTOGRAPHIC_ALGORITHM  = 0x420028;
    public const CRYPTOGRAPHIC_LENGTH     = 0x42002A;
    public const CRYPTOGRAPHIC_USAGE_MASK = 0x42002C;

    // Template
    public const TEMPLATE_ATTRIBUTE = 0x420091;

    // Key pair
    public const PRIVATE_KEY_UNIQUE_IDENTIFIER = 0x420066;
    public const PUBLIC_KEY_UNIQUE_IDENTIFIER  = 0x42006F;
    public const PUBLIC_KEY                    = 0x42004E;
    public const PRIVATE_KEY                   = 0x42004D;

    // Certificate
    public const CERTIFICATE       = 0x420021;
    public const CERTIFICATE_TYPE  = 0x42001D;
    public const CERTIFICATE_VALUE = 0x42001E;

    // Crypto operations
    public const DATA               = 0x420033;
    public const IV_COUNTER_NONCE   = 0x420047;
    public const SIGNATURE_DATA     = 0x42004F;
    public const MAC_DATA           = 0x420051;
    public const VALIDITY_INDICATOR = 0x420098;

    // Revocation
    public const REVOCATION_REASON      = 0x420082;
    public const REVOCATION_REASON_CODE = 0x420083;

    // Query
    public const QUERY_FUNCTION = 0x420074;

    // State
    public const STATE = 0x42008D;

    // Derivation
    public const DERIVATION_METHOD     = 0x420031;
    public const DERIVATION_PARAMETERS = 0x420032;
    public const DERIVATION_DATA       = 0x420030;

    // Lease
    public const LEASE_TIME = 0x420049;
}

final class Operation
{
    public const CREATE             = 0x00000001;
    public const CREATE_KEY_PAIR    = 0x00000002;
    public const REGISTER           = 0x00000003;
    public const RE_KEY             = 0x00000004;
    public const DERIVE_KEY         = 0x00000005;
    public const LOCATE             = 0x00000008;
    public const CHECK              = 0x00000009;
    public const GET                = 0x0000000A;
    public const GET_ATTRIBUTES     = 0x0000000B;
    public const GET_ATTRIBUTE_LIST = 0x0000000C;
    public const ADD_ATTRIBUTE      = 0x0000000D;
    public const MODIFY_ATTRIBUTE   = 0x0000000E;
    public const DELETE_ATTRIBUTE   = 0x0000000F;
    public const OBTAIN_LEASE       = 0x00000010;
    public const ACTIVATE           = 0x00000012;
    public const REVOKE             = 0x00000013;
    public const DESTROY            = 0x00000014;
    public const ARCHIVE            = 0x00000015;
    public const RECOVER            = 0x00000016;
    public const QUERY              = 0x00000018;
    public const POLL               = 0x0000001A;
    public const DISCOVER_VERSIONS  = 0x0000001E;
    public const ENCRYPT            = 0x0000001F;
    public const DECRYPT            = 0x00000020;
    public const SIGN               = 0x00000021;
    public const SIGNATURE_VERIFY   = 0x00000022;
    public const MAC                = 0x00000023;
}

final class ObjectType
{
    public const CERTIFICATE   = 0x00000001;
    public const SYMMETRIC_KEY = 0x00000002;
    public const PUBLIC_KEY    = 0x00000003;
    public const PRIVATE_KEY   = 0x00000004;
    public const SPLIT_KEY     = 0x00000005;
    public const TEMPLATE      = 0x00000006;
    public const SECRET_DATA   = 0x00000007;
    public const OPAQUE_DATA   = 0x00000008;
}

final class ResultStatus
{
    public const SUCCESS           = 0x00000000;
    public const OPERATION_FAILED  = 0x00000001;
    public const OPERATION_PENDING = 0x00000002;
    public const OPERATION_UNDONE  = 0x00000003;
}

final class KeyFormatType
{
    public const RAW                  = 0x00000001;
    public const OPAQUE               = 0x00000002;
    public const PKCS1                = 0x00000003;
    public const PKCS8                = 0x00000004;
    public const X509                 = 0x00000005;
    public const EC_PRIVATE_KEY       = 0x00000006;
    public const TRANSPARENT_SYMMETRIC = 0x00000007;
}

final class Algorithm
{
    public const DES         = 0x00000001;
    public const TRIPLE_DES  = 0x00000002;
    public const AES         = 0x00000003;
    public const RSA         = 0x00000004;
    public const DSA         = 0x00000005;
    public const ECDSA       = 0x00000006;
    public const HMAC_SHA1   = 0x00000007;
    public const HMAC_SHA224 = 0x00000008;
    public const HMAC_SHA256 = 0x00000009;
    public const HMAC_SHA384 = 0x0000000A;
    public const HMAC_SHA512 = 0x0000000B;
    public const HMAC_MD5    = 0x0000000C;
}

final class NameType
{
    public const UNINTERPRETED_TEXT_STRING = 0x00000001;
    public const URI                      = 0x00000002;
}

final class UsageMask
{
    public const SIGN          = 0x00000001;
    public const VERIFY        = 0x00000002;
    public const ENCRYPT       = 0x00000004;
    public const DECRYPT       = 0x00000008;
    public const WRAP_KEY      = 0x00000010;
    public const UNWRAP_KEY    = 0x00000020;
    public const EXPORT        = 0x00000040;
    public const MAC_GENERATE  = 0x00000080;
    public const MAC_VERIFY    = 0x00000100;
    public const DERIVE_KEY    = 0x00000200;
    public const KEY_AGREEMENT = 0x00000800;
}
