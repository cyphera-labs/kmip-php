<?php

declare(strict_types=1);

namespace Cyphera\Kmip;

/**
 * Structured KMIP exception carrying result status and reason codes.
 *
 * Extends \RuntimeException so existing catch blocks continue to work.
 */
class KmipException extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $resultStatus = 0,
        public readonly int $resultReason = 0,
    ) {
        parent::__construct($message);
    }
}
