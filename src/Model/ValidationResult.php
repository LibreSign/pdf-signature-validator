<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

final class ValidationResult
{
    /**
     * @var list<string>
     */
    private const VALID_STATES = [
        self::STATE_SIGNATURE_VALID,
        self::STATE_CERT_TRUSTED,
    ];

    /**
     * @param self::STATE_* $state
     */
    public function __construct(
        public readonly string $state,
        public readonly ?string $reason = null,
    ) {
        $this->isValid = in_array($state, self::VALID_STATES, true);
    }

    public readonly bool $isValid;

    // Signature validation states
    public const STATE_SIGNATURE_VALID = 'Signature is Valid.';
    public const STATE_SIGNATURE_INVALID = 'Signature is Invalid.';
    public const STATE_DIGEST_MISMATCH = 'Digest Mismatch.';
    public const STATE_DOCUMENT_CORRUPTED = "Document isn't signed or corrupted data.";
    public const STATE_NOT_VERIFIED = 'Signature has not yet been verified.';

    // Certificate validation states
    public const STATE_CERT_TRUSTED = 'Certificate is Trusted.';
    public const STATE_CERT_ISSUER_NOT_TRUSTED = "Certificate issuer isn't Trusted.";
    public const STATE_CERT_ISSUER_UNKNOWN = 'Certificate issuer is unknown.';
    public const STATE_CERT_REVOKED = 'Certificate has been Revoked.';
    public const STATE_CERT_EXPIRED = 'Certificate has Expired';
    public const STATE_CERT_NOT_VERIFIED = 'Certificate has not yet been verified.';
}
