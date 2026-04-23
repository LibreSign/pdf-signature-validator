<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

enum ValidationState: string
{
    case SIGNATURE_VALID = 'Signature is Valid.';
    case SIGNATURE_INVALID = 'Signature is Invalid.';
    case DIGEST_MISMATCH = 'Digest Mismatch.';
    case DOCUMENT_CORRUPTED = "Document isn't signed or corrupted data.";
    case NOT_VERIFIED = 'Signature has not yet been verified.';

    case CERT_TRUSTED = 'Certificate is Trusted.';
    case CERT_ISSUER_NOT_TRUSTED = "Certificate issuer isn't Trusted.";
    case CERT_ISSUER_UNKNOWN = 'Certificate issuer is unknown.';
    case CERT_REVOKED = 'Certificate has been Revoked.';
    case CERT_EXPIRED = 'Certificate has Expired';
    case CERT_NOT_VERIFIED = 'Certificate has not yet been verified.';

    public function isValid(): bool
    {
        return $this === self::SIGNATURE_VALID || $this === self::CERT_TRUSTED;
    }
}
