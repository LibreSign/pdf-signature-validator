<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\ValidationStatus;

final class PopplerStatusMapper
{
    public function mapSignatureStatus(string $status): ValidationStatus
    {
        return match ($status) {
            'Signature is Valid.' => new ValidationStatus(1, 'Signature is valid.', $status),
            'Signature is Invalid.' => new ValidationStatus(2, 'Signature is invalid.', $status),
            'Digest Mismatch.' => new ValidationStatus(3, 'Digest mismatch.', $status),
            "Document isn't signed or corrupted data." => new ValidationStatus(4, "Document isn't signed or corrupted data.", $status),
            'Signature has not yet been verified.' => new ValidationStatus(5, 'Signature has not yet been verified.', $status),
            default => new ValidationStatus(6, 'Unknown validation failure.', $status),
        };
    }

    public function mapCertificateStatus(string $status): ValidationStatus
    {
        return match ($status) {
            'Certificate is Trusted.' => new ValidationStatus(1, 'Certificate is trusted.', $status),
            "Certificate issuer isn't Trusted." => new ValidationStatus(2, "Certificate issuer isn't trusted.", $status),
            'Certificate issuer is unknown.' => new ValidationStatus(3, 'Certificate issuer is unknown.', $status),
            'Certificate has been Revoked.' => new ValidationStatus(4, 'Certificate has been revoked.', $status),
            'Certificate has Expired' => new ValidationStatus(5, 'Certificate has expired', $status),
            'Certificate has not yet been verified.' => new ValidationStatus(6, 'Certificate has not yet been verified.', $status),
            default => new ValidationStatus(7, 'Unknown issue with Certificate or corrupted data.', $status),
        };
    }
}
