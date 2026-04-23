<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

final class SignatureMetadata
{
    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int}|null $range
     */
    public function __construct(
        public readonly ?string $field,
        public readonly ?array $range,
        public readonly ?string $signatureType,
        public readonly bool $coversEntireDocument,
    ) {
    }
}
