<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

final class ExtractedSignature
{
    public function __construct(
        public readonly ?string $binarySignature,
        public readonly SignatureMetadata $metadata,
        public readonly ?string $hashAlgorithm,
    ) {
    }
}
