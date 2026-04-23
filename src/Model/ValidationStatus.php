<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

final class ValidationStatus
{
    public function __construct(
        public readonly int $id,
        public readonly string $label,
        public readonly string $raw,
    ) {
    }
}
