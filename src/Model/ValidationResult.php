<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

final class ValidationResult
{
    public function __construct(
        public readonly ValidationState $state,
        public readonly ?string $reason = null,
    ) {
        $this->isValid = $state->isValid();
    }

    public readonly bool $isValid;
}
