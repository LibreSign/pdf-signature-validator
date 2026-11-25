<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

/**
 * Certification in the linked revision history, distinct from signatures
 * that are active in the final document. Inconclusive results are never
 * sufficient to authorize modifications or additional signatures.
 */
final class PdfSignatureHistory
{
    public function __construct(
        public readonly bool $isConclusive,
        public readonly SignatureInventory $current,
        public readonly ?ActiveSignature $certification = null,
        public readonly ?DocMdpPermission $permission = null,
    ) {
    }
}
