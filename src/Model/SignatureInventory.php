<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

/**
 * The signature dictionaries of a PDF, split by whether the document uses them.
 *
 * Active signatures are the ones a signature field (/V) or the catalog
 * (/Perms /DocMDP) points to. Orphaned signatures are signature dictionaries
 * that nothing in the document points to, so they have no effect.
 *
 * When the structure cannot be read, $isConclusive is false and the counts
 * and permission carry no information. Callers should then fall back to
 * their most restrictive behavior.
 */
final class SignatureInventory
{
    public function __construct(
        public readonly bool $isConclusive,
        public readonly int $activeSignatureCount = 0,
        public readonly int $orphanedSignatureCount = 0,
        public readonly ?DocMdpPermission $docMdpPermission = null,
    ) {
    }
}
