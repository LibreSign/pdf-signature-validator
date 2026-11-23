<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

/**
 * A signature reached through the active PDF object graph, never an orphan.
 *
 * Each byte range describes (offset, length). signedRevisionEnd is the end of
 * the last signed range, not the number of PDF incremental revisions.
 * Identity may be null when the signature dictionary is inline.
 */
final class ActiveSignature
{
    /**
     * @param list<array{offset:int,length:int}> $byteRanges
     */
    public function __construct(
        public readonly ?int $objectNumber,
        public readonly array $byteRanges,
        public readonly int $signedRevisionEnd,
        public readonly bool $isCertifying,
        public readonly bool $isDocumentTimestamp,
    ) {
    }
}
