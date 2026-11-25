<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Model;

/** Object roles proven in a single revision and its preceding DSS history. */
final class DocMdpValidationOwnership
{
    /**
     * @param array<int,true> $dss
     * @param array<int,true> $historicalDss
     * @param array<int,true> $timestamps
     * @param array<int,int> $values
     */
    public function __construct(
        public readonly int $root,
        public readonly int $originalSize,
        public readonly array $dss,
        public readonly array $historicalDss,
        public readonly int $formOwner,
        public readonly string $fieldPath,
        public readonly array $timestamps,
        public readonly array $values,
        public readonly ?int $info,
    ) {
    }

    public function containsNewObject(int $number): bool
    {
        return $number < $this->originalSize || $number === $this->info
            || isset($this->dss[$number]) || isset($this->timestamps[$number]) || isset($this->values[$number]);
    }

    public function ownsReferenceSource(int $number): bool
    {
        return isset($this->historicalDss[$number]) || isset($this->timestamps[$number]) || isset($this->values[$number]);
    }
}
