<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * State of one DocMDP evaluation, never shared between documents.
 *
 * @psalm-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @phpstan-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 */
final class DocMdpRevisionState
{
    /** @var array<int, PdfObject> */
    public array $newObjects = [];

    /** @var array<int, int> */
    public array $newObjectRevisions = [];

    /** @var array<string, int> */
    public array $timestampFieldRevisions = [];

    /** @var array<int, PdfObject> */
    public array $currentObjects = [];

    public function __construct(
        public readonly int $rootNumber,
        public readonly ?int $acroFormNumber,
        public readonly ?int $infoNumber,
        public ?string $dssReference,
    ) {
    }

    /** @return array<string, true> */
    public function timestampFieldsAvailableAt(int $revision): array
    {
        $available = [];
        foreach ($this->timestampFieldRevisions as $reference => $introducedAt) {
            if ($introducedAt <= $revision) {
                $available[$reference] = true;
            }
        }

        return $available;
    }
}
