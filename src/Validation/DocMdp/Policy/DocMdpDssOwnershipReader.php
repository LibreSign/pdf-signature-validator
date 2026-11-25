<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;

/** Resolves exclusively owned validation-data evidence objects. */
final class DocMdpDssOwnershipReader
{
    /** @return array<int,true>|null */
    public function read(PdfRevisionObjects $live, ?string $reference, PdfReferencePaths $references): ?array
    {
        if ($reference === null) {
            return [];
        }
        $root = $live->resolve($reference);
        if ($root === null) {
            return null;
        }
        // Pre-existing validation data does not confer ownership of newly introduced objects.
        if ($root['num'] < $live->originalSize) {
            return [];
        }
        return $this->walkEvidence($live, $reference, $references);
    }

    /** @return array<int,true>|null */
    private function walkEvidence(PdfRevisionObjects $live, string $reference, PdfReferencePaths $references): ?array
    {
        $pending = [$reference];
        $owned = [];
        while ($pending !== []) {
            $object = $live->resolve(array_pop($pending));
            if ($object === null || $object['num'] < $live->originalSize) {
                return null;
            }
            $number = $object['num'];
            if (isset($owned[$number])) {
                continue;
            }
            if (!$this->hasEvidenceStreamProperties($object['entries'], $object['stream'])) {
                return null;
            }
            $owned[$number] = true;
            $paths = $references->read($object['value']);
            if ($paths === null || ($object['stream'] !== null && $paths !== [])) {
                return null;
            }
            foreach ($paths as $path) {
                $pending[] = $path['reference'];
            }
        }

        return $owned;
    }

    /** @param array<string,string>|null $entries */
    private function hasEvidenceStreamProperties(?array $entries, ?string $stream): bool
    {
        return $stream === null || array_diff(array_keys($entries ?? []), ['/Length', '/Filter', '/DecodeParms', '/DL']) === [];
    }

}
