<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

/**
 * Strict structural checks for trailers in post-certification revisions.
 *
 * @psalm-import-type PdfObject from PdfIncrementalRevisionReader
 * @psalm-import-type SignedRevision from PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from PdfIncrementalRevisionReader
 * @phpstan-import-type SignedRevision from PdfIncrementalRevisionReader
 */
final class PdfRevisionTrailerPolicy
{
    /**
     * @param array<string,string> $trailer
     * @param SignedRevision $signed
     * @param array<int,PdfObject> $objects
     */
    public function matches(
        array $trailer,
        int $previousXref,
        array $signed,
        array $objects,
        ?string &$currentInfo,
    ): bool {
        if (($trailer['/Prev'] ?? null) !== (string) $previousXref
            || ($trailer['/Root'] ?? null) !== $signed['root']
            || isset($trailer['/Encrypt']) || isset($trailer['/XRefStm'])) {
            return false;
        }

        $info = $trailer['/Info'] ?? $currentInfo;
        if ($info === $currentInfo) {
            return true;
        }
        if ($currentInfo !== null || $info === null
            || !$this->isSafeNewInfo($info, $objects, $signed['size'])) {
            return false;
        }

        $currentInfo = $info;
        return true;
    }

    /**
     * Allow only the first creation of an ancillary, non-content Info object.
     * Rewriting existing Info references or adding title/author/actions does
     * not qualify for a validation-data exception.
     *
     * @param array<int,PdfObject> $objects
     */
    private function isSafeNewInfo(string $reference, array $objects, int $originalSize): bool
    {
        if (!preg_match('/^(\d+) (\d+) R$/', $reference, $match)) {
            return false;
        }
        $number = (int) $match[1];
        $object = $objects[$number] ?? null;
        if ($number < $originalSize || $object === null
            || $object['gen'] !== (int) $match[2]
            || $object['stream'] !== null || $object['entries'] === null
            || $object['entries'] === []) {
            return false;
        }

        foreach ($object['entries'] as $key => $value) {
            if (!in_array($key, ['/ModDate', '/Producer'], true)
                || preg_match('/^<[0-9a-f]*>$/', $value) !== 1) {
                return false;
            }
        }

        return true;
    }
}
