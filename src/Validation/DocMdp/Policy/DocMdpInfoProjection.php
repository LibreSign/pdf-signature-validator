<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use UnexpectedValueException;

/**
 * @psalm-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 */
final class DocMdpInfoProjection
{
    /** @param array<int,PdfObject> $remaining */
    public function project(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        array &$remaining,
        ?string $previous,
        ?string $current,
    ): void {
        if ($current === null) {
            return;
        }
        $object = $after->document->resolve($current);
        if ($object === null || !isset($remaining[$object['num']])) {
            return;
        }
        if (($after->incoming[$object['num']] ?? []) !== [] || ($before->incoming[$object['num']] ?? []) !== []) {
            throw new UnexpectedValueException('Information dictionary shared with document objects');
        }
        $previousObject = $previous === null ? null : $before->document->resolve($previous);
        $old = $previousObject['entries'] ?? [];
        $new = $object['entries'];
        if ($new === null || $object['stream'] !== null) {
            throw new UnexpectedValueException('Invalid information dictionary');
        }
        $this->checkEntries($old, $new);
        // Info metadata is ancillary; it never authorizes a revision alone.
        unset($remaining[$object['num']]);
    }


    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     */
    private function checkEntries(array $old, array $new): void
    {
        foreach (array_keys($old + $new) as $key) {
            if (($old[$key] ?? null) !== ($new[$key] ?? null)
                && (!in_array($key, ['/ModDate', '/Producer'], true)
                    || preg_match('/^<[0-9a-f]*>$/D', $new[$key] ?? '') !== 1)) {
                throw new UnexpectedValueException('Non-ancillary information change');
            }
        }
    }
}
