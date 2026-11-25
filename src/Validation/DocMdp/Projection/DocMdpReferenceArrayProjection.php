<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Projection;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use UnexpectedValueException;

/**
 * @psalm-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 */
final class DocMdpReferenceArrayProjection
{
    /**
     * @param array<int,PdfObject> $remaining
     * @param list<string> $timestampRefs
     */
    public function project(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        PdfRevisionObjects $shadow,
        array &$remaining,
        ?string $previous,
        ?string $current,
        ?string $shadowValue,
        array $timestampRefs,
    ): ?string {
        $this->discardArrayChange($before, $after, $remaining, $previous, $current, $timestampRefs);
        if ($timestampRefs === []) {
            return $shadowValue;
        }
        if ($shadowValue !== null && !str_starts_with($shadowValue, '[')) {
            throw new UnexpectedValueException('Unsupported indirect signed timestamp array');
        }
        $refs = $shadow->referenceArray($shadowValue ?? '[]');
        if ($refs === null) {
            throw new UnexpectedValueException('Invalid projected array');
        }

        return '[' . implode(' ', array_merge($refs, $timestampRefs)) . ']';
    }


    /**
     * @param array<int,PdfObject> $remaining
     * @param list<string> $timestampRefs
     */
    private function discardArrayChange(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array &$remaining, ?string $previous, ?string $current, array $timestampRefs): void
    {
        $oldArray = $previous === null ? null : $before->document->resolve($previous);
        $newArray = $current === null ? null : $after->document->resolve($current);
        if ($newArray === null || (!isset($remaining[$newArray['num']]) && ($oldArray['num'] ?? null) === $newArray['num'])) {
            return;
        }
        $number = $newArray['num'];
        if (!$after->hasOnlyRoleReferences($number)
            || (isset($before->document->objects[$number]) && !$before->hasOnlyRoleReferences($number))
            || (($oldArray['num'] ?? null) !== $number && isset($before->document->objects[$number]))) {
            throw new UnexpectedValueException('Shared or repurposed array');
        }
        if ($timestampRefs !== []) {
            throw new UnexpectedValueException('Unsupported indirect timestamp array');
        }
        unset($remaining[$number]);
    }
}
