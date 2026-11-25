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
final class DocMdpPageProjection
{
    public function __construct(
        private readonly DocMdpReferenceArrayProjection $arrays = new DocMdpReferenceArrayProjection(),
        private readonly DocMdpProjectedDictionary $dictionary = new DocMdpProjectedDictionary(),
    ) {
    }

    /**
     * @param array<int,PdfObject> $remaining
     * @param array<int,true> $approvals
     * @param array<int,true> $timestamps
     */
    public function project(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        PdfRevisionObjects $shadow,
        array &$remaining,
        array $approvals,
        array $timestamps,
        bool $allowAnnotations,
    ): void {
        if (array_keys($before->pages) !== array_keys($after->pages)) {
            throw new UnexpectedValueException('Unproven page-tree modification');
        }
        foreach ($after->pages as $number => $page) {
            $oldPage = $before->pages[$number];
            $timestampRefs = $this->timestampAnnotations($before, $after, $oldPage['annotations'], $page['annotations'], $approvals, $timestamps, $allowAnnotations);
            $projected = $this->arrays->project(
                $before,
                $after,
                $shadow,
                $remaining,
                $oldPage['entries']['/Annots'] ?? null,
                $page['entries']['/Annots'] ?? null,
                $shadow->objects[$number]['entries']['/Annots'] ?? null,
                $timestampRefs,
            );
            if (isset($remaining[$number])) {
                $entries = $remaining[$number]['entries'] ?? [];
                $this->dictionary->setEntry($entries, '/Annots', $projected);
                $remaining[$number] = $this->dictionary->withEntries($remaining[$number], $entries);
            }
        }
    }


    /**
     * @param list<string> $previous
     * @param list<string> $current
     * @param array<int,true> $approvals
     * @param array<int,true> $timestamps
     * @return list<string>
     */
    private function timestampAnnotations(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array $previous, array $current, array $approvals, array $timestamps, bool $allowAnnotations): array
    {
        if (!$allowAnnotations && array_slice($current, 0, count($previous)) !== $previous) {
            throw new UnexpectedValueException('Annotation change at P=2');
        }
        $removed = array_diff($previous, $current);
        foreach ($removed as $ref) {
            if (!$allowAnnotations || isset($before->fields[(int) $ref])) {
                throw new UnexpectedValueException('Signature widget removal');
            }
        }

        $timestampRefs = [];
        foreach (array_diff($current, $previous) as $ref) {
            $annotation = (int) $ref;
            if (isset($after->fields[$annotation])) {
                if (isset($timestamps[$annotation])) {
                    $timestampRefs[] = $ref;
                } elseif (!isset($approvals[$annotation])) {
                    throw new UnexpectedValueException('Unapproved widget addition');
                }
            } elseif (!$allowAnnotations) {
                throw new UnexpectedValueException('Annotation addition at P=2');
            }
        }
        // P=3 may change the ordering of annotations but not that of
        // existing form widgets and their certified appearances.
        $oldWidgets = array_values(array_filter($previous, static fn (string $ref): bool => isset($before->fields[(int) $ref])));
        $newWidgets = array_values(array_filter($current, static fn (string $ref): bool => isset($before->fields[(int) $ref])));
        if ($oldWidgets !== $newWidgets) {
            throw new UnexpectedValueException('Existing widget reordering');
        }

        return $timestampRefs;
    }
}
