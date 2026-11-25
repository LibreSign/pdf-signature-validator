<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;

/**
 * Identifies the authorized changes in one incremental revision and projects
 * the remaining validation-data changes without mutating the signed snapshot.
 *
 * @psalm-import-type PdfObject from PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from PdfIncrementalRevisionReader
 */
final class DocMdpRevisionChangeInspector
{
    public function __construct(
        private readonly DocMdpFormChangePolicy $forms = new DocMdpFormChangePolicy(),
        private readonly DocMdpAnnotationChangePolicy $annotations = new DocMdpAnnotationChangePolicy(),
        private readonly DocMdpAppearancePolicy $appearances = new DocMdpAppearancePolicy(),
        private readonly DocMdpRevisionProjection $projection = new DocMdpRevisionProjection(),
    ) {
    }

    /**
     * @param array{objects:array<int,PdfObject>,eof:int,end:int,info:?string} $revision
     * @return array{after:DocMdpDocumentGraph,remaining:array<int,PdfObject>}|null
     */
    public function inspect(DocMdpDocumentGraph $before, PdfRevisionObjects $shadow, string $root, array $revision, SignatureInventory $inventory, bool $allowAnnotations, ?string $previousInfo): ?array
    {
        $objects = $before->document->apply($revision['objects']);
        if (!$objects instanceof \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects) {
            return null;
        }
        $after = DocMdpDocumentGraph::read($objects, $root);
        if (!$after instanceof \LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph) {
            return null;
        }
        $fieldChanges = $this->forms->inspect($before, $after, $inventory, $revision['eof'], $revision['end']);
        $annotationChanges = $this->annotations->inspect($before, $after, $allowAnnotations);
        if ($fieldChanges === null || $annotationChanges === null) {
            return null;
        }
        $appearanceChanges = $this->appearanceChanges(
            $before,
            $after,
            $revision['objects'],
            $fieldChanges['oldAppearances'] + $annotationChanges['oldAppearances'],
            $fieldChanges['newAppearances'] + $annotationChanges['newAppearances'],
        );
        if ($appearanceChanges === null) {
            return null;
        }
        $accepted = $fieldChanges['accepted'] + $annotationChanges['accepted'] + $appearanceChanges;
        $remaining = $this->projection->project(
            $before,
            $after,
            $shadow,
            $revision['objects'],
            $accepted,
            $fieldChanges['approvals'],
            $fieldChanges['timestamps'],
            $allowAnnotations,
            $previousInfo,
            $revision['info'],
        );
        if ($remaining === null || ($remaining === [] && $accepted === [] && !$this->hasAnnotationListChange($before, $after))) {
            return null;
        }

        return ['after' => $after, 'remaining' => $remaining];
    }

    /**
     * @param array<int,PdfObject> $objects
     * @param array<int,true> $oldRoots
     * @param array<int,true> $newRoots
     * @return array<int,true>|null
     */
    private function appearanceChanges(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array $objects, array $oldRoots, array $newRoots): ?array
    {
        $old = $this->appearances->inspect($before, $oldRoots);
        $new = $this->appearances->inspect($after, $newRoots);
        if ($old === null || $new === null) {
            return null;
        }
        $accepted = [];
        foreach ($objects as $number => $object) {
            $original = $before->document->objects[$number] ?? null;
            if ($original !== null && PdfRevisionObjects::same($original, $object)) {
                continue;
            }
            if (!isset($old['reachable'][$number]) && !isset($new['reachable'][$number])) {
                continue;
            }
            if (!isset($new['exclusive'][$number]) || ($original !== null && !isset($old['exclusive'][$number]))) {
                return null;
            }
            $accepted[$number] = true;
        }

        return $accepted;
    }

    private function hasAnnotationListChange(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after): bool
    {
        foreach ($after->pages as $number => $page) {
            if ($page['annotations'] !== $before->pages[$number]['annotations']) {
                return true;
            }
        }

        return false;
    }
}
