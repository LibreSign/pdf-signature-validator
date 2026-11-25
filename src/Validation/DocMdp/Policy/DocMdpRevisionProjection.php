<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use UnexpectedValueException;

/**
 * Removes only already-proven form/annotation changes from the revisions.
 * Remaining changes are evaluated by the existing validation-data policy,
 * including when both classes of change occur in the same revision.
 *
 * @psalm-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 */
final class DocMdpRevisionProjection
{
    public function __construct(
        private readonly DocMdpFormProjection $form = new DocMdpFormProjection(),
        private readonly DocMdpPageProjection $pages = new DocMdpPageProjection(),
        private readonly DocMdpInfoProjection $info = new DocMdpInfoProjection(),
    ) {
    }

    /**
     * @param array<int,PdfObject> $updates
     * @param array<int,true> $accepted
     * @param array<int,true> $approvals
     * @param array<int,true> $timestamps
     * @return array<int,PdfObject>|null
     */
    public function project(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        PdfRevisionObjects $shadow,
        array $updates,
        array $accepted,
        array $approvals,
        array $timestamps,
        bool $allowAnnotations,
        ?string $previousInfo,
        ?string $currentInfo,
    ): ?array {
        $remaining = array_diff_key($updates, $accepted);
        try {
            $this->form->project($before, $after, $shadow, $remaining, $approvals, $timestamps);
            $this->pages->project($before, $after, $shadow, $remaining, $approvals, $timestamps, $allowAnnotations);
            $this->info->project($before, $after, $remaining, $previousInfo, $currentInfo);
        } catch (UnexpectedValueException) {
            return null;
        }

        foreach ($remaining as $number => $object) {
            if (isset($shadow->objects[$number]) && PdfRevisionObjects::same($shadow->objects[$number], $object)) {
                unset($remaining[$number]);
            }
        }

        return $remaining;
    }
}
