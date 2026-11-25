<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpValidationOwnership;

/** Ensures that all new objects belong to a valid, isolated validation role. */
final class DocMdpValidationOwnershipPolicy
{
    public function __construct(
        private readonly DocMdpDssOwnershipReader $dssReader = new DocMdpDssOwnershipReader(),
        private readonly DocMdpTimestampOwnershipReader $timestampReader = new DocMdpTimestampOwnershipReader(),
        private readonly DocMdpValidationReferencePolicy $references = new DocMdpValidationReferencePolicy(),
    ) {
    }

    public function allows(PdfRevisionSnapshot $document, DocMdpRevisionState $state): bool
    {
        $live = $document->signedObjects();
        if (!$live instanceof \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects) {
            return false;
        }
        $budget = 536_870_912;
        $historicalDss = [];
        foreach ($document->revisions as $index => $revision) {
            $live = $live->apply($revision);
            if (!$live instanceof \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects) {
                return false;
            }
            $roles = $this->readRoles($live, $document, $state, $index, $historicalDss);
            if (!$roles instanceof \LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpValidationOwnership || !$this->ownsAllObjects(array_keys($revision), $roles)
                || !$this->references->allows($live, $roles, $budget)) {
                return false;
            }
            $historicalDss = $roles->historicalDss;
        }

        return true;
    }

    /**
     * @param array<int,true> $historicalDss
     */
    private function readRoles(PdfRevisionObjects $live, PdfRevisionSnapshot $document, DocMdpRevisionState $state, int $index, array $historicalDss): ?DocMdpValidationOwnership
    {
        $catalog = $live->objects[$state->rootNumber]['entries'] ?? null;
        if ($catalog === null) {
            return null;
        }
        $dss = $this->dssReader->read($live, $catalog['/DSS'] ?? null, new PdfReferencePaths());
        $timestamps = $this->timestampReader->read($live, $state->rootNumber, $catalog['/AcroForm'] ?? '<<>>', $state->timestampFieldsAvailableAt($index));
        if ($dss === null || $timestamps === null) {
            return null;
        }
        $infoRef = $document->revisionInfo[$index] ?? $document->signed['info'];
        $info = $infoRef === null ? null : ($live->resolve($infoRef)['num'] ?? null);

        // Superseded VRI records can retain existing evidence references, but
        // cannot authorize new objects and must remain isolated.
        return new DocMdpValidationOwnership(
            $state->rootNumber,
            $document->signed['size'],
            $dss,
            $historicalDss + $dss,
            $timestamps['owner'],
            $timestamps['path'],
            $timestamps['timestamps'],
            $timestamps['values'],
            $info,
        );
    }

    /** @param list<int> $numbers */
    private function ownsAllObjects(array $numbers, DocMdpValidationOwnership $roles): bool
    {
        foreach ($numbers as $number) {
            if (!$roles->containsNewObject($number)) {
                return false;
            }
        }

        return true;
    }
}
