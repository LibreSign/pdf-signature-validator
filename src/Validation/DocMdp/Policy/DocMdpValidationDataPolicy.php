<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * DocMDP policy for structural validation-data exceptions, independent from
 * the PDF revision parser and from the application's business rules.
 */
final class DocMdpValidationDataPolicy
{
    private DocMdpNewObjectPolicy $newObjects;
    private DocMdpRevisionPolicy $revisions;

    public function __construct(
        ?DocMdpNewObjectPolicy $newObjects = null,
        ?DocMdpRevisionPolicy $revisions = null,
    ) {
        $this->newObjects = $newObjects ?? new DocMdpNewObjectPolicy();
        $this->revisions = $revisions ?? new DocMdpRevisionPolicy(newObjects: $this->newObjects);
    }

    public function allows(PdfRevisionSnapshot $document): bool
    {
        $state = $this->createState($document);
        if (!$state instanceof \LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState || !$this->newObjects->indexNewObjects($document, $state)
            || !$this->newObjects->validateNewObjects($state)) {
            return false;
        }

        foreach ($document->revisions as $revisionIndex => $revision) {
            if (!$this->revisions->allowsRevision($document, $state, $revisionIndex, $revision)) {
                return false;
            }
        }

        return true;
    }

    private function createState(PdfRevisionSnapshot $document): ?DocMdpRevisionState
    {
        if (!preg_match('/^(\d+) \d+ R$/', $document->signed['root'], $rootMatch)) {
            return null;
        }
        $rootNumber = (int) $rootMatch[1];
        $catalog = $document->signedObject($rootNumber);
        if ($catalog === null || $catalog['entries'] === null) {
            return null;
        }
        $entries = $catalog['entries'];
        $acroFormRef = $entries['/AcroForm'] ?? '';
        $acroForm = preg_match('/^(\d+) \d+ R$/', $acroFormRef, $acroFormMatch)
            ? (int) $acroFormMatch[1] : null;
        $info = $document->signed['info'] === null ? null : (int) $document->signed['info'];

        return new DocMdpRevisionState($rootNumber, $acroForm, $info, $entries['/DSS'] ?? null);
    }

}
