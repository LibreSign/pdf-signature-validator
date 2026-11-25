<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy\DocMdpValidationDataPolicy;

/**
 * Facade for the DocMDP exemption covering DSS and document timestamps.
 *
 * The result is a structural classification, not cryptographic validation.
 * A false result must never override regular DocMDP validation.
 */
final class DocMdpValidationDataInspector
{
    private PdfIncrementalRevisionReader $reader;
    private DocMdpValidationDataPolicy $policy;

    public function __construct(
        ?PdfIncrementalRevisionReader $reader = null,
        ?DocMdpValidationDataPolicy $policy = null,
    ) {
        $this->reader = $reader ?? new PdfIncrementalRevisionReader();
        $this->policy = $policy ?? new DocMdpValidationDataPolicy();
    }

    public function hasOnlyValidationDataUpdates(string $content, int $certifiedEnd): bool
    {
        if ($certifiedEnd <= 0 || $certifiedEnd >= strlen($content)) {
            return false;
        }

        $signed = $this->reader->readSignedRevision($content, $certifiedEnd);
        if ($signed === null) {
            return false;
        }
        $history = $this->reader->readIncrementalUpdateHistory($content, $certifiedEnd, $signed);
        if ($history === null || $history === []) {
            return false;
        }

        return $this->policy->allows(new PdfRevisionSnapshot(
            substr($content, 0, $certifiedEnd),
            $signed,
            array_column($history, 'objects'),
            $this->reader,
            array_column($history, 'info'),
        ));
    }
}
