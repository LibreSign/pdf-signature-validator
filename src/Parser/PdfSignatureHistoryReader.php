<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
use LibreSign\PdfSignatureValidator\Model\PdfSignatureHistory;
use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionBoundaryReader;

/**
 * Resolve the certification in the revision in which it was actually active.
 * Absence from the final catalog/field tree is not proof of no certification.
 */
final class PdfSignatureHistoryReader
{
    private const MAX_TOTAL_PREFIX_BYTES = 536_870_912;

    public function __construct(
        private readonly PdfSignatureInventoryReader $inventory = new PdfSignatureInventoryReader(),
        private readonly PdfRevisionBoundaryReader $xref = new PdfRevisionBoundaryReader(),
    ) {
    }

    public function readFromString(string $content): PdfSignatureHistory
    {
        $current = $this->inventory->readFromString($content);
        $boundaries = $this->xref->read($content);
        if ($boundaries === null) {
            return new PdfSignatureHistory(false, $current, $this->certification($current), $current->docMdpPermission);
        }

        $certification = null;
        $permission = null;
        $conclusive = $current->isConclusive;
        $previousApproval = false;
        $totalBytes = 0;
        $knownBoundaries = [];
        foreach ($boundaries as $boundary) {
            $totalBytes += $boundary['end'];
            if ($totalBytes > self::MAX_TOTAL_PREFIX_BYTES) {
                return new PdfSignatureHistory(false, $current, $certification, $permission);
            }
            $knownBoundaries[] = $boundary;
            $inventory = $boundary['end'] === strlen($content)
                ? $current
                : $this->inventory->readFromString(substr($content, 0, $boundary['end']));
            if (!$inventory->isConclusive) {
                $conclusive = false;
                continue;
            }

            $conclusive = $this->matchesKnownRevisions($inventory, $knownBoundaries) && $conclusive;
            $activeCertification = $this->certification($inventory);
            $previousCertification = $certification;
            if ($previousCertification instanceof ActiveSignature) {
                $conclusive = $this->sameCertification($previousCertification, $activeCertification)
                    && $inventory->docMdpPermission === $permission && $conclusive;
            }
            if (!$previousCertification instanceof ActiveSignature && $activeCertification instanceof ActiveSignature) {
                $certification = $activeCertification;
                $permission = $inventory->docMdpPermission;
                $conclusive = !$previousApproval
                    && $this->coversKnownRevision($activeCertification, [$boundary]) && $conclusive;
            }

            $previousApproval = $previousApproval || $this->hasApproval($inventory);
        }

        return new PdfSignatureHistory($conclusive, $current, $certification, $permission);
    }

    /** @param list<array{eof:int,end:int,xref:int}> $boundaries */
    private function matchesKnownRevisions(SignatureInventory $inventory, array $boundaries): bool
    {
        foreach ($inventory->activeSignatures as $signature) {
            if (!$this->coversKnownRevision($signature, $boundaries)) {
                return false;
            }
        }

        return true;
    }

    private function sameCertification(ActiveSignature $original, ?ActiveSignature $current): bool
    {
        return $current instanceof \LibreSign\PdfSignatureValidator\Model\ActiveSignature && $current->objectNumber === $original->objectNumber
            && $current->byteRanges === $original->byteRanges;
    }

    private function hasApproval(SignatureInventory $inventory): bool
    {
        foreach ($inventory->activeSignatures as $signature) {
            if (!$signature->isCertifying) {
                return true;
            }
        }

        return false;
    }

    private function certification(SignatureInventory $inventory): ?ActiveSignature
    {
        foreach ($inventory->activeSignatures as $signature) {
            if ($signature->isCertifying) {
                return $signature;
            }
        }
        return null;
    }

    /** @param list<array{eof:int,end:int,xref:int}> $boundaries */
    private function coversKnownRevision(ActiveSignature $signature, array $boundaries): bool
    {
        foreach ($boundaries as $boundary) {
            if ($signature->signedRevisionEnd >= $boundary['eof'] && $signature->signedRevisionEnd <= $boundary['end']) {
                return true;
            }
        }
        return false;
    }
}
