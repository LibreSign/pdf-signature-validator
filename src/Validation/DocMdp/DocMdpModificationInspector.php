<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy\DocMdpValidationDataPolicy;

/**
 * Structural authorization of post-certification modifications.
 *
 * A positive result requires an active certification in its original
 * revision, and every following revision must be accounted for. Unsupported
 * structure or an unclassified change never implies permission. This is not
 * a CMS signature or certificate-trust validation.
 *
 * @psalm-import-type PdfObject from PdfIncrementalRevisionReader
 * @psalm-import-type SignedRevision from PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from PdfIncrementalRevisionReader
 * @phpstan-import-type SignedRevision from PdfIncrementalRevisionReader
 */
final class DocMdpModificationInspector
{
    public function __construct(
        private readonly PdfIncrementalRevisionReader $reader = new PdfIncrementalRevisionReader(),
        private readonly PdfSignatureInventoryReader $inventory = new PdfSignatureInventoryReader(),
        private readonly DocMdpValidationDataPolicy $validationData = new DocMdpValidationDataPolicy(),
    ) {
    }

    public function allows(string $content, int $certifiedEnd, DocMdpPermission $permission): bool
    {
        if ($certifiedEnd <= 0 || $certifiedEnd >= strlen($content)) {
            return false;
        }
        $signedContent = substr($content, 0, $certifiedEnd);
        $signedInventory = $this->inventory->readFromString($signedContent);
        $certification = $this->certification($signedInventory, $certifiedEnd, $permission);
        if (!$certification instanceof \LibreSign\PdfSignatureValidator\Model\ActiveSignature) {
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

        $inventories = $this->verifiedInventories($content, $certification, $permission, $history);
        if ($inventories === null) {
            return false;
        }

        return $this->allowsVerifiedChanges($signedContent, $signed, $history, $inventories, $permission);
    }

    /**
     * @param SignedRevision $signed
     * @param list<array{objects:array<int,PdfObject>,eof:int,end:int,info:?string}> $history
     * @param list<SignatureInventory> $inventories
     */
    private function allowsVerifiedChanges(string $signedContent, array $signed, array $history, array $inventories, DocMdpPermission $permission): bool
    {
        $revisions = array_column($history, 'objects');
        if ($this->validationData->allows(new PdfRevisionSnapshot($signedContent, $signed, $revisions, $this->reader, array_column($history, 'info')))) {
            return true;
        }
        if ($permission === DocMdpPermission::NO_CHANGES) {
            return false;
        }

        return $this->allowsProjectedChanges($signedContent, $signed, $history, $inventories, $permission);
    }

    /**
     * Check the certification in every actual revision, not only in the final catalog.
     *
     * @param list<array{objects:array<int,PdfObject>,eof:int,end:int,info:?string}> $history
     * @return list<SignatureInventory>|null
     */
    private function verifiedInventories(string $content, ActiveSignature $certification, DocMdpPermission $permission, array $history): ?array
    {
        $inventories = [];
        $totalPrefixBytes = $certification->signedRevisionEnd;
        foreach ($history as $revision) {
            $totalPrefixBytes += $revision['end'];
            if ($totalPrefixBytes > 536_870_912) {
                return null;
            }
            $inventory = $this->inventory->readFromString(substr($content, 0, $revision['end']));
            $current = $this->certification($inventory, $certification->signedRevisionEnd, $permission);
            if (!$current instanceof \LibreSign\PdfSignatureValidator\Model\ActiveSignature || $current->objectNumber !== $certification->objectNumber
                || $current->byteRanges !== $certification->byteRanges) {
                return null;
            }
            $inventories[] = $inventory;
        }

        return $inventories;
    }

    /**
     * @param SignedRevision $signed
     * @param list<array{objects:array<int,PdfObject>,eof:int,end:int,info:?string}> $history
     * @param list<SignatureInventory> $inventories
     */
    private function allowsProjectedChanges(string $signedContent, array $signed, array $history, array $inventories, DocMdpPermission $permission): bool
    {
        $original = PdfRevisionObjects::fromSigned($signedContent, $signed, $this->reader);
        if (!$original instanceof \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects) {
            return false;
        }
        $before = DocMdpDocumentGraph::read($original, $signed['root']);
        if (!$before instanceof \LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph) {
            return false;
        }
        $shadow = $original;
        $validationRevisions = [];
        $previousInfo = $signed['info'];
        $inspector = new DocMdpRevisionChangeInspector();
        $allowAnnotations = $permission === DocMdpPermission::FORM_FILLING_AND_ANNOTATIONS;

        foreach ($history as $index => $revision) {
            $change = $inspector->inspect($before, $shadow, $signed['root'], $revision, $inventories[$index], $allowAnnotations, $previousInfo);
            if ($change === null) {
                return false;
            }
            if ($change['remaining'] !== []) {
                $validationRevisions[] = $change['remaining'];
                $shadow = $shadow->apply($change['remaining']);
                if (!$shadow instanceof \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects) {
                    return false;
                }
            }
            $previousInfo = $revision['info'];
            $before = $change['after'];
        }

        return $validationRevisions === [] || $this->validationData->allows(
            new PdfRevisionSnapshot($signedContent, $signed, $validationRevisions, $this->reader),
        );
    }

    private function certification(SignatureInventory $inventory, int $certifiedEnd, DocMdpPermission $permission): ?ActiveSignature
    {
        if (!$inventory->isConclusive || $inventory->docMdpPermission !== $permission) {
            return null;
        }
        foreach ($inventory->activeSignatures as $signature) {
            if ($signature->isCertifying && $signature->signedRevisionEnd === $certifiedEnd) {
                return $signature;
            }
        }
        return null;
    }
}
