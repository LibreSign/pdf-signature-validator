<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * Evaluates each revision against its immediate predecessor.
 */
final class DocMdpRevisionPolicy
{
    private PdfSyntaxReader $syntax;
    private DssChangeRule $dssRule;
    private DocMdpEntryChangePolicy $entries;

    public function __construct(
        ?PdfSyntaxReader $syntax = null,
        ?DssChangeRule $dssRule = null,
        ?DocMdpEntryChangePolicy $entries = null,
    ) {
        $this->syntax = $syntax ?? new PdfSyntaxReader();
        $this->dssRule = $dssRule ?? new DssChangeRule();
        $this->entries = $entries ?? new DocMdpEntryChangePolicy($this->syntax);
    }

    /**
     * @param array<int, array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}> $revision
     */
    public function allowsRevision(
        PdfRevisionSnapshot $document,
        DocMdpRevisionState $state,
        int $revisionIndex,
        array $revision,
    ): bool {
        $hasValidationData = false;
        $timestamps = $state->timestampFieldsAvailableAt($revisionIndex);
        foreach ($revision as $number => $object) {
            if ($number >= $document->signed['size']) {
                if ($state->newObjectRevisions[$number] === $revisionIndex) {
                    continue;
                }
                $status = $this->validateRewrittenNewObject($state, $revisionIndex, $number, $object);
            } else {
                $status = $this->validateRewrittenObject($document, $state, $revisionIndex, $number, $object, $timestamps);
            }
            if ($status === null) {
                return false;
            }
            $hasValidationData = $hasValidationData || $status;
        }

        // A metadata-only revision is not exempt even if DSS appears later.
        return $hasValidationData;
    }

    /**
     * A subsequent LTA renewal may append DSS evidence to a DSS dictionary
     * introduced after certification. Never permit arbitrary new-object
     * rewriting: especially not stream evidence or timestamp dictionaries.
     *
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $object
     * @return bool|null
     */
    private function validateRewrittenNewObject(
        DocMdpRevisionState $state,
        int $revisionIndex,
        int $number,
        array $object,
    ): ?bool {
        $old = $state->currentObjects[$number] ?? $state->newObjects[$number] ?? null;
        if ($old === null || $old['gen'] !== $object['gen']) {
            return null;
        }
        if ($old['value'] === $object['value'] && $old['stream'] === $object['stream']) {
            $state->currentObjects[$number] = $object;
            return false;
        }
        if ($old['stream'] !== null || $object['stream'] !== null
            || $old['entries'] === null || $object['entries'] === null) {
            return null;
        }

        $reference = $number . ' ' . $object['gen'] . ' R';
        if ($state->dssReference === $reference) {
            if (!$this->isAppendOnlyDssChange($old['entries'], $object['entries'])
                || !$this->dssRule->allowsNewDss(
                    $reference,
                    array_replace($state->newObjects, [$number => $object]),
                    $state->newObjectRevisions,
                    $revisionIndex,
                )) {
                return null;
            }
            $state->currentObjects[$number] = $object;
            return true;
        }

        // /Info objects introduced after certification can be rewritten for
        // ancillary producer/date metadata, but never for content metadata.
        if ($this->isAncillaryInfo($old['entries']) && $this->isAncillaryInfo($object['entries'])) {
            $state->currentObjects[$number] = $object;
            return false;
        }

        return null;
    }

    /** @param array<string,string> $entries */
    private function isAncillaryInfo(array $entries): bool
    {
        return $entries !== [] && array_diff(array_keys($entries), ['/ModDate', '/Producer']) === [];
    }

    /** @param array<string,string> $old
     *  @param array<string,string> $new */
    private function isAppendOnlyDssChange(array $old, array $new): bool
    {
        foreach (array_keys($old + $new) as $key) {
            $previous = $old[$key] ?? null;
            $current = $new[$key] ?? null;
            if ($previous === $current) {
                continue;
            }
            if (!in_array($key, ['/Certs', '/CRLs', '/OCSPs'], true)
                || $current === null
                || !preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $previous ?? '[]', $oldRefs)
                || !preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $current, $newRefs)) {
                return false;
            }
            preg_match_all('/\d+ \d+ R/', $oldRefs[1], $before);
            preg_match_all('/\d+ \d+ R/', $newRefs[1], $after);
            if (array_slice($after[0], 0, count($before[0])) !== $before[0]) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $object
     * @param array<string, true> $timestampFields
     * @return bool|null null=violation, true=qualifying validation update,
     *                   false=allowed ancillary change
     */
    private function validateRewrittenObject(
        PdfRevisionSnapshot $document,
        DocMdpRevisionState $state,
        int $revisionIndex,
        int $number,
        array $object,
        array $timestampFields,
    ): ?bool {
        $old = $state->currentObjects[$number] ?? $document->signedObject($number);
        if ($old === null) {
            return null;
        }
        if ($old['value'] === $object['value'] && $old['stream'] === $object['stream']) {
            $state->currentObjects[$number] = $object;
            return false;
        }
        if ($old['stream'] !== null || $object['stream'] !== null
            || $old['entries'] === null || $object['entries'] === null) {
            return null;
        }

        if (!$this->entries->allowsChangedEntries($state, $number, $old['entries'], $object['entries'], $timestampFields)) {
            return null;
        }
        $result = $this->qualifiesAsValidationUpdate($state, $revisionIndex, $number, $old['entries'], $object['entries']);
        if ($result !== null) {
            $state->currentObjects[$number] = $object;
        }

        return $result;
    }

    /** @param array<string,string> $old
     *  @param array<string,string> $new */
    private function qualifiesAsValidationUpdate(
        DocMdpRevisionState $state,
        int $revisionIndex,
        int $number,
        array $old,
        array $new,
    ): ?bool {
        if ($number === $state->rootNumber) {
            return $this->checkCatalogValidationUpdate($state, $revisionIndex, $old, $new);
        }
        if ($number === $state->acroFormNumber) {
            return ($old['/Fields'] ?? null) !== ($new['/Fields'] ?? null);
        }
        if (($old['/Type'] ?? null) === '/Page') {
            return ($old['/Annots'] ?? null) !== ($new['/Annots'] ?? null);
        }

        return false;
    }

    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     */
    private function checkCatalogValidationUpdate(
        DocMdpRevisionState $state,
        int $revisionIndex,
        array $old,
        array $new,
    ): ?bool {
        $dss = $new['/DSS'] ?? null;
        if ($state->dssReference !== null && $dss === null) {
            return null;
        }

        $addsDss = $dss !== null && $dss !== $state->dssReference;
        if ($addsDss && !$this->dssRule->allowsNewDss(
            $dss,
            $state->newObjects,
            $state->newObjectRevisions,
            $revisionIndex,
        )) {
            return null;
        }

        $state->dssReference = $dss;
        $oldForm = $this->syntax->parseDictionaryEntries($old['/AcroForm'] ?? '<<>>');
        $newForm = $this->syntax->parseDictionaryEntries($new['/AcroForm'] ?? '<<>>');
        $addsTimestamp = $oldForm !== null && $newForm !== null
            && ($oldForm['/Fields'] ?? null) !== ($newForm['/Fields'] ?? null);

        return $addsDss || $addsTimestamp;
    }
}
