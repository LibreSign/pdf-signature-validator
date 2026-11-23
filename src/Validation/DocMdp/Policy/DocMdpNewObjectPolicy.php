<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * Checks newly introduced objects and timestamp/DSS semantics.
 *
 * @psalm-import-type PdfObject from DocMdpRevisionState
 * @phpstan-import-type PdfObject from DocMdpRevisionState
 */
final class DocMdpNewObjectPolicy
{
    public function indexNewObjects(PdfRevisionSnapshot $document, DocMdpRevisionState $state): bool
    {
        foreach ($document->revisions as $revisionIndex => $revision) {
            foreach ($revision as $number => $object) {
                if ($number < $document->signed['size']) {
                    continue;
                }
                if (isset($state->newObjects[$number])) {
                    return false;
                }
                $state->newObjects[$number] = $object;
                $state->newObjectRevisions[$number] = $revisionIndex;
            }
        }

        return true;
    }

    public function validateNewObjects(DocMdpRevisionState $state): bool
    {
        foreach ($state->newObjects as $number => $object) {
            $entries = $object['entries'];
            if ($entries === null) {
                continue;
            }
            if (!$this->allowsNewObjectType($entries)) {
                return false;
            }
            if (isset($entries['/FT'])) {
                if (!$this->isTimestampField(
                    $entries,
                    $state->newObjects,
                    $state->newObjectRevisions,
                    $state->newObjectRevisions[$number],
                )) {
                    return false;
                }
                $state->timestampFieldRevisions[$number . ' 0 R'] = $state->newObjectRevisions[$number];
            }
        }

        return true;
    }

    /** @param array<string, string> $entries */
    private function allowsNewObjectType(array $entries): bool
    {
        $type = $entries['/Type'] ?? null;
        if (in_array($type, ['/Sig', '/ObjStm', '/XRef'], true)
            || (isset($entries['/ByteRange']) && $type !== '/DocTimeStamp')) {
            return false;
        }
        if ($type === '/DocTimeStamp' && (($entries['/SubFilter'] ?? null) !== '/ETSI.RFC3161'
            || !isset($entries['/ByteRange'], $entries['/Contents']))) {
            return false;
        }
        if (isset($entries['/FT'])) {
            return true;
        }

        return $type !== '/Annot' && ($entries['/Subtype'] ?? null) !== '/Widget';
    }

    /**
     * A newly added DSS must actually reference a DSS dictionary. Allowing
     * arbitrary /Version changes or an unreferenced object is not enough.
     *
     * @param array<int, PdfObject> $newObjects
     * @param array<int,int> $newObjectRevisions
     */
    public function isNewDssDictionary(string $reference, array $newObjects, array $newObjectRevisions, int $revisionIndex): bool
    {
        if (!preg_match('/^(\d+) \d+ R$/', $reference, $match)) {
            return false;
        }
        $dssNumber = (int) $match[1];
        if (($newObjectRevisions[$dssNumber] ?? PHP_INT_MAX) > $revisionIndex) {
            return false;
        }
        $dss = $newObjects[$dssNumber]['entries'] ?? null;
        if ($dss === null || ($dss['/Type'] ?? '/DSS') !== '/DSS') {
            return false;
        }
        foreach (array_keys($dss) as $key) {
            if (!in_array($key, ['/Type', '/VRI', '/Certs', '/CRLs', '/OCSPs'], true)) {
                return false;
            }
        }
        return isset($dss['/VRI']) || isset($dss['/Certs']) || isset($dss['/CRLs']) || isset($dss['/OCSPs']);
    }

    /**
     * A document timestamp field: merged field and widget without kids or
     * actions, invisible (zero-area /Rect), whose value is a new
     * /DocTimeStamp dictionary with /SubFilter /ETSI.RFC3161.
     *
     * @param array<string, string> $entries
     * @param array<int, PdfObject> $newObjects
     * @param array<int,int> $newObjectRevisions
     */
    private function isTimestampField(
        array $entries,
        array $newObjects,
        array $newObjectRevisions,
        int $currentRevision,
    ): bool {
        return $this->isInvisibleTimestampWidget($entries)
            && $this->referencesExistingDocumentTimestamp(
                $entries,
                $newObjects,
                $newObjectRevisions,
                $currentRevision,
            );
    }

    /** @param array<string,string> $entries */
    private function isInvisibleTimestampWidget(array $entries): bool
    {
        if (($entries['/FT'] ?? null) !== '/Sig'
            || isset($entries['/Kids']) || isset($entries['/Parent'])
            || isset($entries['/A']) || isset($entries['/AA'])
            || ($entries['/Type'] ?? '/Annot') !== '/Annot'
            || ($entries['/Subtype'] ?? '/Widget') !== '/Widget') {
            return false;
        }

        $rect = $entries['/Rect'] ?? null;
        $number = '(-?(?:\d+\.?\d*|\.\d+))';
        if ($rect === null || preg_match("/^\\[{$number} {$number} {$number} {$number}\\]$/", $rect, $corners) !== 1) {
            return false;
        }

        return abs(((float) $corners[3] - (float) $corners[1]) * ((float) $corners[4] - (float) $corners[2])) === 0.0;
    }

    /**
     * @param array<string,string> $entries
     * @param array<int,PdfObject> $newObjects
     * @param array<int,int> $introducedAt
     */
    private function referencesExistingDocumentTimestamp(
        array $entries,
        array $newObjects,
        array $introducedAt,
        int $currentRevision,
    ): bool {
        if (!preg_match('/^(\d+) \d+ R$/', $entries['/V'] ?? '', $match)) {
            return false;
        }
        $valueNumber = (int) $match[1];
        if (($introducedAt[$valueNumber] ?? PHP_INT_MAX) > $currentRevision) {
            return false;
        }
        $value = $newObjects[$valueNumber]['entries'] ?? null;

        return $value !== null
            && ($value['/Type'] ?? null) === '/DocTimeStamp'
            && ($value['/SubFilter'] ?? null) === '/ETSI.RFC3161';
    }
}
