<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * DocMDP rule for invisible document-timestamp fields and the revision in which
 * the referenced timestamp object became available.
 *
 * @psalm-import-type PdfObject from DocMdpRevisionState
 * @phpstan-import-type PdfObject from DocMdpRevisionState
 */
final class DocumentTimestampRule
{
    /**
     * A document timestamp field: merged field and widget without kids or
     * actions, invisible (zero-area /Rect), whose value is a new
     * /DocTimeStamp dictionary with /SubFilter /ETSI.RFC3161.
     *
     * @param array<string, string> $entries
     * @param array<int, PdfObject> $newObjects
     * @param array<int,int> $newObjectRevisions
     */
    public function allowsTimestampField(
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
        if (!preg_match('/^(\d+) (\d+) R$/', $entries['/V'] ?? '', $match)) {
            return false;
        }
        $valueNumber = (int) $match[1];
        if (($introducedAt[$valueNumber] ?? PHP_INT_MAX) > $currentRevision) {
            return false;
        }
        $object = $newObjects[$valueNumber] ?? null;
        $value = $object['entries'] ?? null;

        return $object !== null
            && $object['gen'] === (int) $match[2]
            && $value !== null
            && ($value['/Type'] ?? null) === '/DocTimeStamp'
            && ($value['/SubFilter'] ?? null) === '/ETSI.RFC3161';
    }
}
