<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionSnapshot;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * Checks newly introduced objects and delegates timestamp-field rules.
 *
 * @psalm-import-type PdfObject from DocMdpRevisionState
 * @phpstan-import-type PdfObject from DocMdpRevisionState
 */
final class DocMdpNewObjectPolicy
{
    private DocumentTimestampRule $timestampRule;

    public function __construct(?DocumentTimestampRule $timestampRule = null)
    {
        $this->timestampRule = $timestampRule ?? new DocumentTimestampRule();
    }

    public function indexNewObjects(PdfRevisionSnapshot $document, DocMdpRevisionState $state): bool
    {
        foreach ($document->revisions as $revisionIndex => $revision) {
            foreach ($revision as $number => $object) {
                if ($number < $document->signed['size']) {
                    continue;
                }
                if (isset($state->newObjects[$number])) {
                    // A later revision may rewrite validation data, but each
                    // rewrite must be checked against its immediate predecessor.
                    continue;
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
                if (!$this->timestampRule->allowsTimestampField(
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
}
