<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * DocMDP rule for a newly referenced document security store (DSS).
 * It is intentionally structural and does not validate embedded OCSP/CRL data.
 *
 * @psalm-import-type PdfObject from DocMdpRevisionState
 * @phpstan-import-type PdfObject from DocMdpRevisionState
 */
final class DssChangeRule
{
    /**
     * A newly added DSS must actually reference a DSS dictionary. Allowing
     * arbitrary /Version changes or an unreferenced object is not enough.
     *
     * @param array<int, PdfObject> $newObjects
     * @param array<int,int> $newObjectRevisions
     */
    public function allowsNewDss(string $reference, array $newObjects, array $newObjectRevisions, int $revisionIndex): bool
    {
        if (!preg_match('/^(\d+) (\d+) R$/', $reference, $match)) {
            return false;
        }
        $dssNumber = (int) $match[1];
        if (($newObjectRevisions[$dssNumber] ?? PHP_INT_MAX) > $revisionIndex
            || ($newObjects[$dssNumber]['gen'] ?? -1) !== (int) $match[2]) {
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
        return $this->hasValidStreamReferences($dss, $newObjects, $newObjectRevisions, $revisionIndex);
    }

    /**
     * Certificate and revocation material in a DSS must be arrays of
     * indirect references to PDF stream objects, not plain hex literals.
     *
     * @param array<string,string> $dss
     * @param array<int,PdfObject> $newObjects
     * @param array<int,int> $introducedAt
     */
    private function hasValidStreamReferences(
        array $dss,
        array $newObjects,
        array $introducedAt,
        int $revisionIndex,
    ): bool {
        $found = false;
        foreach (['/Certs', '/CRLs', '/OCSPs'] as $key) {
            if (!isset($dss[$key])) {
                continue;
            }
            if (!preg_match('/^\\[((?:\\d+ \\d+ R ?)*)\\]$/', $dss[$key], $array)) {
                return false;
            }
            preg_match_all('/(\\d+) (\\d+) R/', $array[1], $references, PREG_SET_ORDER);
            foreach ($references as $reference) {
                if (!$this->isExistingStream($reference, $newObjects, $introducedAt, $revisionIndex)) {
                    return false;
                }
                $found = true;
            }
        }

        // VRI-only updates cannot prove an LTV exception until VRI
        // substructure validation is implemented. Reject rather than treating
        // the mere presence of /VRI as trustworthy evidence.
        return $found;
    }

    /**
     * @param array<array-key,string> $reference
     * @param array<int,PdfObject> $newObjects
     * @param array<int,int> $introducedAt
     */
    private function isExistingStream(
        array $reference,
        array $newObjects,
        array $introducedAt,
        int $revisionIndex,
    ): bool {
        $number = (int) $reference[1];
        $generation = (int) $reference[2];
        $object = $newObjects[$number] ?? null;

        return $object !== null
            && $object['gen'] === $generation
            && $object['stream'] !== null
            && ($introducedAt[$number] ?? PHP_INT_MAX) <= $revisionIndex;
    }
}
