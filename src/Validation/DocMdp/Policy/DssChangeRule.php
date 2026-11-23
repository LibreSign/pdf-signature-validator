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
}
