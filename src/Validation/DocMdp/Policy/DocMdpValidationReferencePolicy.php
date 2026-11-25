<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpValidationOwnership;

/**
 * Validates incoming and outgoing references of isolated validation objects.
 *
 * @psalm-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 */
final class DocMdpValidationReferencePolicy
{
    public function __construct(private readonly PdfReferencePaths $reader = new PdfReferencePaths())
    {
    }

    public function allows(PdfRevisionObjects $live, DocMdpValidationOwnership $roles, int &$budget): bool
    {
        $pageOwners = [];
        foreach ($live->objects as $owner => $object) {
            $budget -= strlen($object['value']);
            if ($budget < 0) {
                return false;
            }
            $paths = $this->reader->read($object['value']);
            if ($paths === null) {
                return false;
            }
            foreach ($paths as $edge) {
                $target = $live->resolve($edge['reference']);
                if ($target === null) {
                    if ($roles->ownsReferenceSource($owner)) {
                        return false;
                    }
                    continue;
                }
                if (!$this->allowsReference($roles, $owner, $object, $target, $edge['path'], $pageOwners)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * @param PdfObject $object
     * @param PdfObject $target
     * @param array<int,int> $pageOwners
     */
    private function allowsReference(DocMdpValidationOwnership $roles, int $owner, array $object, array $target, string $path, array &$pageOwners): bool
    {
        $number = $target['num'];
        if ($number === $roles->info && $number >= $roles->originalSize) {
            return false;
        }
        if (!$this->allowsDssReference($roles, $owner, $number, $path)) {
            return false;
        }
        if (isset($roles->timestamps[$number]) && !$this->allowsTimestampReference($roles, $owner, $object, $target, $path, $pageOwners)) {
            return false;
        }

        return $this->allowsSignatureReference($roles, $owner, $target, $path);
    }

    private function allowsDssReference(DocMdpValidationOwnership $roles, int $owner, int $number, string $path): bool
    {
        if (isset($roles->historicalDss[$number]) && !isset($roles->historicalDss[$owner])) {
            return $owner === $roles->root && $path === '/DSS';
        }

        return !isset($roles->historicalDss[$owner]) || isset($roles->historicalDss[$number]);
    }

    /**
     * @param PdfObject $object
     * @param PdfObject $target
     * @param array<int,int> $pageOwners
     */
    private function allowsTimestampReference(DocMdpValidationOwnership $roles, int $owner, array $object, array $target, string $path, array &$pageOwners): bool
    {
        $fromForm = $owner === $roles->formOwner && $path === $roles->fieldPath;
        $fromPage = ($object['entries']['/Type'] ?? null) === '/Page' && $path === '/Annots[]';
        if (!$fromPage) {
            return $fromForm;
        }
        $number = $target['num'];
        if (isset($pageOwners[$number]) || (isset($target['entries']['/P'])
            && $target['entries']['/P'] !== $owner . ' ' . $object['gen'] . ' R')) {
            return false;
        }
        $pageOwners[$number] = $owner;

        return true;
    }

    /** @param PdfObject $target */
    private function allowsSignatureReference(DocMdpValidationOwnership $roles, int $owner, array $target, string $path): bool
    {
        $number = $target['num'];
        if (isset($roles->values[$number]) && ($owner !== $roles->values[$number] || $path !== '/V')) {
            return false;
        }
        if (isset($roles->timestamps[$owner])
            && (($path !== '/V' || ($roles->values[$number] ?? null) !== $owner) && ($path !== '/P' || ($target['entries']['/Type'] ?? null) !== '/Page'))) {
            return false;
        }

        return !isset($roles->values[$owner]);
    }
}
