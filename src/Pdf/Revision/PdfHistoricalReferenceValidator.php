<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

/** Strict active cross-reference provenance and object generation validation. */
final class PdfHistoricalReferenceValidator
{
    /** @param array<int, ?int> $offsets
     *  @param array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}> $compressedObjects
     */
    public function referenceMatches(string $content, array $offsets, array $compressedObjects, string $reference): bool
    {
        if (!preg_match('/^(\d+) (\d+) R$/', $reference, $match)) {
            return false;
        }
        $number = (int) $match[1];
        $offset = $offsets[$number] ?? null;
        if ($offset === null) {
            return isset($compressedObjects[$number]) && (int) $match[2] === 0;
        }
        $pattern = '/\G' . $match[1] . '\s+' . $match[2] . '\s+obj\b/';

        return preg_match($pattern, $content, $objectHeader, 0, $offset) === 1;
    }

    /** @param array<int,array{int,int,bool}> $entries */
    public function entriesMatchObjectHeaders(string $content, array $entries): bool
    {
        foreach ($entries as $num => [$entryOffset, $generation, $inUse]) {
            if (!$inUse) {
                continue;
            }
            $pattern = '/\G' . $num . '\s+' . $generation . '\s+obj\b/';
            if ($entryOffset >= strlen($content)
                || preg_match($pattern, $content, $objectHeader, 0, $entryOffset) !== 1) {
                return false;
            }
        }

        return true;
    }

}
