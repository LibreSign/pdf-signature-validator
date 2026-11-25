<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/**
 * Reads certified PDF and its subsequent incremental revisions strictly.
 * Unsupported xref streams fail closed instead of implying an exemption.
 *
 * @psalm-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @psalm-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string,compressedObjects?:array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>}
 * @phpstan-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @phpstan-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string,compressedObjects?:array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>}
 */
final class PdfIncrementalRevisionReader
{
    private const MAX_REVISIONS = 128;

    private PdfIndirectObjectReader $objects;
    private PdfCrossReferenceReader $xref;
    private PdfRevisionTrailerPolicy $trailers;

    public function __construct(?PdfSyntaxReader $syntax = null, ?PdfRevisionTrailerPolicy $trailers = null)
    {
        $syntax ??= new PdfSyntaxReader();
        $this->objects = new PdfIndirectObjectReader($syntax);
        $this->xref = new PdfCrossReferenceReader($syntax);
        $this->trailers = $trailers ?? new PdfRevisionTrailerPolicy();
    }

    /** @return SignedRevision|null */
    public function readSignedRevision(string $content, int $coveredEnd): ?array
    {
        return $this->xref->readSignedRevision($content, $coveredEnd);
    }

    /**
     * @param SignedRevision $signed
     * @return PdfObject|null
     */
    public function readSignedObject(string $content, array $signed, int $num): ?array
    {
        return $this->objects->readSignedObject($content, $signed, $num);
    }

    /**
     * Parse every incremental update after the certified revision.
     *
     * @param SignedRevision $signed
     * @return list<array<int, PdfObject>>|null Each revision is retained separately
     */
    public function readIncrementalUpdates(string $content, int $coveredEnd, array $signed): ?array
    {
        $history = $this->readIncrementalUpdateHistory($content, $coveredEnd, $signed);
        return $history === null ? null : array_column($history, 'objects');
    }

    /**
     * The exact EOF boundary and the trailing PDF whitespace of each update.
     * @param SignedRevision $signed
     * @return list<array{objects:array<int,PdfObject>,eof:int,end:int,info:?string}>|null
     */
    public function readIncrementalUpdateHistory(string $content, int $coveredEnd, array $signed): ?array
    {
        $pos = $coveredEnd;
        $previousXref = $signed['startxref'];
        $revisions = [];
        $currentInfo = $signed['info'];
        while (true) {
            $pos += strspn($content, "\x00\t\n\x0c\r ", $pos);
            if ($pos >= strlen($content)) {
                return $revisions;
            }
            if (count($revisions) >= self::MAX_REVISIONS) {
                return null;
            }
            $parsed = $this->readRevision($content, $pos, $previousXref, $signed, $currentInfo);
            if ($parsed === null) {
                return null;
            }
            $revisions[] = [
                'objects' => $parsed['objects'],
                'eof' => $pos,
                'end' => $pos + strspn($content, "\x00\t\n\x0c\r ", $pos),
                'info' => $currentInfo,
            ];
            $previousXref = $parsed['xrefOffset'];
        }
    }

    /**
     * @param SignedRevision $signed
     * @return array{objects:array<int,PdfObject>,xrefOffset:int}|null
     */
    private function readRevision(string $content, int &$pos, int $previousXref, array $signed, ?string &$currentInfo): ?array
    {
        $objectsAndOffsets = $this->readRevisionObjects($content, $pos);
        if ($objectsAndOffsets === null) {
            return null;
        }
        [$objects, $offsets] = $objectsAndOffsets;
        $xrefOffset = $pos;
        $xrefIsStream = preg_match('/\G(\d+) 0 obj\b/', $content, $streamHeader, 0, $pos) === 1;
        if ($xrefIsStream) {
            $streamNumber = (int) $streamHeader[1];
            if (isset($offsets[$streamNumber])) {
                return null;
            }
            $offsets[$streamNumber] = [$xrefOffset, 0];
        }
        $xref = $this->xref->readSection($content, $pos);
        if ($xref === null || $xref['compressed'] !== []
            || !$this->xrefMatchesObjects($xref['entries'], $offsets, count($offsets))
            || !$this->trailers->matches($xref['trailer'], $previousXref, $signed, $objects, $currentInfo)) {
            return null;
        }
        $pos = $xref['end'];
        if (!preg_match('/\G\s*startxref\s+(\d+)\s+%%EOF/', $content, $match, 0, $pos)
            || (int) $match[1] !== $xrefOffset) {
            return null;
        }
        $pos += strlen($match[0]);

        return ['objects' => $objects, 'xrefOffset' => $xrefOffset];
    }

    /** @return array{array<int,PdfObject>,array<int,array{int,int}>}|null */
    private function readRevisionObjects(string $content, int &$pos): ?array
    {
        $objects = [];
        $offsets = [];
        while (preg_match('/\G\d+\s+\d+\s+obj\b/', $content, $match, 0, $pos)) {
            $object = $this->objects->read($content, $pos);
            if ($object === null || isset($objects[$object['num']])) {
                return null;
            }
            if (($object['entries']['/Type'] ?? null) === '/XRef') {
                // This object is the xref stream, whose offset must point to
                // itself. It is not a normal document-object modification.
                break;
            }
            $objects[$object['num']] = $object;
            $offsets[$object['num']] = [$pos, $object['gen']];
            $pos = $object['end'];
            $pos += strspn($content, "\x00\t\n\x0c\r ", $pos);
        }

        return [$objects, $offsets];
    }

    /** @param array<int,array{int,int,bool}> $entries
     *  @param array<int,array{int,int}> $offsets */
    private function xrefMatchesObjects(array $entries, array $offsets, int $count): bool
    {
        $listed = 0;
        foreach ($entries as $num => [$offset, $generation, $inUse]) {
            if (!$inUse) {
                if ($num !== 0) {
                    return false;
                }
                continue;
            }
            if (($offsets[$num] ?? null) !== [$offset, $generation]) {
                return false;
            }
            $listed++;
        }

        return $listed === $count;
    }

}
