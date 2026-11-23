<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Reads certified PDF and its subsequent incremental revisions strictly.
 * Unsupported xref streams fail closed instead of implying an exemption.
 *
 * @psalm-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @psalm-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string}
 * @phpstan-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @phpstan-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string}
 */
final class PdfIncrementalRevisionReader
{
    private const MAX_REVISIONS = 128;

    private PdfSyntaxReader $syntax;
    private PdfCrossReferenceReader $xref;

    public function __construct(?PdfSyntaxReader $syntax = null)
    {
        $this->syntax = $syntax ?? new PdfSyntaxReader();
        $this->xref = new PdfCrossReferenceReader($this->syntax);
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
        if (!isset($signed['offsets'][$num])) {
            return null;
        }
        $object = $this->readIndirectObject($content, $signed['offsets'][$num]);
        return $object !== null && $object['num'] === $num ? $object : null;
    }

    /**
     * Parse every incremental update after the certified revision.
     *
     * @param SignedRevision $signed
     * @return list<array<int, PdfObject>>|null Each revision is retained separately
     */
    public function readIncrementalUpdates(string $content, int $coveredEnd, array $signed): ?array
    {
        $pos = $coveredEnd;
        $previousXref = $signed['startxref'];
        $revisions = [];
        while (true) {
            $pos += strspn($content, "\x00\t\n\x0c\r ", $pos);
            if ($pos >= strlen($content)) {
                return $revisions;
            }
            if (count($revisions) >= self::MAX_REVISIONS) {
                return null;
            }
            $parsed = $this->readRevision($content, $pos, $previousXref, $signed);
            if ($parsed === null) {
                return null;
            }
            $revisions[] = $parsed['objects'];
            $previousXref = $parsed['xrefOffset'];
        }
    }

    /**
     * @param SignedRevision $signed
     * @return array{objects:array<int,PdfObject>,xrefOffset:int}|null
     */
    private function readRevision(string $content, int &$pos, int $previousXref, array $signed): ?array
    {
        $objectsAndOffsets = $this->readRevisionObjects($content, $pos);
        if ($objectsAndOffsets === null) {
            return null;
        }
        [$objects, $offsets] = $objectsAndOffsets;
        $xrefOffset = $pos;
        $xref = $this->xref->readSection($content, $pos);
        if ($xref === null || !$this->xrefMatchesObjects($xref['entries'], $offsets, count($objects))
            || !$this->trailerMatchesSignedRevision($xref['trailer'], $previousXref, $signed)) {
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
            $object = $this->readIndirectObject($content, $pos);
            if ($object === null || isset($objects[$object['num']])) {
                return null;
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

    /** @param array<string,string> $trailer
     *  @param SignedRevision $signed */
    private function trailerMatchesSignedRevision(array $trailer, int $previousXref, array $signed): bool
    {
        return ($trailer['/Prev'] ?? null) === (string) $previousXref
            && ($trailer['/Root'] ?? null) === $signed['root']
            && ($trailer['/Info'] ?? $signed['info']) === $signed['info']
            && !isset($trailer['/Encrypt']) && !isset($trailer['/XRefStm']);
    }

    /** @return PdfObject|null */
    private function readIndirectObject(string $content, int $pos): ?array
    {
        if (!preg_match('/\G(\d+)\s+(\d+)\s+obj\b/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);
        $this->syntax->skipPdfWhitespace($content, $pos);
        $entries = null;
        $value = null;
        if (substr($content, $pos, 2) === '<<') {
            $valueStart = $pos;
            $entries = $this->syntax->readPdfDictionary($content, $pos, 0);
            $value = $entries === null ? null : $this->syntax->readPdfValue($content, $valueStart, 0);
        }
        if ($entries === null) {
            $value = $this->syntax->readPdfValue($content, $pos, 0);
        }
        if ($value === null) {
            return null;
        }
        $stream = $this->readObjectStream($content, $pos, $entries);
        if ($stream === false || !preg_match('/\G\s*endobj\b/', $content, $end, 0, $pos)) {
            return null;
        }

        return [
            'num' => (int) $match[1], 'gen' => (int) $match[2],
            'value' => $value, 'entries' => $entries, 'stream' => $stream,
            'end' => $pos + strlen($end[0]),
        ];
    }

    /** @param array<string,string>|null $entries
     *  @return string|false|null false means invalid stream, null means no stream */
    private function readObjectStream(string $content, int &$pos, ?array $entries): string|false|null
    {
        if (!preg_match('/\G\s*stream(?:\r\n|\n)/', $content, $start, 0, $pos)) {
            return null;
        }
        $length = $entries['/Length'] ?? '';
        if (!ctype_digit($length)) {
            return false;
        }
        $pos += strlen($start[0]);
        $stream = substr($content, $pos, (int) $length);
        $pos += (int) $length;
        if (strlen($stream) !== (int) $length
            || !preg_match('/\G\s*endstream\b/', $content, $end, 0, $pos)) {
            return false;
        }
        $pos += strlen($end[0]);

        return $stream;
    }

}
