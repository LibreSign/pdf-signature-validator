<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Reads classic PDF xref sections and the chain of a certified revision.
 *
 * @psalm-type SignedRevision = array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string}
 * @phpstan-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string}
 * @psalm-type XrefSection = array{entries:array<int,array{int,int,bool}>,trailer:array<string,string>,end:int}
 * @phpstan-type XrefSection array{entries:array<int,array{int,int,bool}>,trailer:array<string,string>,end:int}
 */
final class PdfCrossReferenceReader
{
    private PdfSyntaxReader $syntax;

    public function __construct(?PdfSyntaxReader $syntax = null)
    {
        $this->syntax = $syntax ?? new PdfSyntaxReader();
    }

    /** @return SignedRevision|null */
    public function readSignedRevision(string $content, int $coveredEnd): ?array
    {
        $signedContent = substr($content, 0, $coveredEnd);
        $startxrefPos = strrpos($signedContent, 'startxref');
        if ($startxrefPos === false
            || !preg_match('/\Gstartxref\s+(\d+)\s+%%EOF\s*$/', $signedContent, $match, 0, $startxrefPos)) {
            return null;
        }
        $startxref = (int) $match[1];
        $xref = $this->signedXrefChain($signedContent, $startxref);
        if ($xref === null) {
            return null;
        }
        [$offsets, $trailer] = $xref;
        $size = $trailer['/Size'] ?? '';
        $root = $trailer['/Root'] ?? '';
        $info = $trailer['/Info'] ?? null;
        if (!ctype_digit($size) || !preg_match('/^\d+ \d+ R$/', $root)
            || ($info !== null && !preg_match('/^\d+ \d+ R$/', $info))) {
            return null;
        }

        return [
            'startxref' => $startxref,
            'offsets' => array_filter($offsets, static fn (?int $offset): bool => $offset !== null),
            'size' => (int) $size,
            'root' => $root,
            'info' => $info,
        ];
    }

    /** @return array{array<int,?int>,array<string,string>}|null */
    private function signedXrefChain(string $content, int $startxref): ?array
    {
        $offsets = [];
        $trailer = null;
        $visited = [];
        $offset = $startxref;
        while ($offset !== null) {
            if (!$this->validOffset($offset, $content, $visited)) {
                return null;
            }
            $visited[$offset] = true;
            $section = $this->readSection($content, $offset);
            if ($section === null || isset($section['trailer']['/XRefStm'])) {
                return null;
            }
            $trailer ??= $section['trailer'];
            foreach ($section['entries'] as $num => [$entryOffset, , $inUse]) {
                if (!array_key_exists($num, $offsets)) {
                    $offsets[$num] = $inUse ? $entryOffset : null;
                }
            }
            $offset = $this->previousOffset($section['trailer']);
            if ($offset === -1) {
                return null;
            }
        }

        return $trailer === null ? null : [$offsets, $trailer];
    }

    /** @return XrefSection|null */
    public function readSection(string $content, int $pos): ?array
    {
        if (!preg_match('/\Gxref[ \t]*(?:\r\n|\r|\n)/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);
        $entries = $this->readXrefEntries($content, $pos);
        if ($entries === null || !preg_match('/\G\s*trailer\b/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);
        $this->syntax->skipPdfWhitespace($content, $pos);
        if (substr($content, $pos, 2) !== '<<') {
            return null;
        }
        $trailer = $this->syntax->readPdfDictionary($content, $pos, 0);

        return $trailer === null ? null : ['entries' => $entries, 'trailer' => $trailer, 'end' => $pos];
    }

    /** @return array<int,array{int,int,bool}>|null */
    private function readXrefEntries(string $content, int &$pos): ?array
    {
        $entries = [];
        while (preg_match('/\G[ \t]*(\d+) (\d+)[ \t]*(?:\r\n|\r|\n)/', $content, $header, 0, $pos)) {
            $pos += strlen($header[0]);
            $first = (int) $header[1];
            for ($i = 0; $i < (int) $header[2]; $i++) {
                if (!preg_match('/\G(\d{10}) (\d{5}) ([nf])(?: \r| \n|\r\n)/', $content, $entry, 0, $pos)) {
                    return null;
                }
                $pos += 20;
                $number = $first + $i;
                if (array_key_exists($number, $entries)) {
                    return null;
                }
                $entries[$number] = [(int) $entry[1], (int) $entry[2], $entry[3] === 'n'];
            }
        }

        return $entries;
    }


    /** @param array<int,bool> $visited */
    private function validOffset(int $offset, string $content, array $visited): bool
    {
        return !isset($visited[$offset])
            && count($visited) < 1000
            && $offset >= 0
            && $offset < strlen($content);
    }

    /** @param array<string,string> $trailer */
    private function previousOffset(array $trailer): ?int
    {
        $previous = $trailer['/Prev'] ?? null;
        if ($previous === null) {
            return null;
        }

        return ctype_digit($previous) ? (int) $previous : -1;
    }
}
