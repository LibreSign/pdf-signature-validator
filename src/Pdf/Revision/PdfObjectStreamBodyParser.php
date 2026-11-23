<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/** Strict parser for indirect objects embedded inside a historical /ObjStm. */
final class PdfObjectStreamBodyParser
{
    private const MAX_STREAM_BYTES = 16_777_216;
    private const MAX_OBJECTS = 100_000;

    public function __construct(private readonly PdfSyntaxReader $syntax)
    {
    }

    /**
     * @return list<array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>|null
     */
    public function parse(string $content, int $count, int $first): ?array
    {
        if ($first <= 0 || $first > strlen($content)
            || $count > self::MAX_OBJECTS || strlen($content) > self::MAX_STREAM_BYTES) {
            return null;
        }
        $header = substr($content, 0, $first);
        if (preg_match('/^(?:\s*\d+\s+\d+)+\s*$/', $header) !== 1) {
            return null;
        }
        preg_match_all('/\d+/', $header, $match);
        if (count($match[0]) !== $count * 2) {
            return null;
        }
        $objects = [];
        $last = -1;
        $seen = [];
        for ($i = 0; $i < $count; $i++) {
            $number = (int) $match[0][$i * 2];
            $relative = (int) $match[0][$i * 2 + 1];
            if ($number <= 0 || isset($seen[$number])
                || $relative <= $last || $relative >= strlen($content) - $first) {
                return null;
            }
            $seen[$number] = true;
            $last = $relative;
            $objects[] = [$number, $relative];
        }

        return $this->parseBodies($content, $first, $objects);
    }

    /**
     * @param list<array{int,int}> $offsets
     * @return list<array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>|null
     */
    private function parseBodies(string $content, int $first, array $offsets): ?array
    {
        $parsed = [];
        foreach ($offsets as $i => [$number, $relative]) {
            $start = $first + $relative;
            $limit = $first + ($offsets[$i + 1][1] ?? (strlen($content) - $first));
            $pos = $start;
            $value = $this->syntax->readPdfValue($content, $pos, 0);
            if ($value === null || $pos > $limit
                || strspn($content, "\x00\t\n\x0c\r ", $pos, $limit - $pos) !== $limit - $pos) {
                return null;
            }
            $entries = str_starts_with($value, '<<') ? $this->syntax->parseDictionaryEntries($value) : null;
            if (str_starts_with($value, '<<') && $entries === null) {
                return null;
            }
            $parsed[] = [
                'num' => $number, 'gen' => 0, 'value' => $value,
                'entries' => $entries, 'stream' => null, 'end' => $pos,
            ];
        }

        return $parsed;
    }
}
