<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Syntax;

/** References in canonical PDF values, retaining their dictionary/array path. */
final class PdfReferencePaths
{
    public function __construct(private readonly PdfSyntaxReader $syntax = new PdfSyntaxReader())
    {
    }

    /** @return list<array{reference:string,path:string}>|null */
    public function read(string $value, string $path = ''): ?array
    {
        $references = [];
        if (!$this->collect($value, $path, 0, $references)) {
            return null;
        }

        return $references;
    }

    /** @param list<array{reference:string,path:string}> $references */
    private function collect(string $value, string $path, int $depth, array &$references): bool
    {
        if ($depth > 64) {
            return false;
        }
        if (preg_match('/^(\d+) (\d+) R$/D', $value, $match)) {
            $references[] = ['reference' => (int) $match[1] . ' ' . (int) $match[2] . ' R', 'path' => $path];
            return true;
        }
        if (str_starts_with($value, '<<')) {
            $entries = $this->syntax->parseDictionaryEntries($value);
            if ($entries === null) {
                return false;
            }
            foreach ($entries as $key => $entry) {
                if (!$this->collect($entry, $path . $key, $depth + 1, $references)) {
                    return false;
                }
            }
        } elseif (str_starts_with($value, '[')) {
            $pos = 1;
            while (true) {
                $this->syntax->skipPdfWhitespace($value, $pos);
                if ($pos >= strlen($value)) {
                    return false;
                }
                if ($value[$pos] === ']') {
                    return $pos === strlen($value) - 1;
                }
                $item = $this->syntax->readPdfValue($value, $pos, $depth + 1);
                if ($item === null || !$this->collect($item, $path . '[]', $depth + 1, $references)) {
                    return false;
                }
            }
        }

        return true;
    }
}
