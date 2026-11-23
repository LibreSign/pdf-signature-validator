<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Syntax;

/**
 * Strict token reader for canonical PDF values. Rejects duplicate dictionary
 * keys and unsupported syntax instead of recovering from malformed input.
 */
final class PdfSyntaxReader
{
    private const MAX_NESTING_DEPTH = 64;

    private PdfLiteralStringReader $literal;

    public function __construct(?PdfLiteralStringReader $literal = null)
    {
        $this->literal = $literal ?? new PdfLiteralStringReader();
    }

    /**
     * Top-level entries of a PDF dictionary, each value in canonical form.
     *
     * @return array<string, string>|null Null when the object is not a dictionary
     */
    public function parseDictionaryEntries(string $object): ?array
    {
        $pos = 0;
        $this->skipPdfWhitespace($object, $pos);
        if (substr($object, $pos, 2) !== '<<') {
            return null;
        }
        return $this->readPdfDictionary($object, $pos, 0);
    }

    /**
     * @return array<string, string>|null Null on malformed input or a duplicate key
     */
    public function readPdfDictionary(string $pdf, int &$pos, int $depth): ?array
    {
        if ($depth > self::MAX_NESTING_DEPTH) {
            return null;
        }
        $pos += 2;
        $entries = [];
        while (true) {
            $this->skipPdfWhitespace($pdf, $pos);
            if ($pos >= strlen($pdf) || $pdf[$pos] !== '/') {
                if (substr($pdf, $pos, 2) !== '>>') {
                    return null;
                }
                $pos += 2;
                return $entries;
            }
            $key = $this->readPdfValue($pdf, $pos, $depth + 1);
            $value = $this->readPdfValue($pdf, $pos, $depth + 1);
            if ($key === null || $value === null || isset($entries[$key])) {
                return null;
            }
            $entries[$key] = $value;
        }
    }

    /**
     * Read one PDF object at $pos and return it in a canonical form: single
     * spaces between tokens, dictionary keys sorted, names with #xx escapes
     * decoded and strings compared by their bytes, so a rewritten but
     * unchanged object compares equal regardless of the writer's formatting.
     */
    public function readPdfValue(string $pdf, int &$pos, int $depth): ?string
    {
        if ($depth > self::MAX_NESTING_DEPTH) {
            return null;
        }
        $this->skipPdfWhitespace($pdf, $pos);
        if ($pos >= strlen($pdf)) {
            return null;
        }
        if (substr($pdf, $pos, 2) === '<<') {
            return $this->dictionaryValue($pdf, $pos, $depth);
        }

        return match ($pdf[$pos]) {
            '[' => $this->arrayValue($pdf, $pos, $depth),
            '(' => $this->literal->read($pdf, $pos),
            '<' => $this->hexString($pdf, $pos),
            default => $this->plainToken($pdf, $pos),
        };
    }

    private function dictionaryValue(string $pdf, int &$pos, int $depth): ?string
    {
        $entries = $this->readPdfDictionary($pdf, $pos, $depth + 1);
        if ($entries === null) {
            return null;
        }
        ksort($entries);
        $parts = [];
        foreach ($entries as $key => $value) {
            $parts[] = $key . ' ' . $value;
        }

        return '<<' . implode(' ', $parts) . '>>';
    }

    private function arrayValue(string $pdf, int &$pos, int $depth): ?string
    {
        $pos++;
        $items = [];
        while (true) {
            $this->skipPdfWhitespace($pdf, $pos);
            if ($pos >= strlen($pdf)) {
                return null;
            }
            if ($pdf[$pos] === ']') {
                $pos++;
                return '[' . implode(' ', $items) . ']';
            }
            $item = $this->readPdfValue($pdf, $pos, $depth + 1);
            if ($item === null) {
                return null;
            }
            $items[] = $item;
        }
    }

    private function hexString(string $pdf, int &$pos): ?string
    {
        $end = strpos($pdf, '>', $pos);
        if ($end === false) {
            return null;
        }
        $hex = strtolower((string) preg_replace('/\s+/', '', substr($pdf, $pos + 1, $end - $pos - 1)));
        if (!ctype_xdigit($hex) && $hex !== '') {
            return null;
        }
        $pos = $end + 1;

        return '<' . $hex . (strlen($hex) % 2 === 1 ? '0' : '') . '>';
    }

    private function plainToken(string $pdf, int &$pos): ?string
    {
        if (!preg_match('/\G\/?[^\x00\t\n\x0c\r ()<>\[\]{}\/%]*/', $pdf, $token, 0, $pos)
            || $token[0] === '') {
            return null;
        }
        $pos += strlen($token[0]);
        if ($token[0][0] === '/') {
            return $this->canonicalName(substr($token[0], 1));
        }
        if (ctype_digit($token[0]) && preg_match('/\G\s+(\d+)\s+R(?![^\x00\t\n\x0c\r ()<>\[\]{}\/%])/', $pdf, $ref, 0, $pos)) {
            $pos += strlen($ref[0]);
            return $token[0] . ' ' . $ref[1] . ' R';
        }

        return $token[0];
    }

    /**
     * Name with #xx escapes decoded, then re-escaped only where needed, so
     * /ObjStm and /Obj#53tm compare equal.
     */
    private function canonicalName(string $name): string
    {
        $decoded = (string)preg_replace_callback(
            '/#([0-9A-Fa-f]{2})/',
            static fn (array $match): string => chr((int)hexdec($match[1])),
            $name,
        );
        return '/' . (string)preg_replace_callback(
            '/[^\x21-\x7e]|[#()<>\[\]{}\/%]/',
            static fn (array $match): string => sprintf('#%02X', ord($match[0])),
            $decoded,
        );
    }

    public function skipPdfWhitespace(string $pdf, int &$pos): void
    {
        $length = strlen($pdf);
        while ($pos < $length) {
            if (in_array($pdf[$pos], ["\x00", "\t", "\n", "\x0c", "\r", " "], true)) {
                $pos++;
                continue;
            }
            if ($pdf[$pos] !== '%') {
                return;
            }
            $pos += strcspn($pdf, "\r\n", $pos);
        }
    }
}
