<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/**
 * Strictly resolves historical compressed objects using their xref type-2
 * stream/index locator, never a regex scan or parser recovery.
 */
final class PdfObjectStreamReader
{
    private const MAX_STREAM_BYTES = 16_777_216;
    private const MAX_OBJECTS = 100_000;

    private PdfObjectStreamBodyParser $bodies;

    public function __construct(private readonly PdfSyntaxReader $syntax)
    {
        $this->bodies = new PdfObjectStreamBodyParser($syntax);
    }

    /**
     * @param array<int,?int> $offsets
     * @param array<int,array{int,int}> $compressed
     * @return array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>|null
     */
    public function resolve(string $pdf, array $offsets, array $compressed): ?array
    {
        $cache = [];
        $resolved = [];
        foreach ($compressed as $number => [$streamNumber, $index]) {
            $offset = $offsets[$streamNumber] ?? null;
            if ($offset === null) {
                return null;
            }
            if (!isset($cache[$streamNumber])) {
                $cache[$streamNumber] = $this->readStream($pdf, $offset, $streamNumber);
                if ($cache[$streamNumber] === null) {
                    return null;
                }
            }
            $object = $cache[$streamNumber][$index] ?? null;
            if ($object === null || $object['num'] !== $number) {
                return null;
            }
            $resolved[$number] = $object;
        }

        return $resolved;
    }

    /**
     * @return list<array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>|null
     */
    private function readStream(string $pdf, int $offset, int $number): ?array
    {
        $container = $this->readContainer($pdf, $offset, $number);
        if ($container === null) {
            return null;
        }
        [$dict, $bytes] = $container;
        $decoded = $this->decompress($bytes, isset($dict['/Filter']));
        if ($decoded === null) {
            return null;
        }

        return $this->bodies->parse($decoded, (int) $dict['/N'], (int) $dict['/First']);
    }

    /** @return array{array<string,string>,string}|null */
    private function readContainer(string $pdf, int $offset, int $number): ?array
    {
        if (!preg_match('/\G' . $number . ' 0 obj\b/', $pdf, $header, 0, $offset)) {
            return null;
        }
        $pos = $offset + strlen($header[0]);
        $this->syntax->skipPdfWhitespace($pdf, $pos);
        if (substr($pdf, $pos, 2) !== '<<') {
            return null;
        }
        $dict = $this->syntax->readPdfDictionary($pdf, $pos, 0);
        if ($dict === null || !$this->validDictionary($dict)) {
            return null;
        }
        if (!preg_match('/\G\s*stream(?:\r\n|\n)/', $pdf, $marker, 0, $pos)) {
            return null;
        }
        $pos += strlen($marker[0]);
        $length = (int) $dict['/Length'];
        if ($length < 1 || $length > self::MAX_STREAM_BYTES
            || $length > strlen($pdf) - $pos) {
            return null;
        }
        $bytes = substr($pdf, $pos, $length);
        $pos += $length;
        if (!preg_match('/\G\s*endstream\s*endobj\b/', $pdf, $end, 0, $pos)) {
            return null;
        }
        return [$dict, $bytes];
    }

    /** @param array<string,string> $dict */
    private function validDictionary(array $dict): bool
    {
        return ($dict['/Type'] ?? null) === '/ObjStm'
            && ctype_digit($dict['/N'] ?? '')
            && ctype_digit($dict['/First'] ?? '')
            && ctype_digit($dict['/Length'] ?? '')
            && (int) $dict['/N'] >= 1
            && (int) $dict['/N'] <= self::MAX_OBJECTS
            && in_array($dict['/Filter'] ?? null, [null, '/FlateDecode'], true)
            && !isset($dict['/DecodeParms']);
    }

    /** @SuppressWarnings(PHPMD.ErrorControlOperator) Invalid compressed input is an expected rejection. */
    private function decompress(string $bytes, bool $flate): ?string
    {
        if (!$flate) {
            return $bytes;
        }
        if (!function_exists('gzuncompress')) {
            return null;
        }
        $decoded = @gzuncompress($bytes, self::MAX_STREAM_BYTES);

        return is_string($decoded) ? $decoded : null;
    }

}
