<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/**
 * Strict cross-reference stream container reader. The entry decoder handles
 * limits, reference provenance and unsupported compressed objects separately.
 */
final class PdfXrefStreamReader
{
    private const MAX_STREAM_BYTES = 16_777_216;

    private PdfXrefStreamEntryDecoder $decoder;

    public function __construct(private readonly PdfSyntaxReader $syntax)
    {
        $this->decoder = new PdfXrefStreamEntryDecoder();
    }

    /** @return array{entries:array<int,array{int,int,bool}>,compressed:array<int,array{int,int}>,trailer:array<string,string>,end:int}|null */
    public function readSection(string $pdf, int $pos): ?array
    {
        $container = $this->readContainer($pdf, $pos);
        if ($container === null) {
            return null;
        }
        [$trailer, $stream, $end] = $container;
        $decoded = $this->decoder->decode($pdf, $trailer, $stream);
        if ($decoded === null) {
            return null;
        }

        return $decoded + ['trailer' => $trailer, 'end' => $end];
    }

    /** @param array<string,string> $trailer */
    private function validTrailer(array $trailer): bool
    {
        return ($trailer['/Type'] ?? null) === '/XRef'
            && ctype_digit($trailer['/Size'] ?? '')
            && ctype_digit($trailer['/Length'] ?? '')
            && in_array($trailer['/Filter'] ?? null, [null, '/FlateDecode'], true)
            && !isset($trailer['/DecodeParms']);
    }

    /** @return array{array<string,string>,string,int}|null */
    private function readContainer(string $pdf, int $pos): ?array
    {
        if (!preg_match('/\G\d+ 0 obj\b/', $pdf, $header, 0, $pos)) {
            return null;
        }
        $pos += strlen($header[0]);
        $this->syntax->skipPdfWhitespace($pdf, $pos);
        if (substr($pdf, $pos, 2) !== '<<') {
            return null;
        }
        $trailer = $this->syntax->readPdfDictionary($pdf, $pos, 0);
        if ($trailer === null || !$this->validTrailer($trailer)) {
            return null;
        }

        if (!preg_match('/\G\s*stream(?:\r\n|\n)/', $pdf, $marker, 0, $pos)) {
            return null;
        }
        $pos += strlen($marker[0]);
        $length = (int) $trailer['/Length'];
        if ($length < 1 || $length > self::MAX_STREAM_BYTES
            || $length > strlen($pdf) - $pos) {
            return null;
        }
        $stream = substr($pdf, $pos, $length);
        $pos += $length;
        if (!preg_match('/\G\s*endstream\s*endobj\b/', $pdf, $end, 0, $pos)) {
            return null;
        }

        return [$trailer, $stream, $pos + strlen($end[0])];
    }
}
