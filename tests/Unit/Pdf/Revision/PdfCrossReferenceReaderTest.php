<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfCrossReferenceReader;
use LibreSign\PdfSignatureValidator\Tests\Unit\Parser\SyntheticPdf;
use PHPUnit\Framework\TestCase;

final class PdfCrossReferenceReaderTest extends TestCase
{
    public function testReadsFlateEncodedXrefStream(): void
    {
        $pdf = SyntheticPdf::withObjectStream([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ], []);
        $offset = self::xrefOffset($pdf);
        $start = strpos($pdf, "stream\n", $offset) + strlen("stream\n");
        $end = strpos($pdf, "\nendstream", $start);
        $raw = substr($pdf, $start, $end - $start);
        $deflated = gzcompress($raw);
        $prefix = substr($pdf, 0, $start);
        $prefix = str_replace('/Length ' . strlen($raw), '/Filter /FlateDecode /Length ' . strlen($deflated), $prefix);
        $compressed = $prefix . $deflated . substr($pdf, $end);

        $xref = (new PdfCrossReferenceReader())->readSection($compressed, $offset);
        self::assertNotNull($xref);
        self::assertSame(6, count($xref['entries']));
        self::assertSame($offset, $xref['entries'][5][0]);
    }

    public function testRejectsInvalidXrefStreamWidths(): void
    {
        $pdf = SyntheticPdf::withObjectStream([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ], []);
        $corrupt = str_replace('/W [1 4 2]', '/W [9 4 2]', $pdf);

        self::assertNull((new PdfCrossReferenceReader())->readSection($corrupt, self::xrefOffset($corrupt)));
    }

    public function testRejectsCompressedObjectEntryUntilStrictHistoricalResolutionExists(): void
    {
        $pdf = SyntheticPdf::withObjectStream([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ], [
            4 => '<< /Type /Example >>',
        ]);

        self::assertNull((new PdfCrossReferenceReader())->readSection($pdf, self::xrefOffset($pdf)));
    }

    private static function xrefOffset(string $pdf): int
    {
        preg_match('/startxref\s+(\d+)/', $pdf, $match);

        return (int) $match[1];
    }
}
