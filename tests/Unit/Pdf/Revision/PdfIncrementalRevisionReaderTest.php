<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader;
use LibreSign\PdfSignatureValidator\Tests\Unit\Parser\SyntheticPdf;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdfIncrementalRevisionReaderTest extends TestCase
{
    private PdfIncrementalRevisionReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PdfIncrementalRevisionReader();
    }

    public function testReadsCertifiedRevisionWithoutGuessingCatalogFromText(): void
    {
        $signed = $this->certifiedPdf();
        $revision = $this->reader->readSignedRevision($signed, strlen($signed));

        self::assertNotNull($revision);
        self::assertSame('1 0 R', $revision['root']);
        self::assertSame(8, $revision['size']);
        self::assertSame('/Catalog', $this->reader->readSignedObject($signed, $revision, 1)['entries']['/Type']);
    }

    public function testKeepsEachIncrementalRevisionInsteadOfOnlyTheFinalObject(): void
    {
        $signed = $this->certifiedPdf();
        $modified = SyntheticPdf::incrementalUpdate($signed, [
            1 => '<< /Type /Catalog /Pages 2 0 R /Version /1.7 >>',
        ]);
        $restored = SyntheticPdf::incrementalUpdate($modified, [
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
        ]);
        $signedRevision = $this->reader->readSignedRevision($restored, strlen($signed));
        self::assertNotNull($signedRevision);

        $updates = $this->reader->readIncrementalUpdates($restored, strlen($signed), $signedRevision);

        self::assertCount(2, $updates);
        self::assertSame('/1.7', $updates[0][1]['entries']['/Version']);
        self::assertArrayNotHasKey('/Version', $updates[1][1]['entries']);
    }

    /** @return iterable<string,array{string,string}> */
    public static function alteredTrailerProvider(): iterable
    {
        yield 'different catalog reference' => ['/Root 1 0 R', '/Root 2 0 R'];
        yield 'changed previous xref pointer' => ['/Prev ', '/Prev 9999 '];
        yield 'xref stream flag not supported' => ['/Prev ', '/XRefStm 13 /Prev '];
        yield 'encrypted revision forbidden' => ['/Prev ', '/Encrypt 13 0 R /Prev '];
    }

    #[DataProvider('alteredTrailerProvider')]
    public function testRejectsCorruptedOrUnsafeTrailer(string $find, string $replace): void
    {
        $signed = $this->certifiedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [8 => '<< /Type /DSS /Certs [] >>']);
        $lastTrailer = (int) strrpos($updated, 'trailer');
        $updated = substr($updated, 0, $lastTrailer)
            . str_replace($find, $replace, substr($updated, $lastTrailer));
        $signedRevision = $this->reader->readSignedRevision($signed, strlen($signed));
        self::assertNotNull($signedRevision);

        self::assertNull($this->reader->readIncrementalUpdates($updated, strlen($signed), $signedRevision));
    }

    public function testResolvesCompressedCatalogFromSignedXrefStream(): void
    {
        $pdf = SyntheticPdf::withObjectStream(
            [5 => SyntheticPdf::signature(1)],
            [1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>'],
        );

        $signed = $this->reader->readSignedRevision($pdf, strlen($pdf));
        self::assertNotNull($signed);
        self::assertSame(1, $signed['compressedObjects'][1]['num']);
    }

    private function certifiedPdf(): string
    {
        return SyntheticPdf::certifiedPdf(SyntheticPdf::signature(1));
    }
    public function testRejectsDuplicateCrossReferenceEntriesWithinOneUpdate(): void
    {
        $signed = $this->certifiedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [8 => '<< /Type /DSS /Certs [] >>']);
        self::assertSame(1, preg_match('/xref\\n8 1\\n\\d{10} 00000 n \\n/', $updated, $match));
        $duplicated = substr($match[0], strlen("xref\n"));
        $updated = str_replace($match[0], $match[0] . $duplicated, $updated);

        $signedRevision = $this->reader->readSignedRevision($signed, strlen($signed));
        self::assertNotNull($signedRevision);
        self::assertNull($this->reader->readIncrementalUpdates($updated, strlen($signed), $signedRevision));
    }

}
