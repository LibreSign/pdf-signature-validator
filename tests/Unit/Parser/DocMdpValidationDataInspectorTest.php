<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\DocMdpValidationDataInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SignerPHP\PdfCore\Service\PdfDocumentPreparer;

final class DocMdpValidationDataInspectorTest extends TestCase
{
    private const CATALOG = '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>';

    private const CATALOG_DSS = '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> /DSS 8 0 R >>';

    private const DSS = '<< /Type /DSS /Certs [9 0 R] >>';

    /** @return iterable<string, array{int}> */
    public static function permissionProvider(): iterable
    {
        yield 'P=1' => [1];
        yield 'P=2' => [2];
        yield 'P=3' => [3];
    }

    #[DataProvider('permissionProvider')]
    public function testAllowsDssDataAfterCertificationAtAllPermissionLevels(int $level): void
    {
        $signed = SyntheticPdf::certifiedPdf(SyntheticPdf::signature($level));
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => self::CATALOG_DSS,
            8 => self::DSS,
            9 => '<ABCD>',
        ]);

        self::assertTrue($this->inspect($signed, $updated));
    }

    public function testRejectsVersionOnlyChangeWithoutDss(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate(
            $signed,
            [1 => substr(self::CATALOG, 0, -2) . ' /Version /1.7 >>'],
        );

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRejectsSigFlagsOnlyChangeWithoutTimestamp(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace(
                '/AcroForm << /Fields [7 0 R] >>',
                '/AcroForm << /Fields [7 0 R] /SigFlags 3 >>',
                self::CATALOG,
            ),
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRejectsUnrelatedCatalogChangeAlongsideDss(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace('/DSS 8 0 R', '/OpenAction 9 0 R /DSS 8 0 R', self::CATALOG_DSS),
            8 => self::DSS,
            9 => '<ABCD>',
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRejectsContentStreamChangeAlongsideDss(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => self::CATALOG_DSS,
            3 => '<< /Type /Page /Parent 2 0 R /Contents 10 0 R /MediaBox [0 0 400 200] >>',
            8 => self::DSS,
            9 => '<ABCD>',
            10 => '<< /Length 3 >> stream' . "\n" . 'abc' . "\n" . 'endstream',
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRejectsIntermediateUnauthorizedRevisionEvenIfLaterRestored(): void
    {
        $signed = $this->signedPdf();
        $tampered = SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace('/Pages 2 0 R', '/Pages 2 0 R /OpenAction 20 0 R', self::CATALOG),
        ]);
        $restored = SyntheticPdf::incrementalUpdate($tampered, [
            1 => self::CATALOG_DSS,
            8 => self::DSS,
            9 => '<ABCD>',
        ]);

        self::assertFalse($this->inspect($signed, $restored));
    }

    public function testRejectsVersionOnlyRevisionAfterGenuineDssRevision(): void
    {
        $signed = $this->signedPdf();
        $updated = $this->withDss($signed);
        $versionOnly = SyntheticPdf::incrementalUpdate($updated, [
            1 => str_replace('/DSS 8 0 R', '/DSS 8 0 R /Version /1.7', self::CATALOG_DSS),
        ]);

        self::assertFalse($this->inspect($signed, $versionOnly));
    }

    public function testRejectsDssReferenceToUncreatedObject(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace('/DSS 8 0 R', '/DSS 30 0 R', self::CATALOG_DSS),
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testAllowsDocumentTimestampAfterCertification(): void
    {
        $signed = $this->signedPdf();
        $updated = $this->withTimestamp($signed);

        self::assertTrue($this->inspect($signed, $updated));
    }

    public function testAllowsTimestampFollowedByDss(): void
    {
        $signed = $this->signedPdf();
        $timestamped = $this->withTimestamp($signed);
        $dssUpdated = SyntheticPdf::incrementalUpdate($timestamped, [
            1 => str_replace(
                ' /AcroForm << /Fields [7 0 R] >>',
                ' /AcroForm << /Fields [7 0 R 8 0 R] >> /DSS 10 0 R',
                self::CATALOG,
            ),
            10 => '<< /Type /DSS /Certs [11 0 R] >>',
            11 => '<ABCD>',
        ]);

        self::assertTrue($this->inspect($signed, $dssUpdated));
    }

    public function testAllowsDssFollowedByTimestamp(): void
    {
        $signed = $this->signedPdf();
        $dssUpdated = $this->withDss($signed);
        $timestamped = SyntheticPdf::incrementalUpdate($dssUpdated, [
            1 => str_replace(
                '/AcroForm << /Fields [7 0 R] >>',
                '/AcroForm << /Fields [7 0 R 10 0 R] >>',
                self::CATALOG_DSS,
            ),
            10 => $this->timestampField(11),
            11 => $this->timestampObject(),
        ]);

        self::assertTrue($this->inspect($signed, $timestamped));
    }

    public function testRejectsVisibleTimestampField(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace('/Fields [7 0 R]', '/Fields [7 0 R 8 0 R]', self::CATALOG),
            8 => str_replace('/Rect [0 0 0 0]', '/Rect [0 0 100 50]', $this->timestampField(9)),
            9 => $this->timestampObject(),
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRealJSignPdfCertificationAcceptsOnlyDssUpdate(): void
    {
        [$signed, $updated] = $this->realJSignPdfWithDss();

        self::assertTrue($this->inspect($signed, $updated));
    }

    public function testRealJSignPdfCertificationRejectsDssWithCatalogTampering(): void
    {
        [$signed, $updated] = $this->realJSignPdfWithDss(true);

        self::assertFalse($this->inspect($signed, $updated));
    }

    /**
     * Use an actual JSignPdf-certified document. Copy its live catalog bytes
     * instead of reserializing them, since reserialization may change a PDF
     * string's significant trailing whitespace.
     *
     * @return array{string, string}
     */
    private function realJSignPdfWithDss(bool $tamperCatalog = false): array
    {
        $signed = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/real_jsignpdf_level1.pdf');
        self::assertIsString($signed);

        $document = (new PdfDocumentPreparer())->prepare($signed);
        $trailer = $document->getTrailerObject();
        $rootRef = (string) $trailer['Root'];
        $rootNumber = (int) $trailer['Root']->asObjectReferenceOrNull();
        $rootOffset = $document->getXrefTable()[$rootNumber] ?? null;
        self::assertIsInt($rootOffset);

        self::assertSame(1, preg_match(
            '/^\d+\s+\d+\s+obj\s*(.*?)\s*endobj/s',
            substr($signed, $rootOffset),
            $catalogMatch,
        ));
        $catalog = $catalogMatch[1];
        if ($tamperCatalog) {
            $catalog = str_replace('/Pages 4 0 R', '/Pages 99 0 R', $catalog);
            self::assertStringContainsString('/Pages 99 0 R', $catalog);
        }

        $size = $trailer['Size']->asIntOrNull();
        self::assertIsInt($size);
        $catalog = substr_replace($catalog, "/DSS $size 0 R>>", (int) strrpos($catalog, '>>'), 2);
        $objects = [
            $rootNumber => $catalog,
            $size => '<< /Type /DSS /Certs [' . ($size + 1) . ' 0 R] >>',
            $size + 1 => '<ABCD>',
        ];
        ksort($objects);

        self::assertGreaterThan(0, preg_match_all('/startxref\s+(\d+)/', $signed, $xrefMatches));
        $previousXref = (int) end($xrefMatches[1]);
        $updated = $signed;
        $offsets = [];
        foreach ($objects as $number => $value) {
            $offsets[$number] = strlen($updated);
            $updated .= "$number 0 obj\n$value\nendobj\n";
        }

        $xrefOffset = strlen($updated);
        $updated .= "xref\n";
        foreach ($offsets as $number => $offset) {
            $updated .= sprintf("%d 1\n%010d 00000 n \n", $number, $offset);
        }
        $infoRef = isset($trailer['Info']) ? '/Info ' . (string) $trailer['Info'] . ' ' : '';
        $updated .= 'trailer' . "\n" . '<< /Size ' . ($size + 2)
            . " /Root $rootRef " . $infoRef . "/Prev $previousXref >>\n"
            . "startxref\n$xrefOffset\n%%EOF\n";

        return [$signed, $updated];
    }

    private function signedPdf(): string
    {
        return SyntheticPdf::certifiedPdf(SyntheticPdf::signature(1));
    }

    private function inspect(string $signed, string $updated): bool
    {
        return (new DocMdpValidationDataInspector())->hasOnlyValidationDataUpdates(
            $updated,
            strlen($signed),
        );
    }

    private function withDss(string $signed): string
    {
        return SyntheticPdf::incrementalUpdate($signed, [
            1 => self::CATALOG_DSS,
            8 => self::DSS,
            9 => '<ABCD>',
        ]);
    }

    private function withTimestamp(string $signed): string
    {
        return SyntheticPdf::incrementalUpdate($signed, [
            1 => str_replace('/Fields [7 0 R]', '/Fields [7 0 R 8 0 R]', self::CATALOG),
            8 => $this->timestampField(9),
            9 => $this->timestampObject(),
        ]);
    }

    private function timestampField(int $timestampObject): string
    {
        return '<< /FT /Sig /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /V '
            . $timestampObject . ' 0 R >>';
    }

    private function timestampObject(): string
    {
        return '<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /ByteRange [0 1 2 3] /Contents <ABCD> >>';
    }
}
