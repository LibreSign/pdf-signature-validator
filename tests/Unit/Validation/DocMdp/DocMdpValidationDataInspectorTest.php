<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp;

use LibreSign\PdfSignatureValidator\Tests\Fixtures\CertifiedPdfRevisionFixture;
use LibreSign\PdfSignatureValidator\Tests\Unit\Parser\SyntheticPdf;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\DocMdpValidationDataInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

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
            9 => "<< /Length 4 >>\nstream\nABCD\nendstream",
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
            9 => "<< /Length 4 >>\nstream\nABCD\nendstream",
        ]);

        self::assertFalse($this->inspect($signed, $updated));
    }

    public function testRejectsTrailerSizeBelowReferencedNewObjectNumber(): void
    {
        $signed = $this->signedPdf();
        $updated = $this->withDss($signed);
        self::assertTrue($this->inspect($signed, $updated));

        $invalid = preg_replace('~/Size \\d+ /Root 1 0 R /Prev~', '/Size 1 /Root 1 0 R /Prev', $updated);
        self::assertNotNull($invalid);
        self::assertFalse($this->inspect($signed, $invalid));
    }

    public function testRejectsContentStreamChangeAlongsideDss(): void
    {
        $signed = $this->signedPdf();
        $updated = SyntheticPdf::incrementalUpdate($signed, [
            1 => self::CATALOG_DSS,
            3 => '<< /Type /Page /Parent 2 0 R /Contents 10 0 R /MediaBox [0 0 400 200] >>',
            8 => self::DSS,
            9 => "<< /Length 4 >>\nstream\nABCD\nendstream",
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
            9 => "<< /Length 4 >>\nstream\nABCD\nendstream",
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
            11 => "<< /Length 4 >>\nstream\nABCD\nendstream",
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

    public function testAllowsASecondDssRevisionWithAppendedValidationEvidence(): void
    {
        $signed = $this->signedPdf();
        $initial = $this->withDss($signed);
        $renewed = SyntheticPdf::incrementalUpdate($initial, [
            8 => '<< /Type /DSS /Certs [9 0 R 10 0 R] >>',
            10 => "<< /Length 4 >>\nstream\nEFGH\nendstream",
        ]);

        self::assertTrue($this->inspect($signed, $initial));
        self::assertTrue($this->inspect($signed, $renewed));
    }

    public function testAllowsAddingASecondDssEvidenceCategoryInLaterRevision(): void
    {
        $signed = $this->signedPdf();
        $initial = $this->withDss($signed);
        $renewed = SyntheticPdf::incrementalUpdate($initial, [
            8 => '<< /Type /DSS /Certs [9 0 R] /CRLs [10 0 R] >>',
            10 => "<< /Length 4 >>\nstream\nEFGH\nendstream",
        ]);

        self::assertTrue($this->inspect($signed, $renewed));
    }

    public function testRejectsDssRevisionThatRemovesEarlierEvidence(): void
    {
        $signed = $this->signedPdf();
        $initial = $this->withDss($signed);
        $renewed = SyntheticPdf::incrementalUpdate($initial, [
            8 => '<< /Type /DSS /Certs [10 0 R] >>',
            10 => "<< /Length 4 >>\nstream\nEFGH\nendstream",
        ]);

        self::assertFalse($this->inspect($signed, $renewed));
    }

    public function testRejectsDssRevisionWithUnrelatedRewrittenObject(): void
    {
        $signed = $this->signedPdf();
        $initial = $this->withDss($signed);
        $renewed = SyntheticPdf::incrementalUpdate($initial, [
            8 => '<< /Type /DSS /Certs [9 0 R 10 0 R] >>',
            9 => "<< /Length 4 >>\nstream\nEVIL\nendstream",
            10 => "<< /Length 4 >>\nstream\nEFGH\nendstream",
        ]);

        self::assertFalse($this->inspect($signed, $renewed));
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

    /** @return iterable<string, array{string, bool}> */
    public static function realCertifiedPdfUpdates(): iterable
    {
        yield 'DSS addition does not violate certification' => ['dss', true];
        yield 'DSS with modified page tree is a violation' => ['tampered_catalog', false];
    }

    #[DataProvider('realCertifiedPdfUpdates')]
    public function testRealCertifiedPdfDssValidation(string $scenario, bool $expected): void
    {
        [$signed, $updated] = match ($scenario) {
            'dss' => CertifiedPdfRevisionFixture::withDss(),
            'tampered_catalog' => CertifiedPdfRevisionFixture::withDssAndChangedPageTree(),
        };

        self::assertSame($expected, $this->inspect($signed, $updated));
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
            9 => "<< /Length 4 >>\nstream\nABCD\nendstream",
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
