<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * PDF syntax and signature structure rules from ISO 32000-1. Every case
 * asserts the whole inventory.
 */
final class PdfSignatureInventoryStructureTest extends TestCase
{
    private PdfSignatureInventoryReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PdfSignatureInventoryReader();
    }

    /**
     * ISO 32000-1, 7.3.5: a name may write any character as #xx, so each
     * escaped case is the same PDF as the plain one.
     *
     * @return array<string, array{string, bool, int, int, ?DocMdpPermission}>
     */
    public static function pdfNameEscapingProvider(): array
    {
        $pdf = static fn (string $fieldType, string $method, string $referenceKey): string => SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => '<< /Type /Sig ' . SyntheticPdf::SIGNED_BYTES . ' ' . $referenceKey . ' [<< /Type /SigRef'
                . ' /TransformMethod ' . $method . ' /TransformParams << /Type /TransformParams /P 1 >> >>] >>',
            7 => '<< /FT ' . $fieldType . ' /T (Signature1) /V 5 0 R >>',
        ]);

        return [
            'plain names' => [$pdf('/Sig', '/DocMDP', '/Reference'), true, 1, 0, DocMdpPermission::NO_CHANGES],
            'field type /S#69g' => [$pdf('/S#69g', '/DocMDP', '/Reference'), true, 1, 0, DocMdpPermission::NO_CHANGES],
            'transform method /Doc#4dDP' => [$pdf('/Sig', '/Doc#4dDP', '/Reference'), true, 1, 0, DocMdpPermission::NO_CHANGES],
            'key /Refe#72ence' => [$pdf('/Sig', '/DocMDP', '/Refe#72ence'), true, 1, 0, DocMdpPermission::NO_CHANGES],
            'text field pointing to the signature' => [$pdf('/Tx', '/DocMDP', '/Reference'), true, 0, 1, null],
            'keys /Reference and /Refe#72ence in one dictionary' => [
                $pdf('/Sig', '/DocMDP', '/Reference [] /Refe#72ence'), false, 0, 0, null,
            ],
        ];
    }

    #[DataProvider('pdfNameEscapingProvider')]
    public function testPdfNameEscaping(
        string $pdf,
        bool $conclusive,
        int $active,
        int $orphaned,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertFullInventory($pdf, $conclusive, $active, $orphaned, $permission);
    }

    /**
     * ISO 32000-1, 12.8.4, table 258: the signature that /Perms /DocMDP
     * references must have a DocMDP transform.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function docMdpCatalogConsistencyProvider(): array
    {
        $fieldOnly = static fn (string $signature): string => SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => $signature,
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
        ]);
        $fieldMdp = '<< /Type /SigRef /TransformMethod /FieldMDP'
            . ' /TransformParams << /Type /TransformParams /Action /All /V /1.2 >> >>';

        return [
            '/Perms references a DocMDP signature' => [
                SyntheticPdf::certifiedPdf(SyntheticPdf::signature(2)), true, 1, DocMdpPermission::FORM_FILLING,
            ],
            'DocMDP signature referenced only by a field' => [
                $fieldOnly(SyntheticPdf::signature(2)), true, 1, DocMdpPermission::FORM_FILLING,
            ],
            '/Perms references a signature without /Reference' => [
                SyntheticPdf::certifiedPdf(SyntheticPdf::signature(null)), false, 0, null,
            ],
            '/Perms references a signature with only FieldMDP' => [
                SyntheticPdf::certifiedPdf(SyntheticPdf::signatureWithReferences([$fieldMdp])), false, 0, null,
            ],
            '/Perms references a signature with an empty /Reference' => [
                SyntheticPdf::certifiedPdf(SyntheticPdf::signatureWithReferences([])), false, 0, null,
            ],
            'approval without /Perms' => [$fieldOnly(SyntheticPdf::signature(null)), true, 1, null],
        ];
    }

    #[DataProvider('docMdpCatalogConsistencyProvider')]
    public function testDocMdpCatalogConsistency(
        string $pdf,
        bool $conclusive,
        int $active,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertFullInventory($pdf, $conclusive, $active, 0, $permission);
    }

    /**
     * ISO 32000-1, 7.3.10: a reference names the object number and the
     * generation. Every case writes the generation in the object header and
     * in the cross-reference table.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function signatureReferenceGenerationProvider(): array
    {
        $field = static fn (int $objectGeneration, int $referenceGeneration): string => SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => SyntheticPdf::signature(1),
            7 => "<< /FT /Sig /T (Signature1) /V 5 $referenceGeneration R >>",
        ], [5 => $objectGeneration]);

        return [
            '5 0 obj through /V 5 0 R' => [$field(0, 0), true, 1, DocMdpPermission::NO_CHANGES],
            '5 0 obj through /V 5 1 R' => [$field(0, 1), false, 0, null],
            '5 1 obj through /V 5 1 R' => [$field(1, 1), true, 1, DocMdpPermission::NO_CHANGES],
            '5 1 obj through /V 5 0 R' => [$field(1, 0), false, 0, null],
            '5 0 obj through /Perms /DocMDP 5 1 R' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 1 R >> >>',
                    5 => SyntheticPdf::signature(1),
                ]),
                false, 0, null,
            ],
            'field referenced twice with a valid generation' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R 7 0 R] >> >>',
                    5 => SyntheticPdf::signature(1),
                    7 => '<< /FT /Sig /V 5 0 R >>',
                ]),
                true, 1, DocMdpPermission::NO_CHANGES,
            ],
            'visited field followed by a mismatched generation' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R 7 1 R] >> >>',
                    5 => SyntheticPdf::signature(1),
                    7 => '<< /FT /Sig /V 5 0 R >>',
                ]),
                false, 0, null,
            ],
        ];
    }

    #[DataProvider('signatureReferenceGenerationProvider')]
    public function testSignatureReferenceGeneration(
        string $pdf,
        bool $conclusive,
        int $active,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertFullInventory($pdf, $conclusive, $active, 0, $permission);
    }

    /**
     * Every active signature needs a /ByteRange that fits the file, even
     * when it is the only one.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function activeSignatureByteRangeProvider(): array
    {
        $certification = SyntheticPdf::certifiedPdf(SyntheticPdf::signature(2));
        $approval = SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => SyntheticPdf::signature(null),
            7 => '<< /FT /Sig /T (Approval) /V 5 0 R >>',
        ]);
        $afterTheFile = static fn (array $range): array => [$range[0], $range[1], $range[2], $range[3] + 1];
        // "[0 0000000123" and "[+0 000000123" have the same length and numbers
        $signedOffset = static fn (string $pdf): string => str_replace('/ByteRange [0 0', '/ByteRange [+0 ', $pdf);

        return [
            'certification' => [$certification, true, 1, DocMdpPermission::FORM_FILLING],
            'certification with the offset +0' => [$signedOffset($certification), true, 1, DocMdpPermission::FORM_FILLING],
            'certification ending after the file' => [
                SyntheticPdf::changeLastByteRange($certification, $afterTheFile), false, 0, null,
            ],
            'certification with overlapping ranges' => [
                SyntheticPdf::changeLastByteRange($certification, static fn (array $range): array => [
                    $range[0], $range[1], $range[1] - 1, $range[3],
                ]),
                false, 0, null,
            ],
            'certification without /ByteRange' => [
                SyntheticPdf::certifiedPdf(
                    '<< /Type /Sig /Contents <0000> /Reference [' . SyntheticPdf::docMdpReference('/P 2') . '] >>',
                ),
                false, 0, null,
            ],
            'approval' => [$approval, true, 1, null],
            'approval ending after the file' => [SyntheticPdf::changeLastByteRange($approval, $afterTheFile), false, 0, null],
            'approval with an odd number of /ByteRange values' => [
                str_replace('/ByteRange [0 0', '/ByteRange [  0', $approval), false, 0, null,
            ],
            'unsigned' => [SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']), true, 0, null],
        ];
    }

    #[DataProvider('activeSignatureByteRangeProvider')]
    public function testActiveSignatureByteRange(
        string $pdf,
        bool $conclusive,
        int $active,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertFullInventory($pdf, $conclusive, $active, 0, $permission);
    }

    /**
     * An inconclusive inventory must keep the defaults: no signatures and no permission.
     */
    private function assertFullInventory(
        string $pdf,
        bool $conclusive,
        int $active,
        int $orphaned,
        ?DocMdpPermission $permission,
    ): void {
        $inventory = $this->reader->readFromString($pdf);

        $this->assertSame($conclusive, $inventory->isConclusive);
        $this->assertSame($active, $inventory->activeSignatureCount);
        $this->assertSame($orphaned, $inventory->orphanedSignatureCount);
        $this->assertSame($permission, $inventory->docMdpPermission);
    }
}
