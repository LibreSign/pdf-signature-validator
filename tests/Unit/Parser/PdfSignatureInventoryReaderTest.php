<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class PdfSignatureInventoryReaderTest extends TestCase
{
    private const DOC_MDP_REFERENCE = '<< /Type /SigRef /TransformMethod /DocMDP'
        . ' /TransformParams << /Type /TransformParams /P 1 /V /1.2 >> >>';

    private PdfSignatureInventoryReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PdfSignatureInventoryReader();
    }

    public function testUnsignedPdfHasNoSignatures(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']));

        $this->assertInventory($inventory, 0, 0, null);
    }

    public function testUnreferencedCertificationSignatureIsOrphaned(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            5 => SyntheticPdf::signature(1),
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testCertificationReferencedFromPermsAndFieldIsActive(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm 6 0 R >>',
            5 => SyntheticPdf::signature(1),
            6 => '<< /Fields [7 0 R] /SigFlags 3 >>',
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testCertificationReferencedOnlyFromPermsIsActive(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => SyntheticPdf::signature(3),
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::FORM_FILLING_AND_ANNOTATIONS);
    }

    public function testCertificationReferencedOnlyFromFieldIsActive(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => SyntheticPdf::signature(1),
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureFieldTypeIsInheritedFromParentField(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
            5 => SyntheticPdf::signature(2),
            6 => '<< /FT /Sig /T (Parent) /Kids [7 0 R] >>',
            7 => '<< /Parent 6 0 R /T (Child) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::FORM_FILLING);
    }

    public function testValueOfNonSignatureFieldIsNotASignature(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => SyntheticPdf::signature(1),
            7 => '<< /FT /Tx /T (Text1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testInlineSignatureDictionaryIsActive(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            7 => '<< /FT /Sig /T (Signature1) /V ' . SyntheticPdf::signature(1) . ' >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureWithoutDocMdpIsActiveButDoesNotCertify(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R 8 0 R] >> >>',
            5 => SyntheticPdf::signature(null),
            6 => SyntheticPdf::signature(null),
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
            8 => '<< /FT /Sig /T (Signature2) /V 6 0 R >>',
        ]));

        $this->assertInventory($inventory, 2, 0, null);
    }

    public function testIndirectReferenceAndTransformParamsAreResolved(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => '<< /Type /Sig /Reference [8 0 R] >>',
            8 => '<< /Type /SigRef /TransformMethod /DocMDP /TransformParams 9 0 R >>',
            9 => '<< /Type /TransformParams /P 1 /V /1.2 >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testDocumentTimestampIsCountedAsSignature(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => '<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 >>',
            6 => '<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 >>',
            7 => '<< /FT /Sig /T (Timestamp1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 1, null);
    }

    public function testFieldCycleDoesNotLoopForever(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
            5 => SyntheticPdf::signature(1),
            6 => '<< /FT /Sig /T (Parent) /Kids [7 0 R] >>',
            7 => '<< /Parent 6 0 R /T (Child) /V 5 0 R /Kids [6 0 R] >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureDroppedByIncrementalUpdateBecomesOrphaned(): void
    {
        $signed = SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => SyntheticPdf::signature(1),
        ]);

        $inventory = $this->reader->readFromString(SyntheticPdf::incrementalUpdate($signed, [
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testSignatureAddedByIncrementalUpdateIsActive(): void
    {
        $unsigned = SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']);

        $inventory = $this->reader->readFromString(SyntheticPdf::incrementalUpdate($unsigned, [
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => SyntheticPdf::signature(1),
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testObjectsInsideCompressedObjectStreamAreFollowed(): void
    {
        $inventory = $this->reader->readFromString(SyntheticPdf::withObjectStream(
            [5 => SyntheticPdf::signature(1), 6 => SyntheticPdf::signature(2)],
            [
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R >>',
                7 => '<< /Fields [8 0 R] >>',
                8 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
            ],
        ));

        $this->assertInventory($inventory, 1, 1, DocMdpPermission::NO_CHANGES);
    }

    public function testRealJSignPdfCertificationIsActive(): void
    {
        $inventory = $this->reader->readFromString($this->fixture('real_jsignpdf_level1.pdf'));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testRealSignedPdfHasOneActiveSignature(): void
    {
        $inventory = $this->reader->readFromString($this->fixture('small_valid-signed.pdf'));

        $this->assertTrue($inventory->isConclusive);
        $this->assertSame(1, $inventory->activeSignatureCount);
        $this->assertSame(0, $inventory->orphanedSignatureCount);
    }

    public function testRealUnsignedPdfHasNoSignatures(): void
    {
        $inventory = $this->reader->readFromString($this->fixture('small_valid.pdf'));

        $this->assertInventory($inventory, 0, 0, null);
    }

    public function testRealCertificationFollowedByApprovalIsConclusive(): void
    {
        $inventory = $this->reader->readFromString($this->fixture('real_pyhanko_certification_then_approval.pdf'));

        $this->assertInventory($inventory, 2, 0, DocMdpPermission::FORM_FILLING);
    }

    /**
     * pyHanko refuses to certify after an approval, so this file was signed
     * with that guard turned off.
     */
    public function testRealCertificationAfterApprovalIsInconclusive(): void
    {
        $inventory = $this->reader->readFromString($this->fixture('real_pyhanko_approval_then_certification.pdf'));

        $this->assertFalse($inventory->isConclusive);
    }

    /**
     * @return array<string, array{string, int, ?DocMdpPermission}>
     */
    public static function omittedOrNullEntryProvider(): array
    {
        return [
            'AcroForm omitted' => [SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']), 0, null],
            'AcroForm explicitly null' => [SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm null >>']), 0, null],
            'signature value omitted' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    7 => '<< /FT /Sig /T (Signature1) >>',
                ]),
                0,
                null,
            ],
            'signature value explicitly null' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    7 => '<< /FT /Sig /T (Signature1) /V null >>',
                ]),
                0,
                null,
            ],
            'signature value is an indirect null object' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    5 => 'null',
                    7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
                ]),
                0,
                null,
            ],
            'valid signature reference' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    5 => SyntheticPdf::signature(1),
                    7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
                ]),
                1,
                DocMdpPermission::NO_CHANGES,
            ],
        ];
    }

    #[DataProvider('omittedOrNullEntryProvider')]
    public function testNullEntryIsTheSameAsAnOmittedOne(string $pdf, int $active, ?DocMdpPermission $permission): void
    {
        $this->assertInventory($this->reader->readFromString($pdf), $active, 0, $permission);
    }

    /**
     * Each PDF holds one active P=1 certification.
     *
     * @return array<string, array{string}>
     */
    public static function signatureArrayRepresentationProvider(): array
    {
        $field = '<< /FT /Sig /T (Signature1) /V 5 0 R >>';
        $parent = '<< /FT /Sig /T (Parent) /Kids %s >>';
        $child = '<< /Parent 6 0 R /T (Child) /V 5 0 R >>';
        $certification = '<< /Type /Sig /Reference %s >>';
        $perms = '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>';

        return [
            'direct Fields array' => [SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                5 => SyntheticPdf::signature(1),
                7 => $field,
            ])],
            'indirect Fields array' => [SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields 9 0 R >> >>',
                5 => SyntheticPdf::signature(1),
                7 => $field,
                9 => '[7 0 R]',
            ])],
            'direct Kids array' => [SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
                5 => SyntheticPdf::signature(1),
                6 => sprintf($parent, '[7 0 R]'),
                7 => $child,
            ])],
            'indirect Kids array' => [SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
                5 => SyntheticPdf::signature(1),
                6 => sprintf($parent, '9 0 R'),
                7 => $child,
                9 => '[7 0 R]',
            ])],
            'direct Reference array' => [SyntheticPdf::pdf([
                1 => $perms,
                5 => sprintf($certification, '[8 0 R]'),
                8 => self::DOC_MDP_REFERENCE,
            ])],
            'indirect Reference array' => [SyntheticPdf::pdf([
                1 => $perms,
                5 => sprintf($certification, '9 0 R'),
                8 => self::DOC_MDP_REFERENCE,
                9 => '[8 0 R]',
            ])],
        ];
    }

    #[DataProvider('signatureArrayRepresentationProvider')]
    public function testDirectAndIndirectArraysAreRead(string $pdf): void
    {
        $this->assertInventory($this->reader->readFromString($pdf), 1, 0, DocMdpPermission::NO_CHANGES);
    }

    /**
     * Every signature is applied in its own incremental revision, so its
     * /ByteRange covers the file up to that revision.
     *
     * @return array<string, array{string, bool, int, int, ?DocMdpPermission}>
     */
    public static function docMdpCertificationStructureProvider(): array
    {
        $unsigned = SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']);
        $catalog = '<< /Type /Catalog /Pages 2 0 R %s /AcroForm << /Fields [%s] >> >>';

        return [
            'certification first, approval second' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R'),
                        5 => SyntheticPdf::signature(2),
                        7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R 8 0 R'),
                        6 => SyntheticPdf::signature(null),
                        8 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
                    ],
                ),
                true, 2, 0, DocMdpPermission::FORM_FILLING,
            ],
            'approval first, certification second' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '', '7 0 R'),
                        5 => SyntheticPdf::signature(null),
                        7 => '<< /FT /Sig /T (Approval) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 6 0 R >>', '7 0 R 8 0 R'),
                        6 => SyntheticPdf::signature(2),
                        8 => '<< /FT /Sig /T (Certification) /V 6 0 R >>',
                    ],
                ),
                false, 0, 0, null,
            ],
            'two active DocMDP certifications' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R'),
                        5 => SyntheticPdf::signature(2),
                        7 => '<< /FT /Sig /T (Certification1) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 6 0 R >>', '7 0 R 8 0 R'),
                        6 => SyntheticPdf::signature(2),
                        8 => '<< /FT /Sig /T (Certification2) /V 6 0 R >>',
                    ],
                ),
                false, 0, 0, null,
            ],
            'certification first, with a higher object number and listed last' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '/Perms << /DocMDP 9 0 R >>', '8 0 R'),
                        8 => '<< /FT /Sig /T (Certification) /V 9 0 R >>',
                        9 => SyntheticPdf::signature(2),
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 9 0 R >>', '7 0 R 8 0 R'),
                        5 => SyntheticPdf::signature(null),
                        7 => '<< /FT /Sig /T (Approval) /V 5 0 R >>',
                    ],
                ),
                true, 2, 0, DocMdpPermission::FORM_FILLING,
            ],
            'approval first, with a higher object number and listed last' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '', '8 0 R'),
                        8 => '<< /FT /Sig /T (Approval) /V 9 0 R >>',
                        9 => SyntheticPdf::signature(null),
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R 8 0 R'),
                        5 => SyntheticPdf::signature(2),
                        7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                    ],
                ),
                false, 0, 0, null,
            ],
            'orphaned P=1 dictionary and active approval' => [
                SyntheticPdf::incrementalUpdate(
                    SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>', 5 => SyntheticPdf::signature(1)]),
                    [
                        1 => sprintf($catalog, '', '7 0 R'),
                        6 => SyntheticPdf::signature(null),
                        7 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
                    ],
                ),
                true, 1, 1, null,
            ],
        ];
    }

    #[DataProvider('docMdpCertificationStructureProvider')]
    public function testDocMdpCertificationStructure(
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

    /**
     * A certification (P=2) in the first revision and an approval in the
     * second, with the approval's /ByteRange changed in place.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function byteRangeStructureProvider(): array
    {
        $catalog = '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [%s] >> >>';
        $pdf = SyntheticPdf::incrementalUpdate(
            SyntheticPdf::incrementalUpdate(SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']), [
                1 => sprintf($catalog, '7 0 R'),
                5 => SyntheticPdf::signature(2),
                7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
            ]),
            [
                1 => sprintf($catalog, '7 0 R 8 0 R'),
                6 => SyntheticPdf::signature(null),
                8 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
            ],
        );

        return [
            'valid ranges' => [$pdf, true, 2, DocMdpPermission::FORM_FILLING],
            'approval range ends after the file' => [
                SyntheticPdf::changeLastByteRange($pdf, static fn (array $range): array => [
                    $range[0], $range[1], $range[2], $range[3] + 1,
                ]),
                false, 0, null,
            ],
            'approval ranges overlap' => [
                SyntheticPdf::changeLastByteRange($pdf, static fn (array $range): array => [
                    $range[0], $range[1], $range[1] - 1, $range[3],
                ]),
                false, 0, null,
            ],
        ];
    }

    #[DataProvider('byteRangeStructureProvider')]
    public function testByteRangeStructure(string $pdf, bool $conclusive, int $active, ?DocMdpPermission $permission): void
    {
        $this->assertReading($pdf, $conclusive, $active, $permission);
    }

    /**
     * One active certification with each /P value. ISO 32000-1, table 254:
     * the valid values are 1, 2 and 3, and the default is 2.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function docMdpPermissionValidationProvider(): array
    {
        $certified = static fn (string $entry): string => SyntheticPdf::certifiedPdf(
            SyntheticPdf::signatureWithReferences([SyntheticPdf::docMdpReference($entry)]),
        );

        return [
            'P 1' => [$certified('/P 1'), true, 1, DocMdpPermission::NO_CHANGES],
            'P 2' => [$certified('/P 2'), true, 1, DocMdpPermission::FORM_FILLING],
            'P 3' => [$certified('/P 3'), true, 1, DocMdpPermission::FORM_FILLING_AND_ANNOTATIONS],
            'P omitted' => [$certified(''), true, 1, DocMdpPermission::FORM_FILLING],
            'P null' => [$certified('/P null'), true, 1, DocMdpPermission::FORM_FILLING],
            'P 2.9' => [$certified('/P 2.9'), false, 0, null],
            'P 4' => [$certified('/P 4'), false, 0, null],
            'P is the name /2' => [$certified('/P /2'), false, 0, null],
        ];
    }

    #[DataProvider('docMdpPermissionValidationProvider')]
    public function testDocMdpPermissionValidation(
        string $pdf,
        bool $conclusive,
        int $active,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertReading($pdf, $conclusive, $active, $permission);
    }

    /**
     * ISO 32000-1, 12.8.1, asks a certification for "a signature reference
     * dictionary (see Table 253) that has a DocMDP transform method" and sets
     * no precedence between two of them.
     *
     * @return array<string, array{string, bool, int, ?DocMdpPermission}>
     */
    public static function docMdpReferenceMultiplicityProvider(): array
    {
        $certified = static fn (int ...$permissions): string => SyntheticPdf::certifiedPdf(SyntheticPdf::signatureWithReferences(
            array_map(static fn (int $permission): string => SyntheticPdf::docMdpReference('/P ' . $permission), $permissions),
        ));

        return [
            'one DocMDP transform' => [$certified(2), true, 1, DocMdpPermission::FORM_FILLING],
            'two DocMDP transforms that agree' => [$certified(2, 2), true, 1, DocMdpPermission::FORM_FILLING],
            'P 3 then P 1' => [$certified(3, 1), false, 0, null],
            'P 1 then P 3' => [$certified(1, 3), false, 0, null],
        ];
    }

    #[DataProvider('docMdpReferenceMultiplicityProvider')]
    public function testDocMdpReferenceMultiplicity(
        string $pdf,
        bool $conclusive,
        int $active,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertReading($pdf, $conclusive, $active, $permission);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unreadableStructureProvider(): array
    {
        return [
            'not a PDF' => ['not a pdf'],
            'catalog object is missing' => [SyntheticPdf::pdf([4 => '<< /Type /Catalog /Pages 2 0 R >>'])],
            'referenced signature is missing' => [
                SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 9 0 R >> >>']),
            ],
            'field list is not an array' => [
                SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields /None >> >>']),
            ],
            'signature reference is not an array' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
                    5 => '<< /Type /Sig /Reference /None >>',
                ]),
            ],
            'field entry is not a dictionary' => [
                SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [/None] >> >>']),
            ],
            'signature value is an indirect number' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    5 => '42',
                    7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
                ]),
            ],
            'indirect field list is not an array' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields 9 0 R >> >>',
                    9 => '<< /Type /Annot >>',
                ]),
            ],
            'signature byte range is not an array of integers' => [
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >>'
                        . ' /AcroForm << /Fields [7 0 R 8 0 R] >> >>',
                    5 => SyntheticPdf::signature(2),
                    6 => '<< /Type /Sig /ByteRange /None >>',
                    7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                    8 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
                ]),
            ],
        ];
    }

    #[DataProvider('unreadableStructureProvider')]
    public function testUnreadableStructureIsInconclusive(string $content): void
    {
        $inventory = $this->reader->readFromString($content);

        $this->assertFalse($inventory->isConclusive);
        $this->assertSame(0, $inventory->activeSignatureCount);
        $this->assertSame(0, $inventory->orphanedSignatureCount);
        $this->assertNull($inventory->docMdpPermission);
    }

    public function testReadsFromResource(): void
    {
        $resource = fopen('php://memory', 'r+b');
        if ($resource === false) {
            throw new RuntimeException('Could not open a memory stream.');
        }

        fwrite($resource, SyntheticPdf::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => SyntheticPdf::signature(1),
        ]));

        $inventory = $this->reader->readFromResource($resource);
        fclose($resource);

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    private function assertInventory(
        SignatureInventory $inventory,
        int $active,
        int $orphaned,
        ?DocMdpPermission $permission,
    ): void {
        $this->assertTrue($inventory->isConclusive);
        $this->assertSame($active, $inventory->activeSignatureCount);
        $this->assertSame($orphaned, $inventory->orphanedSignatureCount);
        $this->assertSame($permission, $inventory->docMdpPermission);
    }

    private function assertReading(string $pdf, bool $conclusive, int $active, ?DocMdpPermission $permission): void
    {
        $inventory = $this->reader->readFromString($pdf);

        $this->assertSame($conclusive, $inventory->isConclusive);
        $this->assertSame($active, $inventory->activeSignatureCount);
        $this->assertSame($permission, $inventory->docMdpPermission);
    }

    private function fixture(string $name): string
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/' . $name);
        if ($content === false) {
            throw new RuntimeException('Could not read fixture ' . $name);
        }

        return $content;
    }
}
