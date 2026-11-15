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
    private const PAGES = [
        2 => '<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
        3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] >>',
    ];

    private const DOC_MDP_REFERENCE = '<< /Type /SigRef /TransformMethod /DocMDP'
        . ' /TransformParams << /Type /TransformParams /P 1 /V /1.2 >> >>';

    /** Filled in by fillByteRanges() once the revision is written. */
    private const BYTE_RANGE_PLACEHOLDER = '/ByteRange [0 0000000000 0000000000 0000000000]';

    private PdfSignatureInventoryReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PdfSignatureInventoryReader();
    }

    public function testUnsignedPdfHasNoSignatures(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']));

        $this->assertInventory($inventory, 0, 0, null);
    }

    public function testUnreferencedCertificationSignatureIsOrphaned(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
            5 => self::signature(1),
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testCertificationReferencedFromPermsAndFieldIsActive(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm 6 0 R >>',
            5 => self::signature(1),
            6 => '<< /Fields [7 0 R] /SigFlags 3 >>',
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testCertificationReferencedOnlyFromPermsIsActive(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => self::signature(3),
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::FORM_FILLING_AND_ANNOTATIONS);
    }

    public function testCertificationReferencedOnlyFromFieldIsActive(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => self::signature(1),
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureFieldTypeIsInheritedFromParentField(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
            5 => self::signature(2),
            6 => '<< /FT /Sig /T (Parent) /Kids [7 0 R] >>',
            7 => '<< /Parent 6 0 R /T (Child) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::FORM_FILLING);
    }

    public function testValueOfNonSignatureFieldIsNotASignature(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => self::signature(1),
            7 => '<< /FT /Tx /T (Text1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testInlineSignatureDictionaryIsActive(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            7 => '<< /FT /Sig /T (Signature1) /V ' . self::signature(1) . ' >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureWithoutDocMdpIsActiveButDoesNotCertify(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R 8 0 R] >> >>',
            5 => self::signature(null),
            6 => self::signature(null),
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
            8 => '<< /FT /Sig /T (Signature2) /V 6 0 R >>',
        ]));

        $this->assertInventory($inventory, 2, 0, null);
    }

    public function testMissingPermissionDefaultsToFormFilling(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => '<< /Type /Sig /Reference [<< /Type /SigRef /TransformMethod /DocMDP'
                . ' /TransformParams << /Type /TransformParams /V /1.2 >> >>] >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::FORM_FILLING);
    }

    public function testIndirectReferenceAndTransformParamsAreResolved(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => '<< /Type /Sig /Reference [8 0 R] >>',
            8 => '<< /Type /SigRef /TransformMethod /DocMDP /TransformParams 9 0 R >>',
            9 => '<< /Type /TransformParams /P 1 /V /1.2 >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testDocumentTimestampIsCountedAsSignature(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
            5 => '<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 >>',
            6 => '<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 >>',
            7 => '<< /FT /Sig /T (Timestamp1) /V 5 0 R >>',
        ]));

        $this->assertInventory($inventory, 1, 1, null);
    }

    public function testFieldCycleDoesNotLoopForever(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
            5 => self::signature(1),
            6 => '<< /FT /Sig /T (Parent) /Kids [7 0 R] >>',
            7 => '<< /Parent 6 0 R /T (Child) /V 5 0 R /Kids [6 0 R] >>',
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testSignatureDroppedByIncrementalUpdateBecomesOrphaned(): void
    {
        $signed = self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => self::signature(1),
        ]);

        $inventory = $this->reader->readFromString(self::incrementalUpdate($signed, [
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testSignatureAddedByIncrementalUpdateIsActive(): void
    {
        $unsigned = self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']);

        $inventory = $this->reader->readFromString(self::incrementalUpdate($unsigned, [
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => self::signature(1),
        ]));

        $this->assertInventory($inventory, 1, 0, DocMdpPermission::NO_CHANGES);
    }

    public function testObjectsInsideCompressedObjectStreamAreFollowed(): void
    {
        $inventory = $this->reader->readFromString($this->pdfWithObjectStream(
            [5 => self::signature(1), 6 => self::signature(2)],
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
            'AcroForm omitted' => [self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']), 0, null],
            'AcroForm explicitly null' => [self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm null >>']), 0, null],
            'signature value omitted' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    7 => '<< /FT /Sig /T (Signature1) >>',
                ]),
                0,
                null,
            ],
            'signature value explicitly null' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    7 => '<< /FT /Sig /T (Signature1) /V null >>',
                ]),
                0,
                null,
            ],
            'valid signature reference' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                    5 => self::signature(1),
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
            'direct Fields array' => [self::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] >> >>',
                5 => self::signature(1),
                7 => $field,
            ])],
            'indirect Fields array' => [self::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields 9 0 R >> >>',
                5 => self::signature(1),
                7 => $field,
                9 => '[7 0 R]',
            ])],
            'direct Kids array' => [self::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
                5 => self::signature(1),
                6 => sprintf($parent, '[7 0 R]'),
                7 => $child,
            ])],
            'indirect Kids array' => [self::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>',
                5 => self::signature(1),
                6 => sprintf($parent, '9 0 R'),
                7 => $child,
                9 => '[7 0 R]',
            ])],
            'direct Reference array' => [self::pdf([
                1 => $perms,
                5 => sprintf($certification, '[8 0 R]'),
                8 => self::DOC_MDP_REFERENCE,
            ])],
            'indirect Reference array' => [self::pdf([
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
        $unsigned = self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']);
        $catalog = '<< /Type /Catalog /Pages 2 0 R %s /AcroForm << /Fields [%s] >> >>';

        return [
            'certification first, approval second' => [
                self::incrementalUpdate(
                    self::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R'),
                        5 => self::signature(2),
                        7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R 8 0 R'),
                        6 => self::signature(null),
                        8 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
                    ],
                ),
                true,
                2,
                0,
                DocMdpPermission::FORM_FILLING,
            ],
            'approval first, certification second' => [
                self::incrementalUpdate(
                    self::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '', '7 0 R'),
                        5 => self::signature(null),
                        7 => '<< /FT /Sig /T (Approval) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 6 0 R >>', '7 0 R 8 0 R'),
                        6 => self::signature(2),
                        8 => '<< /FT /Sig /T (Certification) /V 6 0 R >>',
                    ],
                ),
                false,
                0,
                0,
                null,
            ],
            'two active DocMDP certifications' => [
                self::incrementalUpdate(
                    self::incrementalUpdate($unsigned, [
                        1 => sprintf($catalog, '/Perms << /DocMDP 5 0 R >>', '7 0 R'),
                        5 => self::signature(2),
                        7 => '<< /FT /Sig /T (Certification1) /V 5 0 R >>',
                    ]),
                    [
                        1 => sprintf($catalog, '/Perms << /DocMDP 6 0 R >>', '7 0 R 8 0 R'),
                        6 => self::signature(2),
                        8 => '<< /FT /Sig /T (Certification2) /V 6 0 R >>',
                    ],
                ),
                false,
                0,
                0,
                null,
            ],
            'orphaned P=1 dictionary and active approval' => [
                self::incrementalUpdate(
                    self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>', 5 => self::signature(1)]),
                    [
                        1 => sprintf($catalog, '', '7 0 R'),
                        6 => self::signature(null),
                        7 => '<< /FT /Sig /T (Approval) /V 6 0 R >>',
                    ],
                ),
                true,
                1,
                1,
                null,
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
     * @return array<string, array{string}>
     */
    public static function unreadableStructureProvider(): array
    {
        return [
            'not a PDF' => ['not a pdf'],
            'catalog object is missing' => [self::pdf([4 => '<< /Type /Catalog /Pages 2 0 R >>'])],
            'referenced signature is missing' => [
                self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 9 0 R >> >>']),
            ],
            'permission outside 1 to 3' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
                    5 => self::signature(4),
                ]),
            ],
            'field list is not an array' => [
                self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields /None >> >>']),
            ],
            'signature reference is not an array' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
                    5 => '<< /Type /Sig /Reference /None >>',
                ]),
            ],
            'field entry is not a dictionary' => [
                self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [/None] >> >>']),
            ],
            'indirect field list is not an array' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields 9 0 R >> >>',
                    9 => '<< /Type /Annot >>',
                ]),
            ],
            'signature byte range is not an array of integers' => [
                self::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >>'
                        . ' /AcroForm << /Fields [7 0 R 8 0 R] >> >>',
                    5 => self::signature(2),
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

        fwrite($resource, self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>',
            5 => self::signature(1),
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

    private static function signature(?int $permission): string
    {
        $dictionary = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached '
            . self::BYTE_RANGE_PLACEHOLDER . ' /Contents <0000>';

        if ($permission !== null) {
            $dictionary .= ' /Reference [<< /Type /SigRef /TransformMethod /DocMDP'
                . ' /TransformParams << /Type /TransformParams /P ' . $permission . ' /V /1.2 >> >>]';
        }

        return $dictionary . ' >>';
    }

    /**
     * A PDF with a classic cross-reference table. Objects 2 and 3 are the page tree.
     *
     * @param array<int, string> $objects
     */
    private static function pdf(array $objects): string
    {
        $objects += self::PAGES;
        ksort($objects);

        $pdf = "%PDF-1.7\n";
        $offsets = [];
        foreach ($objects as $number => $body) {
            $offsets[$number] = strlen($pdf);
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }

        $size = max(array_keys($objects)) + 1;
        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n0 $size\n0000000000 65535 f \n";
        for ($number = 1; $number < $size; $number++) {
            $pdf .= isset($offsets[$number])
                ? sprintf("%010d 00000 n \n", $offsets[$number])
                : "0000000000 65535 f \n";
        }

        return self::fillByteRanges($pdf . "trailer\n<< /Size $size /Root 1 0 R >>\nstartxref\n$xrefOffset\n%%EOF\n", 0);
    }

    /**
     * Appends a revision that replaces or adds the given objects.
     *
     * @param array<int, string> $objects
     */
    private static function incrementalUpdate(string $pdf, array $objects): string
    {
        $revisionStart = strlen($pdf);
        preg_match_all('/startxref\s+(\d+)/', $pdf, $matches);
        $previous = (int)end($matches[1]);
        preg_match_all('/\/Size (\d+)/', $pdf, $sizes);
        $size = max((int)end($sizes[1]), max(array_keys($objects)) + 1);

        $xref = "xref\n";
        foreach ($objects as $number => $body) {
            $xref .= sprintf("%d 1\n%010d 00000 n \n", $number, strlen($pdf));
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }

        $xrefOffset = strlen($pdf);

        return self::fillByteRanges(
            $pdf . $xref . "trailer\n<< /Size $size /Root 1 0 R /Prev $previous >>\nstartxref\n$xrefOffset\n%%EOF\n",
            $revisionStart,
        );
    }

    /**
     * Fills the /ByteRange placeholders written from $offset on, so each
     * signature covers the whole file except its own /Contents. The numbers
     * keep the placeholder width, so no offset moves.
     */
    private static function fillByteRanges(string $pdf, int $offset): string
    {
        while (($position = strpos($pdf, self::BYTE_RANGE_PLACEHOLDER, $offset)) !== false) {
            $contentsStart = (int)strpos($pdf, '<', (int)strpos($pdf, '/Contents', $position));
            $contentsEnd = (int)strpos($pdf, '>', $contentsStart) + 1;
            $byteRange = sprintf(
                '/ByteRange [0 %010d %010d %010d]',
                $contentsStart,
                $contentsEnd,
                strlen($pdf) - $contentsEnd,
            );
            $pdf = substr_replace($pdf, $byteRange, $position, strlen($byteRange));
            $offset = $position + strlen($byteRange);
        }

        return $pdf;
    }

    /**
     * A PDF 1.5 file whose $compressed objects live in a Flate-encoded object
     * stream, indexed by a cross-reference stream.
     *
     * @param array<int, string> $direct
     * @param array<int, string> $compressed
     */
    private function pdfWithObjectStream(array $direct, array $compressed): string
    {
        $direct += self::PAGES;
        $streamNumber = max(array_keys($direct + $compressed)) + 1;
        $xrefNumber = $streamNumber + 1;

        $pdf = "%PDF-1.5\n";
        $entries = [0 => pack('CNn', 0, 0, 65535)];
        foreach ($direct as $number => $body) {
            $entries[$number] = pack('CNn', 1, strlen($pdf), 0);
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }

        $index = '';
        $bodies = '';
        $position = 0;
        foreach ($compressed as $number => $body) {
            $index .= $number . ' ' . strlen($bodies) . ' ';
            $bodies .= $body . "\n";
            $entries[$number] = pack('CNn', 2, $streamNumber, $position++);
        }

        $data = gzcompress($index . $bodies);
        $entries[$streamNumber] = pack('CNn', 1, strlen($pdf), 0);
        $pdf .= "$streamNumber 0 obj\n<< /Type /ObjStm /N " . count($compressed) . ' /First ' . strlen($index)
            . ' /Filter /FlateDecode /Length ' . strlen($data) . " >>\nstream\n$data\nendstream\nendobj\n";

        $xrefOffset = strlen($pdf);
        $entries[$xrefNumber] = pack('CNn', 1, $xrefOffset, 0);
        ksort($entries);
        $table = '';
        for ($number = 0; $number <= $xrefNumber; $number++) {
            $table .= $entries[$number] ?? pack('CNn', 0, 0, 0);
        }

        $pdf .= "$xrefNumber 0 obj\n<< /Type /XRef /Size " . ($xrefNumber + 1) . ' /W [1 4 2] /Root 1 0 R /Length '
            . strlen($table) . " >>\nstream\n$table\nendstream\nendobj\n";

        return $pdf . "startxref\n$xrefOffset\n%%EOF\n";
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
