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

    public function testMostRestrictiveActivePermissionWins(): void
    {
        $inventory = $this->reader->readFromString(self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R 8 0 R] >> >>',
            5 => self::signature(3),
            6 => self::signature(1),
            7 => '<< /FT /Sig /T (Signature1) /V 5 0 R >>',
            8 => '<< /FT /Sig /T (Signature2) /V 6 0 R >>',
        ]));

        $this->assertInventory($inventory, 2, 0, DocMdpPermission::NO_CHANGES);
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

        $inventory = $this->reader->readFromString($this->incrementalUpdate($signed, [
            1 => '<< /Type /Catalog /Pages 2 0 R >>',
        ]));

        $this->assertInventory($inventory, 0, 1, null);
    }

    public function testSignatureAddedByIncrementalUpdateIsActive(): void
    {
        $unsigned = self::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>']);

        $inventory = $this->reader->readFromString($this->incrementalUpdate($unsigned, [
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
        $dictionary = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached'
            . ' /ByteRange [0 0 0 0] /Contents <00>';

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

        return $pdf . "trailer\n<< /Size $size /Root 1 0 R >>\nstartxref\n$xrefOffset\n%%EOF\n";
    }

    /**
     * Appends a revision that replaces or adds the given objects.
     *
     * @param array<int, string> $objects
     */
    private function incrementalUpdate(string $pdf, array $objects): string
    {
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

        return $pdf . $xref
            . "trailer\n<< /Size $size /Root 1 0 R /Prev $previous >>\nstartxref\n$xrefOffset\n%%EOF\n";
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
