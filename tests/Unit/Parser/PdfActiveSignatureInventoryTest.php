<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\DocMdpValidationDataInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class PdfActiveSignatureInventoryTest extends TestCase
{
    /**
     * @return iterable<string, array{string, int, int, ?DocMdpPermission, list<int>}>
     */
    public static function referencedSignatureCases(): iterable
    {
        $certified = SyntheticPdf::certifiedPdf(SyntheticPdf::signature(1));
        $orphan = SyntheticPdf::signature(2);

        yield 'orphan only' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R >>',
                5 => SyntheticPdf::signature(1),
            ]), 0, 1, null, [],
        ];
        yield 'orphan without optional Type entry' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R >>',
                5 => str_replace('/Type /Sig ', '', SyntheticPdf::signature(1)),
            ]), 0, 1, null, [],
        ];
        yield 'active certification without optional Type entry' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
                5 => str_replace('/Type /Sig ', '', SyntheticPdf::signature(1)),
                7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
            ]), 1, 0, DocMdpPermission::NO_CHANGES, [5],
        ];
        yield 'unrelated object with ByteRange but no Contents is not a signature' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R >>',
                5 => '<< /Filter /Adobe.PPKLite /ByteRange [0 1 2 3] >>',
            ]), 0, 0, null, [],
        ];
        yield 'orphan with lower object number before active certifier' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
                4 => $orphan,
                5 => SyntheticPdf::signature(1),
                7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
            ]), 1, 1, DocMdpPermission::NO_CHANGES, [5],
        ];
        yield 'orphan with higher object number after active certifier' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
                5 => SyntheticPdf::signature(1),
                7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                9 => $orphan,
            ]), 1, 1, DocMdpPermission::NO_CHANGES, [5],
        ];
        yield 'orphan inserted after certification in a later revision' => [
            SyntheticPdf::incrementalUpdate($certified, [9 => $orphan]),
            1, 1, DocMdpPermission::NO_CHANGES, [5],
        ];
        yield 'orphan before a later certification revision' => [
            SyntheticPdf::incrementalUpdate(
                SyntheticPdf::pdf([
                    1 => '<< /Type /Catalog /Pages 2 0 R >>',
                    4 => $orphan,
                ]),
                [
                    1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
                    5 => SyntheticPdf::signature(1),
                    7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
                ],
            ), 1, 1, DocMdpPermission::NO_CHANGES, [5],
        ];
        yield 'two active approval signatures' => [
            SyntheticPdf::pdf([
                1 => '<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [8 0 R 7 0 R] >> >>',
                5 => SyntheticPdf::signature(null),
                6 => SyntheticPdf::signature(null),
                7 => '<< /FT /Sig /T (First) /V 5 0 R >>',
                8 => '<< /FT /Sig /T (Second) /V 6 0 R >>',
            ]), 2, 0, null, [6, 5],
        ];
    }

    #[DataProvider('referencedSignatureCases')]
    public function testPublicDetailsNeverContainOrphans(
        string $pdf,
        int $active,
        int $orphans,
        ?DocMdpPermission $permission,
        array $objectNumbers,
    ): void {
        $inventory = (new PdfSignatureInventoryReader())->readFromString($pdf);

        self::assertTrue($inventory->isConclusive);
        self::assertSame($active, $inventory->activeSignatureCount);
        self::assertSame($orphans, $inventory->orphanedSignatureCount);
        self::assertSame($permission, $inventory->docMdpPermission);
        self::assertCount($active, $inventory->activeSignatures);
        self::assertSame(
            $objectNumbers,
            array_map(static fn (ActiveSignature $signature): ?int => $signature->objectNumber, $inventory->activeSignatures),
        );

        foreach ($inventory->activeSignatures as $signature) {
            self::assertSame(0, $signature->byteRanges[0]['offset']);
            self::assertGreaterThan(0, $signature->signedRevisionEnd);
            self::assertLessThanOrEqual(strlen($pdf), $signature->signedRevisionEnd);
            self::assertSame(
                $signature->signedRevisionEnd,
                $signature->byteRanges[array_key_last($signature->byteRanges)]['offset']
                    + $signature->byteRanges[array_key_last($signature->byteRanges)]['length'],
            );
        }
    }

    public function testRealMultiSignatureOrderAndCertificationIdentity(): void
    {
        $inventory = $this->readFixture('pdfs/real_pyhanko_certification_then_approval.pdf');

        self::assertTrue($inventory->isConclusive);
        self::assertSame(2, $inventory->activeSignatureCount);
        self::assertSame(0, $inventory->orphanedSignatureCount);
        self::assertSame(DocMdpPermission::FORM_FILLING, $inventory->docMdpPermission);
        self::assertCount(2, $inventory->activeSignatures);
        self::assertTrue($inventory->activeSignatures[0]->isCertifying);
        self::assertFalse($inventory->activeSignatures[1]->isCertifying);
        self::assertLessThan(
            $inventory->activeSignatures[1]->signedRevisionEnd,
            $inventory->activeSignatures[0]->signedRevisionEnd,
        );
    }

    public function testRealDocumentTimestampIsNotAnOrphan(): void
    {
        $inventory = $this->readFixture('docmdp/pyhanko-p1-timestamp.pdf');

        self::assertTrue($inventory->isConclusive);
        self::assertSame(2, $inventory->activeSignatureCount);
        self::assertSame(0, $inventory->orphanedSignatureCount);
        self::assertTrue($inventory->activeSignatures[0]->isCertifying);
        self::assertFalse($inventory->activeSignatures[0]->isDocumentTimestamp);
        self::assertTrue($inventory->activeSignatures[1]->isDocumentTimestamp);
        self::assertLessThan(
            $inventory->activeSignatures[1]->signedRevisionEnd,
            $inventory->activeSignatures[0]->signedRevisionEnd,
        );
    }

    public function testDssDoesNotInventExtraSignedRevisions(): void
    {
        $path = __DIR__ . '/../../Fixtures/docmdp/pyhanko-p1-dss.pdf';
        $content = file_get_contents($path);
        self::assertIsString($content);
        $inventory = (new PdfSignatureInventoryReader())->readFromString($content);

        self::assertTrue($inventory->isConclusive);
        self::assertCount(1, $inventory->activeSignatures);
        self::assertLessThan(strlen($content), $inventory->activeSignatures[0]->signedRevisionEnd);
        self::assertTrue(
            (new DocMdpValidationDataInspector())->hasOnlyValidationDataUpdates(
                $content,
                $inventory->activeSignatures[0]->signedRevisionEnd,
            ),
        );
    }

    public function testDisallowedCatalogChangeStillRejectedBesideDss(): void
    {
        $path = __DIR__ . '/../../Fixtures/docmdp/pyhanko-p1-dss-action.pdf';
        $content = file_get_contents($path);
        self::assertIsString($content);
        $inventory = (new PdfSignatureInventoryReader())->readFromString($content);

        self::assertTrue($inventory->isConclusive);
        self::assertCount(1, $inventory->activeSignatures);
        self::assertFalse(
            (new DocMdpValidationDataInspector())->hasOnlyValidationDataUpdates(
                $content,
                $inventory->activeSignatures[0]->signedRevisionEnd,
            ),
        );
    }

    /**
     * An unreferenced /Sig containing its own DocMDP /Reference is ignored:
     * pyHanko 0.38.2 independently reports only the actual signature field(s).
     *
     * @return iterable<string,array{string,int}>
     */
    public static function realOrphanWithValidationData(): iterable
    {
        yield 'orphan and legitimate DSS' => ['pyhanko-p1-orphan-dss.pdf', 1];
        yield 'orphan and legitimate document timestamp' => ['pyhanko-p1-orphan-timestamp.pdf', 2];
    }

    #[DataProvider('realOrphanWithValidationData')]
    public function testRealOrphanDoesNotAffectCertificationOrLtaException(
        string $file,
        int $active,
    ): void {
        $path = __DIR__ . '/../../Fixtures/docmdp/' . $file;
        $content = file_get_contents($path);
        self::assertIsString($content);

        $inventory = (new PdfSignatureInventoryReader())->readFromString($content);

        self::assertTrue($inventory->isConclusive);
        self::assertSame($active, $inventory->activeSignatureCount);
        self::assertSame(1, $inventory->orphanedSignatureCount);
        self::assertSame(DocMdpPermission::NO_CHANGES, $inventory->docMdpPermission);
        self::assertCount($active, $inventory->activeSignatures);
        self::assertTrue($inventory->activeSignatures[0]->isCertifying);
        self::assertLessThan(strlen($content), $inventory->activeSignatures[0]->signedRevisionEnd);

        if ($active === 2) {
            self::assertTrue($inventory->activeSignatures[1]->isDocumentTimestamp);
        }

        self::assertTrue(
            (new DocMdpValidationDataInspector())->hasOnlyValidationDataUpdates(
                $content,
                $inventory->activeSignatures[0]->signedRevisionEnd,
            ),
        );
    }

    /** @return iterable<string,array{string}> */
    public static function invalidSignedByteRanges(): iterable
    {
        yield 'missing Contents gap' => ['[0 0]'];
        yield 'empty signed ranges' => ['[0 0 0 0]'];
        yield 'nonzero first offset' => ['[1 1 4 1]'];
        yield 'second signed span has zero length' => ['[0 1 4 0]'];
    }

    #[DataProvider('invalidSignedByteRanges')]
    public function testMalformedActiveSignedRangeIsInconclusive(string $range): void
    {
        $signature = str_replace(
            SyntheticPdf::SIGNED_BYTES,
            '/ByteRange ' . $range . ' /Contents <0000>',
            SyntheticPdf::signature(1),
        );
        $pdf = SyntheticPdf::certifiedPdf($signature);
        $inventory = (new PdfSignatureInventoryReader())->readFromString($pdf);

        self::assertFalse($inventory->isConclusive);
        self::assertSame([], $inventory->activeSignatures);
        self::assertNull($inventory->docMdpPermission);
    }

    public function testUnparseableSignatureNeverBecomesConclusive(): void
    {
        $content = SyntheticPdf::certifiedPdf(SyntheticPdf::signature(1));
        $content = SyntheticPdf::changeLastByteRange($content, static fn (array $range): array => [
            $range[0], $range[1], $range[2], $range[3] + 1,
        ]);
        $inventory = (new PdfSignatureInventoryReader())->readFromString($content);

        self::assertFalse($inventory->isConclusive);
        self::assertSame(0, $inventory->activeSignatureCount);
        self::assertSame([], $inventory->activeSignatures);
        self::assertNull($inventory->docMdpPermission);
    }

    private function readFixture(string $name): \LibreSign\PdfSignatureValidator\Model\SignatureInventory
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/' . $name);
        if ($content === false) {
            throw new RuntimeException('Missing fixture ' . $name);
        }

        return (new PdfSignatureInventoryReader())->readFromString($content);
    }
}
