<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\TestCase;

final class PdfSignatureExtractorTest extends TestCase
{
    public function testThrowsUnsignedPdfExceptionWhenNoSignatureFound(): void
    {
        $extractor = new PdfSignatureExtractor();
        $this->expectException(UnsignedPdfException::class);
        $extractor->extractFromString('%PDF-1.6\n1 0 obj\n<<>>\nendobj');
    }

    public function testExtractsFieldRangeAndSignatureType(): void
    {
        $extractor = new PdfSignatureExtractor();
        $pdf = $this->buildSignedPdfFixture('ABCD', '/adbe.pkcs7.detached', 'Signature1', [0, 10, 20, 30]);

        $result = $extractor->extractFromString($pdf);
        $this->assertCount(1, $result);
        $this->assertSame("\xAB\xCD", $result[0]->binarySignature);
        $this->assertSame('Signature1', $result[0]->metadata->field);
        $this->assertSame('adbe.pkcs7.detached', $result[0]->metadata->signatureType);
        $this->assertSame([
            'offset1' => 0,
            'length1' => 10,
            'offset2' => 20,
            'length2' => 50,
        ], $result[0]->metadata->range);
    }

    public function testExtractsOnlyUniqueSignatureContents(): void
    {
        $extractor = new PdfSignatureExtractor();
        $pdf = "%PDF-1.6\n"
            . "1 0 obj\n<< /Type /Sig /SubFilter /adbe.pkcs7.detached /ByteRange [0 10 20 30] /T (Sig1) /Contents <ABCD> >>\nendobj\n"
            . "2 0 obj\n<< /Type /Sig /SubFilter /adbe.pkcs7.detached /ByteRange [0 10 20 30] /T (Sig2) /Contents <ABCD> >>\nendobj\n";

        $result = $extractor->extractFromString($pdf);
        $this->assertCount(1, $result);
    }

    public function testMarksCoversEntireDocumentWhenSecondRangeEndsAtFileEnd(): void
    {
        $extractor = new PdfSignatureExtractor();
        // Build fixture first to measure its length, then pick length2 = fileSize - offset2.
        // The fixture header is 131 bytes + 400 Xs payload = 531 bytes total.
        // offset2=20 → length2 must be 531-20=511 so that offset2+length2 == fileSize.
        $pdf = $this->buildSignedPdfFixture('ABCD', '/adbe.pkcs7.detached', 'Signature1', [0, 10, 20, 511]);
        $this->assertSame(531, strlen($pdf), 'Fixture size changed – update length2 to fileSize-offset2');
        $result = $extractor->extractFromString($pdf);
        $this->assertTrue($result[0]->metadata->coversEntireDocument);
    }

    private function buildSignedPdfFixture(string $hexSignature, string $subFilter, string $field, array $range): string
    {
        [$offset1, $length1, $offset2, $length2] = $range;
        $payload = str_repeat('X', 400);
        return "%PDF-1.6\n"
            . "1 0 obj\n<< /Type /Sig /SubFilter {$subFilter} /ByteRange [{$offset1} {$length1} {$offset2} {$length2}] /T ({$field}) /Contents <{$hexSignature}> >>\nendobj\n"
            . $payload;
    }
}
