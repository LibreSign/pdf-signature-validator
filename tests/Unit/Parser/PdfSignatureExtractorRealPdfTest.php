<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdfSignatureExtractorRealPdfTest extends TestCase
{
    #[DataProvider('signedPdfProvider')]
    public function testExtractsExpectedMetadataFromRealSignedPdf(
        string $fixture,
        string $expectedField,
        string $expectedSignatureType,
        string $expectedHashAlgorithm,
    ): void {
        $extractor = new PdfSignatureExtractor();

        $content = file_get_contents($this->fixturePath($fixture));
        $this->assertIsString($content);

        $signatures = $extractor->extractFromString($content);

        // Business rule: any signed PDF must yield at least one signature.
        $this->assertNotEmpty($signatures, $fixture);

        $leaf = $signatures[0];
        $this->assertSame($expectedField, $leaf->metadata->field, $fixture);
        $this->assertSame($expectedSignatureType, $leaf->metadata->signatureType, $fixture);
        $this->assertSame($expectedHashAlgorithm, $leaf->hashAlgorithm, $fixture);

        // Business rule parity with Poppler's "Total document signed" for our corpus.
        $this->assertTrue($leaf->metadata->coversEntireDocument, $fixture);
    }

    public function testThrowsUnsignedExceptionForRealUnsignedPdf(): void
    {
        $extractor = new PdfSignatureExtractor();

        $content = file_get_contents($this->fixturePath('small_valid.pdf'));
        $this->assertIsString($content);

        $this->expectException(UnsignedPdfException::class);
        $extractor->extractFromString($content);
    }

    /**
     * @return iterable<string, array{0:string,1:string,2:string,3:string}>
     */
    public static function signedPdfProvider(): iterable
    {
        yield 'real_jsignpdf_level1' => [
            'real_jsignpdf_level1.pdf',
            'Signature1',
            'adbe.pkcs7.detached',
            'SHA-256',
        ];

        yield 'small_valid_signed' => [
            'small_valid-signed.pdf',
            'Signature1',
            'adbe.pkcs7.detached',
            'SHA-256',
        ];
    }

    private function fixturePath(string $file): string
    {
        return __DIR__ . '/../../Fixtures/pdfs/' . $file;
    }
}
