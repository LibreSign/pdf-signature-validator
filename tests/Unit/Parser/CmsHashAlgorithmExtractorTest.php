<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\CmsHashAlgorithmExtractor;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CmsHashAlgorithmExtractorTest extends TestCase
{
    public function testReturnsNullForInvalidCmsPayload(): void
    {
        $extractor = new CmsHashAlgorithmExtractor();
        $this->assertNull($extractor->extract('not-der'));
    }

    #[DataProvider('signedPdfProvider')]
    public function testExtractsAlgorithmFromPdfSignature(string $fixture): void
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/' . $fixture);
        $this->assertIsString($content);

        $signatures = (new PdfSignatureExtractor())->extractFromString($content);

        $this->assertCount(1, $signatures);
        $this->assertSame('SHA-256', (new CmsHashAlgorithmExtractor())->extract($signatures[0]->binarySignature));
    }

    public static function signedPdfProvider(): array
    {
        return [
            'small signed PDF' => ['small_valid-signed.pdf'],
            'JSignPDF signed PDF' => ['real_jsignpdf_level1.pdf'],
        ];
    }
}
