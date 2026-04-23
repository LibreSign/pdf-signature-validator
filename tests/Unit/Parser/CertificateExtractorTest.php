<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\CertificateExtractor;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\TestCase;

/**
 * Tests for certificate extraction from PKCS#7/CMS signatures.
 */
final class CertificateExtractorTest extends TestCase
{
    private CertificateExtractor $certificateExtractor;

    protected function setUp(): void
    {
        $this->certificateExtractor = new CertificateExtractor();
    }

    public function testExtractCertificatesFromInvalidSignature(): void
    {
        $result = $this->certificateExtractor->extractCertificates('not a valid pkcs7 signature');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testExtractCertificatesFromEmptySignature(): void
    {
        $result = $this->certificateExtractor->extractCertificates('');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testExtractCertificateSerialFromInvalidSignature(): void
    {
        $result = $this->certificateExtractor->extractCertificateSerial('invalid data');

        $this->assertNull($result);
    }

    public function testExtractCertificatesAndSerialFromRealSignedPdf(): void
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/small_valid-signed.pdf');
        $this->assertIsString($content);

        $pdfExtractor = new PdfSignatureExtractor();
        $signatures = $pdfExtractor->extractFromString($content);
        $this->assertNotEmpty($signatures);

        $binarySignature = $signatures[0]->binarySignature;
        $this->assertIsString($binarySignature);
        $this->assertNotSame('', $binarySignature);

        $certificates = $this->certificateExtractor->extractCertificates($binarySignature);
        $this->assertNotEmpty($certificates);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $certificates[0]);

        $serial = $this->certificateExtractor->extractCertificateSerial($binarySignature);
        $this->assertIsString($serial);
        $this->assertNotSame('', $serial);
    }
}
