<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\CertificateExtractor;
use LibreSign\PdfSignatureValidator\Parser\CertificateInspector;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\TestCase;

final class CertificateInspectorTest extends TestCase
{
    private CertificateInspector $inspector;

    protected function setUp(): void
    {
        $this->inspector = new CertificateInspector();
    }

    public function testParseReturnsFalseForInvalidCertificate(): void
    {
        $result = $this->inspector->parse('invalid-certificate');

        $this->assertFalse($result);
    }

    public function testSelfSignedFixtureIsDetectedAsSelfSigned(): void
    {
        $certificate = $this->createSelfSignedCertificate();

        $this->assertTrue($this->inspector->isSelfSigned($certificate));
    }

    public function testExtractSerialReturnsValueForFixtureCertificate(): void
    {
        $certificate = $this->extractFirstCertificateFromSignedPdf();

        $serial = $this->inspector->extractSerial($certificate);

        $this->assertIsString($serial);
        $this->assertNotSame('', $serial);
    }

    public function testVerifySignatureWorksForSelfSignedCertificate(): void
    {
        $certificate = $this->createSelfSignedCertificate();

        $this->assertTrue($this->inspector->verifySignature($certificate, $certificate));
    }

    private function createSelfSignedCertificate(): string
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        $this->assertNotFalse($privateKey);

        $csr = openssl_csr_new([
            'commonName' => 'Inspector Test Cert',
            'organizationName' => 'LibreSign',
            'countryName' => 'BR',
        ], $privateKey, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($csr);

        $x509 = openssl_csr_sign($csr, null, $privateKey, 30, ['digest_alg' => 'sha256']);
        $this->assertNotFalse($x509);

        $pem = '';
        $exported = openssl_x509_export($x509, $pem);
        $this->assertTrue($exported);

        return $pem;
    }

    private function extractFirstCertificateFromSignedPdf(): string
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/small_valid-signed.pdf');
        $this->assertIsString($content);

        $pdfExtractor = new PdfSignatureExtractor();
        $signatures = $pdfExtractor->extractFromString($content);
        $this->assertNotEmpty($signatures);

        $binarySignature = $signatures[0]->binarySignature;
        $this->assertIsString($binarySignature);

        $certificateExtractor = new CertificateExtractor();
        $certificates = $certificateExtractor->extractCertificates($binarySignature);
        $this->assertNotEmpty($certificates);

        return $certificates[0];
    }
}
