<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\ValidationResult;
use LibreSign\PdfSignatureValidator\Parser\CertificateExtractor;
use LibreSign\PdfSignatureValidator\Parser\CertificateValidator;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\TestCase;

/**
 * Tests for certificate validation.
 */
final class CertificateValidatorTest extends TestCase
{
    private CertificateValidator $certificateValidator;

    protected function setUp(): void
    {
        $this->certificateValidator = new CertificateValidator();
    }

    public function testValidateExpirationWithInvalidCertificate(): void
    {
        $result = $this->certificateValidator->validateExpiration('invalid certificate');

        $this->assertFalse($result->isValid);
        $this->assertNotEmpty($result->state);
    }

    public function testValidateCertificateChainWithEmptyChain(): void
    {
        $result = $this->certificateValidator->validateChain([]);

        $this->assertFalse($result->isValid);
        $this->assertSame(ValidationResult::STATE_CERT_NOT_VERIFIED, $result->state);
    }

    public function testValidateCertificateChainWithInvalidCertificates(): void
    {
        $result = $this->certificateValidator->validateChain(['invalid1', 'invalid2']);

        $this->assertFalse($result->isValid);
    }

    public function testAddTrustedRootCertificate(): void
    {
        $selfSignedCert = (string) file_get_contents(__DIR__ . '/../../Fixtures/certs/self-signed-cert.pem');

        $this->certificateValidator->addTrustedRoot($selfSignedCert);
        $roots = $this->certificateValidator->getTrustedRoots();

        $this->assertCount(1, $roots);
        $this->assertContains($selfSignedCert, $roots);
    }

    public function testSetMultipleTrustedRoots(): void
    {
        $cert1 = 'CERT1';
        $cert2 = 'CERT2';
        $cert3 = 'CERT3';

        $this->certificateValidator->setTrustedRoots([$cert1, $cert2, $cert3]);
        $roots = $this->certificateValidator->getTrustedRoots();

        $this->assertCount(3, $roots);
        $this->assertSame([$cert1, $cert2, $cert3], $roots);
    }

    public function testConstructorWithTrustedRoots(): void
    {
        $cert1 = 'CERT1';
        $cert2 = 'CERT2';

        $validator = new CertificateValidator([$cert1, $cert2]);
        $roots = $validator->getTrustedRoots();

        $this->assertCount(2, $roots);
        $this->assertSame([$cert1, $cert2], $roots);
    }

    public function testValidateSingleSelfSignedCertificateWithoutTrustRoot(): void
    {
        $selfSignedCert = $this->createSelfSignedCertificate();

        $result = $this->certificateValidator->validateChain([$selfSignedCert]);

        $this->assertFalse($result->isValid);
        $this->assertSame(ValidationResult::STATE_CERT_ISSUER_UNKNOWN, $result->state);
    }

    public function testValidateSingleSelfSignedCertificateWithTrustRoot(): void
    {
        $selfSignedCert = $this->createSelfSignedCertificate();
        $validator = new CertificateValidator([$selfSignedCert]);

        $result = $validator->validateChain([$selfSignedCert]);

        $this->assertTrue($result->isValid);
        $this->assertSame(ValidationResult::STATE_CERT_TRUSTED, $result->state);
    }

    public function testCheckRevocationDetectsCertificateSerialInCrlText(): void
    {
        $certificate = $this->extractFirstCertificateFromSignedPdf();
        $serial = (string) (openssl_x509_parse($certificate, false)['serialNumber'] ?? '');
        $this->assertNotSame('', $serial);

        $result = $this->certificateValidator->checkRevocation($certificate, "header\n{$serial}\nfooter");

        $this->assertFalse($result->isValid);
        $this->assertSame(ValidationResult::STATE_CERT_REVOKED, $result->state);
    }

    public function testCheckRevocationReturnsTrustedWhenSerialNotPresent(): void
    {
        $certificate = $this->extractFirstCertificateFromSignedPdf();

        $result = $this->certificateValidator->checkRevocation($certificate, "header\nno-serial\nfooter");

        $this->assertTrue($result->isValid);
        $this->assertSame(ValidationResult::STATE_CERT_TRUSTED, $result->state);
    }

    private function createSelfSignedCertificate(): string
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        $this->assertNotFalse($privateKey);

        $csr = openssl_csr_new([
            'commonName' => 'Unit Test Cert',
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
