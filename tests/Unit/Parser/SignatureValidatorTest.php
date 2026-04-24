<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\ValidationReason;
use LibreSign\PdfSignatureValidator\Parser\CertificateExtractor;
use LibreSign\PdfSignatureValidator\Parser\SignatureValidator;
use PHPUnit\Framework\TestCase;

/**
 * Tests for cryptographic signature validation.
 */
final class SignatureValidatorTest extends TestCase
{
    private SignatureValidator $signatureValidator;
    private CertificateExtractor $certificateExtractor;

    protected function setUp(): void
    {
        $this->signatureValidator = new SignatureValidator();
        $this->certificateExtractor = new CertificateExtractor();
    }

    public function testVerifyDigestWithValidByteRange(): void
    {
        // Simple test with known data
        $content = 'The quick brown fox jumps over the lazy dog';
        $digest = hash('sha256', $content, true);
        $byteRange = [
            'offset1' => 0,
            'length1' => strlen($content),
            'offset2' => strlen($content),
            'length2' => strlen($content),
        ];

        $result = $this->signatureValidator->verifyDigest(
            $content,
            $digest,
            'SHA256',
            $byteRange,
        );

        $this->assertTrue($result->isValid);
    }

    public function testVerifyDigestWithMismatchedContent(): void
    {
        $content = 'The quick brown fox jumps over the lazy dog';
        $wrongDigest = hash('sha256', 'different content', true);
        $byteRange = [
            'offset1' => 0,
            'length1' => strlen($content),
            'offset2' => strlen($content),
            'length2' => strlen($content),
        ];

        $result = $this->signatureValidator->verifyDigest(
            $content,
            $wrongDigest,
            'SHA256',
            $byteRange,
        );

        $this->assertFalse($result->isValid);
        $this->assertSame('Digest Mismatch.', $result->state->value);
        $this->assertSame(ValidationReason::DIGEST_MISMATCH, $result->reasonCode);
    }

    public function testVerifyDigestWithoutByteRange(): void
    {
        $result = $this->signatureValidator->verifyDigest(
            'content',
            'digest',
            'SHA256',
            null,
        );

        $this->assertFalse($result->isValid);
        $this->assertSame(ValidationReason::NO_BYTE_RANGE, $result->reasonCode);
    }

    public function testVerifySignatureWithValidOpenSslSignature(): void
    {
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($privateKey);

        $data = 'signed content';
        $signature = '';
        $signed = openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $this->assertTrue($signed);

        $details = openssl_pkey_get_details($privateKey);
        $this->assertIsArray($details);
        $publicKeyPem = $details['key'];

        $result = $this->signatureValidator->verifySignature(
            $data,
            $signature,
            $publicKeyPem,
            'SHA256',
        );

        $this->assertTrue($result->isValid);
    }

    public function testVerifySignatureWithInvalidSignatureBytes(): void
    {
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        $this->assertIsArray($details);
        $publicKeyPem = $details['key'];

        $result = $this->signatureValidator->verifySignature(
            'signed content',
            'invalid-signature',
            $publicKeyPem,
            'SHA256',
        );

        $this->assertFalse($result->isValid);
        $this->assertSame(ValidationReason::SIGNATURE_CERTIFICATE_MISMATCH, $result->reasonCode);
    }
}
