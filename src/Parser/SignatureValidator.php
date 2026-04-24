<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\ValidationReason;
use LibreSign\PdfSignatureValidator\Model\ValidationResult;
use LibreSign\PdfSignatureValidator\Model\ValidationState;

/**
 * Validates PDF signatures cryptographically.
 */
final class SignatureValidator
{
    public function __construct(
        private CmsHashAlgorithmExtractor $hashAlgorithmExtractor = new CmsHashAlgorithmExtractor(),
    ) {
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int}|null $byteRange
     */
    public function verifyDigest(
        string $pdfContent,
        string $expectedDigest,
        ?string $hashAlgorithm = null,
        ?array $byteRange = null,
    ): ValidationResult {
        if ($byteRange === null) {
            return new ValidationResult(
                ValidationState::NOT_VERIFIED,
                'No ByteRange in signature',
                ValidationReason::NO_BYTE_RANGE,
            );
        }

        $algorithm = $this->normalizeHashAlgorithmName($hashAlgorithm ?? 'SHA256');
        $contentToHash = $this->extractSignedContent($pdfContent, $byteRange);
        $calculatedHash = hash($algorithm, $contentToHash, true);

        if (hash_equals($calculatedHash, $expectedDigest)) {
            return new ValidationResult(ValidationState::SIGNATURE_VALID);
        }

        return new ValidationResult(
            ValidationState::DIGEST_MISMATCH,
            'PDF content hash does not match signed digest',
            ValidationReason::DIGEST_MISMATCH,
        );
    }

    public function verifySignature(
        string $signedHash,
        string $signature,
        string $publicKeyPem,
        string $hashAlgorithm = 'SHA256',
    ): ValidationResult {
        $algorithm = $this->toOpenSslAlgorithm($hashAlgorithm);
        $isValid = $this->verifySignatureWithOpenSSL($signedHash, $signature, $publicKeyPem, $algorithm);

        if ($isValid) {
            return new ValidationResult(ValidationState::SIGNATURE_VALID);
        }

        return new ValidationResult(
            ValidationState::SIGNATURE_INVALID,
            'Signature does not match certificate',
            ValidationReason::SIGNATURE_CERTIFICATE_MISMATCH,
        );
    }

    public function verifySignatureWithOpenSSL(
        string $dataToVerify,
        string $signature,
        string $publicKeyPem,
        int $algo = OPENSSL_ALGO_SHA256,
    ): bool {
        try {
            $resource = openssl_pkey_get_public($publicKeyPem);
            if ($resource === false) {
                return false;
            }

            $result = openssl_verify($dataToVerify, $signature, $resource, $algo);

            return $result === 1;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $byteRange
     */
    private function extractSignedContent(string $pdfContent, array $byteRange): string
    {
        $data1Start = $byteRange['offset1'] ?? 0;
        $data1Length = $byteRange['length1'] ?? 0;
        $data2Start = $byteRange['offset2'] ?? 0;
        $data2End = $byteRange['length2'] ?? strlen($pdfContent);

        $data1 = substr($pdfContent, $data1Start, $data1Length);
        $data2 = substr($pdfContent, $data2Start, $data2End - $data2Start);

        return $data1 . $data2;
    }

    private function toOpenSslAlgorithm(string $algorithm): int
    {
        return match (strtoupper($algorithm)) {
            'SHA1' => OPENSSL_ALGO_SHA1,
            'SHA224' => OPENSSL_ALGO_SHA224,
            'SHA256' => OPENSSL_ALGO_SHA256,
            'SHA384' => OPENSSL_ALGO_SHA384,
            'SHA512' => OPENSSL_ALGO_SHA512,
            default => OPENSSL_ALGO_SHA256,
        };
    }

    private function normalizeHashAlgorithmName(string $algorithm): string
    {
        return match (strtoupper($algorithm)) {
            'SHA1' => 'sha1',
            'SHA224' => 'sha224',
            'SHA256' => 'sha256',
            'SHA384' => 'sha384',
            'SHA512' => 'sha512',
            'MD5' => 'md5',
            'RIPEMD160' => 'ripemd160',
            default => 'sha256',
        };
    }
}
