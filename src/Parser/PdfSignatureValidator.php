<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Model\ExtractedSignature;
use LibreSign\PdfSignatureValidator\Model\ValidationReason;
use LibreSign\PdfSignatureValidator\Model\ValidationResult;
use LibreSign\PdfSignatureValidator\Model\ValidationState;

/**
 * Complete PDF signature validator.
 */
final class PdfSignatureValidator
{
    private SignatureValidator $signatureValidator;
    private CertificateValidator $certificateValidator;
    private CertificateExtractor $certificateExtractor;
    private PdfSignatureExtractor $extractor;

    /** @var list<string> */
    private array $trustedRoots = [];

    /**
     * @param list<string>|null $trustedRoots Optional trusted root certificates (PEM)
     */
    public function __construct(
        ?SignatureValidator $signatureValidator = null,
        ?CertificateValidator $certificateValidator = null,
        ?CertificateExtractor $certificateExtractor = null,
        ?PdfSignatureExtractor $extractor = null,
        ?array $trustedRoots = null,
    ) {
        $this->signatureValidator = $signatureValidator ?? new SignatureValidator();
        $this->certificateValidator = $certificateValidator ?? new CertificateValidator();
        $this->certificateExtractor = $certificateExtractor ?? new CertificateExtractor();
        $this->extractor = $extractor ?? new PdfSignatureExtractor();

        if ($trustedRoots !== null && $trustedRoots !== []) {
            $this->setTrustedRoots($trustedRoots);
        }
    }

    /**
     * @param list<string> $trustedRoots PEM-encoded certificates
     */
    public function setTrustedRoots(array $trustedRoots): void
    {
        $this->trustedRoots = $trustedRoots;
        $this->certificateValidator->setTrustedRoots($trustedRoots);
    }

    public function addTrustedRoot(string $certificatePem): void
    {
        $this->certificateValidator->addTrustedRoot($certificatePem);
        if (!in_array($certificatePem, $this->trustedRoots, true)) {
            $this->trustedRoots[] = $certificatePem;
        }
    }

    /**
     * @return list<string>
     */
    public function getTrustedRoots(): array
    {
        return $this->trustedRoots;
    }

    /**
     * @param resource $resource
     * @param list<string>|null $trustedRoots
     * @return list<array{signature:ExtractedSignature,signatureValidation:ValidationResult,certificates:list<string>,certificateValidation:ValidationResult}>
     * @throws UnsignedPdfException
     */
    public function validateFromResource($resource, ?array $trustedRoots = null): array
    {
        rewind($resource);
        $content = (string) stream_get_contents($resource);

        return $this->validateFromString($content, $trustedRoots);
    }

    /**
     * @param list<string>|null $trustedRoots
     * @return list<array{signature:ExtractedSignature,signatureValidation:ValidationResult,certificates:list<string>,certificateValidation:ValidationResult}>
     * @throws UnsignedPdfException
     */
    public function validateFromString(string $pdfContent, ?array $trustedRoots = null): array
    {
        $signatures = $this->extractor->extractFromString($pdfContent);

        $results = [];
        foreach ($signatures as $signature) {
            if ($signature->binarySignature === null || $signature->binarySignature === '') {
                $results[] = [
                    'signature' => $signature,
                    'signatureValidation' => new ValidationResult(
                        ValidationState::NOT_VERIFIED,
                        'No binary signature',
                        ValidationReason::NO_BINARY_SIGNATURE,
                    ),
                    'certificates' => [],
                    'certificateValidation' => new ValidationResult(
                        ValidationState::CERT_NOT_VERIFIED,
                        'No binary signature',
                        ValidationReason::NO_BINARY_SIGNATURE,
                    ),
                ];
                continue;
            }

            $digestValidation = $this->signatureValidator->verifyDigest(
                $pdfContent,
                '',
                $signature->hashAlgorithm,
                $signature->metadata->range,
            );

            /** @var list<string> $certificates */
            $certificates = $this->certificateExtractor->extractCertificates($signature->binarySignature);
            $certValidation = $this->validateCertificateChain($certificates, $trustedRoots);

            $results[] = [
                'signature' => $signature,
                'signatureValidation' => $this->determineOverallSignatureState(
                    $digestValidation,
                    $certValidation,
                ),
                'certificates' => $certificates,
                'certificateValidation' => $certValidation,
            ];
        }

        return $results;
    }

    /**
     * @param list<string> $certificates
     * @param list<string>|null $trustedRoots
     */
    private function validateCertificateChain(array $certificates, ?array $trustedRoots = null): ValidationResult
    {
        if ($certificates === []) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'No certificates in signature',
            );
        }

        $leafCertificate = $certificates[0];
        $expirationResult = $this->certificateValidator->validateExpiration($leafCertificate);
        if (!$expirationResult->isValid) {
            return $expirationResult;
        }

        if (count($certificates) > 1) {
            return $this->certificateValidator->validateChain($certificates, $trustedRoots);
        }

        $chainResult = $this->certificateValidator->validateChain(
            [$leafCertificate, $leafCertificate],
            $trustedRoots,
        );

        if ($chainResult->state === ValidationState::CERT_ISSUER_UNKNOWN) {
            return new ValidationResult(
                ValidationState::CERT_ISSUER_UNKNOWN,
                'Self-signed certificate not in trusted roots',
            );
        }

        return $chainResult;
    }

    private function determineOverallSignatureState(
        ValidationResult $digestValidation,
        ValidationResult $certValidation,
    ): ValidationResult {
        if ($digestValidation->state === ValidationState::DIGEST_MISMATCH) {
            return $digestValidation;
        }

        if (!$digestValidation->isValid && $digestValidation->state !== ValidationState::NOT_VERIFIED) {
            return $digestValidation;
        }

        if (!$certValidation->isValid) {
            return match ($certValidation->state) {
                ValidationState::CERT_EXPIRED => new ValidationResult(
                    ValidationState::SIGNATURE_INVALID,
                    'Signing certificate has expired',
                ),
                ValidationState::CERT_REVOKED => new ValidationResult(
                    ValidationState::SIGNATURE_INVALID,
                    'Signing certificate has been revoked',
                ),
                default => new ValidationResult(
                    ValidationState::SIGNATURE_INVALID,
                    'Certificate validation failed: ' . ($certValidation->reason ?? $certValidation->state->value),
                ),
            };
        }

        if ($digestValidation->isValid) {
            return new ValidationResult(ValidationState::SIGNATURE_VALID);
        }

        return new ValidationResult(
            ValidationState::NOT_VERIFIED,
            'Signature verification incomplete',
        );
    }
}
