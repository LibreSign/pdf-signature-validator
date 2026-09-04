<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Model\DocumentModificationState;
use LibreSign\PdfSignatureValidator\Model\ExtractedSignature;
use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use LibreSign\PdfSignatureValidator\Model\ValidationReason;
use LibreSign\PdfSignatureValidator\Model\ValidationResult;
use LibreSign\PdfSignatureValidator\Model\ValidationState;

/**
 * Complete PDF signature validator.
 *
 * @psalm-type PdfSignatureValidationResult = array{
 *     signature: ExtractedSignature,
 *     signatureValidation: ValidationResult,
 *     certificates: list<string>,
 *     certificateValidation: ValidationResult,
 *     timestamp: ?TimestampToken,
 * }
 */
final class PdfSignatureValidator
{
    private SignatureValidator $signatureValidator;
    private CertificateValidator $certificateValidator;
    private CertificateExtractor $certificateExtractor;
    private CmsTimestampExtractor $cmsTimestampExtractor;
    private PdfSignatureExtractor $extractor;
    private PdfDocumentModificationAnalyzer $documentModificationAnalyzer;

    /** @var list<string> */
    private array $trustedRoots = [];

    /**
     * @param list<string>|null $trustedRoots Optional trusted root certificates (PEM)
     */
    public function __construct(
        ?SignatureValidator $signatureValidator = null,
        ?CertificateValidator $certificateValidator = null,
        ?CertificateExtractor $certificateExtractor = null,
        ?CmsTimestampExtractor $cmsTimestampExtractor = null,
        ?PdfSignatureExtractor $extractor = null,
        ?array $trustedRoots = null,
        ?PdfDocumentModificationAnalyzer $documentModificationAnalyzer = null,
    ) {
        $this->signatureValidator = $signatureValidator ?? new SignatureValidator();
        $this->certificateValidator = $certificateValidator ?? new CertificateValidator();
        $this->certificateExtractor = $certificateExtractor ?? new CertificateExtractor();
        $this->cmsTimestampExtractor = $cmsTimestampExtractor ?? new CmsTimestampExtractor();
        $this->extractor = $extractor ?? new PdfSignatureExtractor();
        $this->documentModificationAnalyzer = $documentModificationAnalyzer
            ?? new PdfDocumentModificationAnalyzer();

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
     * @return list<PdfSignatureValidationResult>
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
     * @return list<PdfSignatureValidationResult>
     * @throws UnsignedPdfException
     */
    public function validateFromString(string $pdfContent, ?array $trustedRoots = null): array
    {
        $signatures = $this->extractor->extractFromString($pdfContent);

        $results = [];
        foreach ($signatures as $signature) {
            $binarySignature = $signature->binarySignature;

            if ($binarySignature === null || $binarySignature === '') {
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
                    'timestamp' => null,
                ];
                continue;
            }

            $signatureValidation = $this->validateSignature(
                $signature,
                $binarySignature,
                $pdfContent,
            );

            /** @var list<string> $certificates */
            $certificates = $this->certificateExtractor->extractCertificates($binarySignature);
            $certValidation = $this->validateCertificateChain($certificates, $trustedRoots);

            $results[] = [
                'signature' => $signature,
                'signatureValidation' => $signatureValidation,
                'certificates' => $certificates,
                'certificateValidation' => $certValidation,
                'timestamp' => $this->cmsTimestampExtractor->extract($binarySignature),
            ];
        }

        return $results;
    }

    private function validateSignature(
        ExtractedSignature $signature,
        string $binarySignature,
        string $pdfContent,
    ): ValidationResult {
        $structuralIssue = $this->documentModificationAnalyzer
            ->detectStructuralIssue(
                $signature->metadata,
                $pdfContent,
            );

        if ($structuralIssue === DocumentModificationState::INVALID_BYTE_RANGE) {
            return new ValidationResult(
                ValidationState::NOT_VERIFIED,
                'Invalid PDF signature ByteRange',
                ValidationReason::INVALID_BYTE_RANGE,
            );
        }

        if ($structuralIssue === DocumentModificationState::INVALID_EOF_BOUNDARY) {
            return new ValidationResult(
                ValidationState::NOT_VERIFIED,
                'Invalid signed PDF revision EOF boundary',
                ValidationReason::INVALID_EOF_BOUNDARY,
            );
        }

        $subFilter = $signature->metadata->signatureType;

        if (!in_array(
            $subFilter,
            ['adbe.pkcs7.detached', 'ETSI.CAdES.detached'],
            true,
        )) {
            return new ValidationResult(
                ValidationState::NOT_VERIFIED,
                $subFilter === null
                    ? 'PDF signature SubFilter is missing'
                    : 'Unsupported PDF signature SubFilter: ' . $subFilter,
                ValidationReason::UNSUPPORTED_SUBFILTER,
            );
        }

        return $this->signatureValidator->verifyDetachedCmsSignature(
            $pdfContent,
            $binarySignature,
            $signature->metadata->range,
        );
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

}
