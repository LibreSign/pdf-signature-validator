<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use DateTime;
use LibreSign\PdfSignatureValidator\Model\ValidationResult;
use LibreSign\PdfSignatureValidator\Model\ValidationState;

/**
 * Validates certificate validity and chain.
 */
final class CertificateValidator
{
    /**
     * @var list<string>
     */
    private array $trustedRoots = [];

    /**
     * @param list<string> $trustedRoots
     */
    public function __construct(
        array $trustedRoots = [],
        private CertificateInspector $inspector = new CertificateInspector(),
    ) {
        $this->trustedRoots = $trustedRoots;
    }

    public function addTrustedRoot(string $certificatePem): void
    {
        if (!in_array($certificatePem, $this->trustedRoots, true)) {
            $this->trustedRoots[] = $certificatePem;
        }
    }

    /**
     * @param list<string> $trustedRoots
     */
    public function setTrustedRoots(array $trustedRoots): void
    {
        $this->trustedRoots = $trustedRoots;
    }

    /**
     * @return list<string>
     */
    public function getTrustedRoots(): array
    {
        return $this->trustedRoots;
    }

    public function validateExpiration(string $certificatePem, ?DateTime $signatureTime = null): ValidationResult
    {
        $cert = $this->inspector->parse($certificatePem);
        if ($cert === false) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Failed to parse certificate',
            );
        }

        $validFrom = (int) ($cert['validFrom_time_t'] ?? 0);
        $validTo = (int) ($cert['validTo_time_t'] ?? 0);
        $checkTime = $signatureTime instanceof DateTime ? $signatureTime->getTimestamp() : time();

        if ($checkTime < $validFrom) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Certificate was not valid at time of signature',
            );
        }

        if ($checkTime > $validTo) {
            return new ValidationResult(
                ValidationState::CERT_EXPIRED,
                'Certificate has expired',
            );
        }

        return new ValidationResult(ValidationState::CERT_TRUSTED);
    }

    /**
     * @param list<string> $chain
     * @param list<string>|null $trustedRoots
     */
    public function validateChain(array $chain, ?array $trustedRoots = null): ValidationResult
    {
        $chain = array_values(array_filter(
            $chain,
            static fn (string $item): bool => $item !== '',
        ));
        /** @var list<string> $chain */

        if ($chain === []) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Empty certificate chain',
            );
        }

        $roots = $trustedRoots ?? $this->trustedRoots;
        $leafValidation = $this->validateLeafCertificate($chain[0]);
        if (!$leafValidation->isValid) {
            return $leafValidation;
        }

        $leafIssuerValidation = $this->validateLeafIssuer($chain, $roots);
        if (!$leafIssuerValidation->isValid) {
            return $leafIssuerValidation;
        }

        $intermediateValidation = $this->validateIntermediateCertificates($chain);
        if (!$intermediateValidation->isValid) {
            return $intermediateValidation;
        }

        return $this->validateRootTrust($chain, $roots);
    }

    public function checkRevocation(string $certificatePem, string $crlPem): ValidationResult
    {
        $serial = $this->inspector->extractSerial($certificatePem);
        if ($serial === null) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Certificate has no serial number',
            );
        }

        foreach (explode("\n", $crlPem) as $line) {
            if (strpos($line, $serial) !== false) {
                return new ValidationResult(
                    ValidationState::CERT_REVOKED,
                    'Certificate found in CRL',
                );
            }
        }

        return new ValidationResult(ValidationState::CERT_TRUSTED);
    }

    private function validateLeafCertificate(string $certificatePem): ValidationResult
    {
        if ($this->inspector->parse($certificatePem) === false) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Invalid certificate',
            );
        }

        if (
            !$this->inspector->isSelfSigned($certificatePem)
            && $this->inspector->isLeafCertificateAuthority($certificatePem)
        ) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Leaf certificate is marked as CA',
            );
        }

        return $this->validateExpiration($certificatePem);
    }

    /**
     * @param list<string> $chain
     * @param list<string> $roots
     */
    private function validateLeafIssuer(array $chain, array $roots): ValidationResult
    {
        $leafCert = $chain[0];
        if (count($chain) > 1) {
            $issuerPem = $chain[1];
            if (!$this->inspector->verifySignature($leafCert, $issuerPem)) {
                return new ValidationResult(
                    ValidationState::CERT_ISSUER_NOT_TRUSTED,
                    'Certificate signature validation failed',
                );
            }

            return new ValidationResult(ValidationState::CERT_TRUSTED);
        }

        if (!in_array($leafCert, $roots, true) && !$this->inspector->isSelfSigned($leafCert)) {
            return new ValidationResult(
                ValidationState::CERT_ISSUER_UNKNOWN,
                'Self-signed certificate not in trusted roots',
            );
        }

        return new ValidationResult(ValidationState::CERT_TRUSTED);
    }

    /**
     * @param list<string> $chain
     */
    private function validateIntermediateCertificates(array $chain): ValidationResult
    {
        $chainCount = count($chain);
        if ($chainCount < 3) {
            return new ValidationResult(ValidationState::CERT_TRUSTED);
        }

        for ($i = 1; $i < $chainCount - 1; $i++) {
            $current = $chain[$i];
            $issuer = $chain[$i + 1];

            if (!$this->inspector->verifySignature($current, $issuer)) {
                return new ValidationResult(
                    ValidationState::CERT_ISSUER_NOT_TRUSTED,
                    "Intermediate certificate at position {$i} is not signed by issuer",
                );
            }

            $expirationValidation = $this->validateExpiration($current);
            if (!$expirationValidation->isValid) {
                return $expirationValidation;
            }
        }

        return new ValidationResult(ValidationState::CERT_TRUSTED);
    }

    /**
     * @param list<string> $chain
     * @param list<string> $roots
     */
    private function validateRootTrust(array $chain, array $roots): ValidationResult
    {
        $chainCount = count($chain);
        if ($chainCount === 0) {
            return new ValidationResult(
                ValidationState::CERT_NOT_VERIFIED,
                'Empty certificate chain',
            );
        }

        $root = $chain[$chainCount - 1];

        if (!$this->inspector->isSelfSigned($root)) {
            return new ValidationResult(
                ValidationState::CERT_ISSUER_UNKNOWN,
                'Root certificate is not self-signed',
            );
        }

        $allTrustedRoots = $this->trustedRoots;
        foreach ($roots as $rootPem) {
            if (!in_array($rootPem, $allTrustedRoots, true)) {
                $allTrustedRoots[] = $rootPem;
            }
        }

        if (!in_array($root, $allTrustedRoots, true)) {
            return new ValidationResult(
                ValidationState::CERT_ISSUER_UNKNOWN,
                'Root certificate is not in trusted list',
            );
        }

        return new ValidationResult(ValidationState::CERT_TRUSTED);
    }
}
