<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Low-level certificate parsing and signature inspection helpers.
 */
final class CertificateInspector
{
    /**
     * @return array<array-key, mixed>|false
     */
    public function parse(string $certificatePem): array|false
    {
        try {
            return openssl_x509_parse($certificatePem, false);
        } catch (\Throwable) {
            return false;
        }
    }

    public function verifySignature(string $certificatePem, string $issuerPem): bool
    {
        try {
            return openssl_x509_verify($certificatePem, $issuerPem) === 1;
        } catch (\Throwable) {
            return false;
        }
    }

    public function isSelfSigned(string $certificatePem): bool
    {
        $cert = $this->parse($certificatePem);
        if ($cert === false) {
            return false;
        }

        $subject = $cert['subject'] ?? null;
        $issuer = $cert['issuer'] ?? null;
        if (!is_array($subject) || !is_array($issuer)) {
            return false;
        }

        return $this->normalizeDn($subject) === $this->normalizeDn($issuer)
            && $this->verifySignature($certificatePem, $certificatePem);
    }

    public function extractSerial(string $certificatePem): ?string
    {
        $cert = $this->parse($certificatePem);
        if ($cert === false) {
            return null;
        }

        /** @var mixed $serialValue */
        $serialValue = $cert['serialNumber'] ?? $cert['serialNumberHex'] ?? null;
        $serial = is_string($serialValue) ? $serialValue : (string) $serialValue;
        if ($serial === '' || $serial === '0') {
            return null;
        }

        return $serial;
    }

    public function isLeafCertificateAuthority(string $certificatePem): bool
    {
        $cert = $this->parse($certificatePem);
        if ($cert === false) {
            return false;
        }

        $extensions = $cert['extensions'] ?? null;
        if (!is_array($extensions)) {
            return false;
        }

        /** @var mixed $basicConstraints */
        $basicConstraints = $extensions['basicConstraints'] ?? null;

        return is_string($basicConstraints) && strpos($basicConstraints, 'CA:TRUE') !== false;
    }

    /**
     * @param array<array-key, mixed> $dn
     * @return array<array-key, mixed>
     */
    private function normalizeDn(array $dn): array
    {
        $normalized = $dn;
        ksort($normalized);

        foreach (array_keys($normalized) as $key) {
            if (!is_array($normalized[$key])) {
                continue;
            }

            /** @var array<array-key, mixed> $child */
            $child = $normalized[$key];
            $normalized[$key] = $this->normalizeDn($child);
        }

        return $normalized;
    }
}
