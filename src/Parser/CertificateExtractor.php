<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Extracts X.509 certificates from PKCS#7/CMS signature structures.
 *
 * Uses PHP OpenSSL functions for reliable PKCS#7 parsing and certificate extraction.
 */
final class CertificateExtractor
{
    /**
     * Extract X.509 certificates from PKCS#7/CMS signature.
     *
     * @param string $binarySignature Decoded PKCS#7/CMS signature blob
     * @return list<string> List of PEM-encoded certificates
     */
    public function extractCertificates(string $binarySignature): array
    {
        // Convert binary signature to PEM PKCS#7 format
        $pem = $this->derToPem($binarySignature, 'PKCS7');
        if ($pem === null) {
            return [];
        }

        // Use OpenSSL to extract certificates from PKCS#7
        /** @var array<int, mixed> $rawCertificates */
        $rawCertificates = [];
        if (!openssl_pkcs7_read($pem, $rawCertificates)) {
            return [];
        }

        /** @var list<string> $certificates */
        $certificates = array_values(array_filter(
            $rawCertificates,
            static fn (mixed $entry): bool => is_string($entry),
        ));

        // Filter to only certificate PEMs (skip intermediate data)
        $result = [];
        foreach ($certificates as $cert) {
            if (strpos($cert, 'BEGIN CERTIFICATE') !== false) {
                $result[] = $cert;
            }
        }

        return $result;
    }

    /**
     * Extract certificate serial number from PKCS#7/CMS.
     */
    public function extractCertificateSerial(string $binarySignature): ?string
    {
        $certificates = $this->extractCertificates($binarySignature);
        if ($certificates === []) {
            return null;
        }

        try {
            $cert = openssl_x509_parse($certificates[0], false);
            if ($cert === false || !isset($cert['serialNumber'])) {
                return null;
            }

            return (string) $cert['serialNumber'];
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Convert DER/BER binary to PEM format.
     */
    private function derToPem(string $der, string $type): ?string
    {
        if ($der === '' || $der === '0') {
            return null;
        }

        $pem = "-----BEGIN {$type}-----\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= "-----END {$type}-----\n";

        return $pem;
    }
}
