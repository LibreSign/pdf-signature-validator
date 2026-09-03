<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\File\CMS\SignedData;

final class CmsHashAlgorithmExtractor
{
    public function extract(?string $cmsDer): ?string
    {
        if (!is_string($cmsDer) || $cmsDer === '') {
            return null;
        }

        try {
            $cms = SignedData::load($cmsDer)->toArray();
        } catch (\Throwable) {
            return null;
        }

        $content = $cms['content'] ?? null;
        if (!is_array($content)) {
            return null;
        }

        $algorithms = $content['digestAlgorithms'] ?? null;
        if (!is_array($algorithms)) {
            return null;
        }

        /** @var list<array<array-key, mixed>> $algorithmEntries */
        $algorithmEntries = array_values(array_filter($algorithms, 'is_array'));
        foreach ($algorithmEntries as $algorithm) {
            $algorithmOid = $algorithm['algorithm'] ?? null;
            if (!$algorithmOid instanceof OID) {
                continue;
            }

            $oid = ASN1::getOIDFromName((string) $algorithmOid);
            $mapped = $this->mapOidToName($oid);
            if ($mapped !== null) {
                return $mapped;
            }
        }

        return null;
    }

    private function mapOidToName(string $oid): ?string
    {
        return match ($oid) {
            '1.3.14.3.2.26' => 'SHA1',
            '2.16.840.1.101.3.4.2.1' => 'SHA-256',
            '2.16.840.1.101.3.4.2.2' => 'SHA-384',
            '2.16.840.1.101.3.4.2.3' => 'SHA-512',
            '1.2.840.113549.2.5' => 'MD5',
            default => null,
        };
    }
}
