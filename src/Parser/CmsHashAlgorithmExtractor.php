<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use phpseclib3\File\ASN1;

final class CmsHashAlgorithmExtractor
{
    public function extract(?string $cmsDer): ?string
    {
        if (!is_string($cmsDer) || $cmsDer === '') {
            return null;
        }

        try {
            $decoded = ASN1::decodeBER($cmsDer);
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($decoded)) {
            return null;
        }

        $oid = $this->findDigestAlgorithmOid($decoded);
        if ($oid === null) {
            return null;
        }

        $mapped = $this->mapOidToName($oid);
        $result = $mapped ?? $oid;
        return $result !== '' ? $result : null;
    }

    /**
     * BFS traversal: digestAlgorithms in SignedData is shallower than
     * per-signer or timestamp-embedded algorithms, so BFS reliably finds
     * the main document digest algorithm first.
     *
     * @param array<mixed> $node
     */
    private function findDigestAlgorithmOid(array $node): ?string
    {
        /** @var list<array<mixed>> $queue */
        $queue = [$node];
        while ($queue !== []) {
            $current = array_shift($queue);

            /** @var mixed $type */
            $type = $current['type'] ?? null;
            if ($type === ASN1::TYPE_OBJECT_IDENTIFIER) {
                /** @var mixed $content */
                $content = $current['content'] ?? null;
                if (is_string($content) && $content !== '' &&
                    (str_starts_with($content, '2.16.840.1.101.3.4.2.') || $content === '1.3.14.3.2.26' || $content === '1.2.840.113549.2.5')
                ) {
                    return $content;
                }
            }

            /** @var mixed $value */
            foreach ($current as $value) {
                if (is_array($value)) {
                    $queue[] = $value;
                }
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
