<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use phpseclib4\File\ASN1;

/** @internal */
final class CertificateSubjectExtractor
{
    /** @var array<string, string> */
    private const ATTRIBUTES = [
        '2.5.4.3' => 'commonName',
        '2.5.4.6' => 'countryName',
        '2.5.4.10' => 'organizationName',
        '1.2.840.113549.1.9.1' => 'emailAddress',
    ];

    public function __construct(
        private readonly Asn1NodeReader $reader,
    ) {
    }

    /**
     * @param list<array<array-key, mixed>> $nodes
     * @return array<string, string>
     */
    public function extract(array $nodes): array
    {
        $subject = [];
        $attribute = null;
        foreach ($this->reader->walk($nodes) as $node) {
            $content = $this->reader->content($node);
            $oid = is_string($content) ? ASN1::getOIDFromName($content) : null;
            if ($this->reader->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $oid !== null && isset(self::ATTRIBUTES[$oid])) {
                $attribute = self::ATTRIBUTES[$oid];
                continue;
            }
            if ($attribute !== null && is_string($content) && $this->isValidValue($content)) {
                $subject[$attribute] = $content;
                $attribute = null;
            }
        }

        return $subject;
    }

    private function isValidValue(string $value): bool
    {
        return mb_check_encoding($value, 'UTF-8')
            && preg_match('/[\P{C}]/u', $value) === 1
            && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) !== 1;
    }
}
