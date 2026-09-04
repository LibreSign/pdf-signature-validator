<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;

final class CmsTimestampExtractor
{
    private const TIMESTAMP_TOKEN_OID = '1.2.840.113549.1.9.16.2.14';
    private const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';

    public function __construct(
        private readonly Asn1NodeReader $reader = new Asn1NodeReader(),
        private readonly CertificateSubjectExtractor $certificateSubjectExtractor = new CertificateSubjectExtractor(new Asn1NodeReader()),
        private readonly TstInfoParser $tstInfoParser = new TstInfoParser(new Asn1NodeReader()),
    ) {
        ASN1::loadOIDs('CMS');
    }

    public function extract(string $cmsDer): ?TimestampToken
    {
        try {
            $root = $this->reader->decode($cmsDer);
        } catch (UnexpectedValueException) {
            return null;
        }

        $timestampContent = $this->findTimestampTokenContent($root);
        if ($timestampContent === null) {
            return null;
        }

        try {
            $timestampCms = $this->reader->decode($timestampContent);
        } catch (UnexpectedValueException) {
            return null;
        }
        $tstInfo = $this->findContentAfterOid($timestampCms, self::TST_INFO_OID, ASN1::TYPE_OCTET_STRING);
        if ($tstInfo === null) {
            return null;
        }

        return $this->tstInfoParser->parse($tstInfo, $this->certificateSubjectExtractor->extract($timestampCms));
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findTimestampTokenContent(array $nodes): ?string
    {
        $foundTokenOid = false;
        foreach ($this->reader->walk($nodes) as $node) {
            if ($this->reader->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $this->reader->matchesOid($this->reader->content($node), self::TIMESTAMP_TOKEN_OID)) {
                $foundTokenOid = true;
                continue;
            }

            if (!$foundTokenOid || $this->reader->type($node) !== ASN1::TYPE_SET) {
                continue;
            }

            foreach ($this->reader->children($node['content'] ?? null) as $candidate) {
                $content = $this->reader->content($candidate);
                if ($content instanceof Constructed) {
                    return $content->getEncoded();
                }
            }
        }

        return null;
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findContentAfterOid(array $nodes, string $oid, int $expectedType): ?string
    {
        $foundOid = false;
        foreach ($this->reader->walk($nodes) as $node) {
            if ($this->reader->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $this->reader->matchesOid($this->reader->content($node), $oid)) {
                $foundOid = true;
                continue;
            }

            $content = $this->reader->content($node);
            if ($foundOid && $this->reader->type($node) === $expectedType && is_string($content)) {
                return $content;
            }
        }

        return null;
    }

}
