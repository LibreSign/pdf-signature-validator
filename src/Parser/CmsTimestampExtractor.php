<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Types\BaseType;
use phpseclib4\Math\BigInteger;

final class CmsTimestampExtractor
{
    private const TIMESTAMP_TOKEN_OID = '1.2.840.113549.1.9.16.2.14';
    private const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';

    /** @var array<string, string> */
    private const CERTIFICATE_ATTRIBUTE_OIDS = [
        '2.5.4.3' => 'commonName',
        '2.5.4.6' => 'countryName',
        '2.5.4.10' => 'organizationName',
        '1.2.840.113549.1.9.1' => 'emailAddress',
    ];

    public function __construct()
    {
        ASN1::loadOIDs('CMS');
    }

    public function extract(string $cmsDer): ?TimestampToken
    {
        try {
            $root = ASN1::decodeBER($cmsDer);
        } catch (UnexpectedValueException) {
            return null;
        }

        $root = $this->normalizeNodes($root);
        $timestampContent = $this->findTimestampTokenContent($root);
        if ($timestampContent === null) {
            return null;
        }

        try {
            $timestampCms = ASN1::decodeBER($timestampContent);
        } catch (UnexpectedValueException) {
            return null;
        }
        $timestampCms = $this->normalizeNodes($timestampCms);

        $tstInfo = $this->findContentAfterOid($timestampCms, self::TST_INFO_OID, ASN1::TYPE_OCTET_STRING);
        if ($tstInfo === null) {
            return null;
        }

        return $this->parseTstInfo($tstInfo, $this->extractCertificateSubject($timestampCms));
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findTimestampTokenContent(array $nodes): ?string
    {
        $foundTokenOid = false;
        foreach ($this->walk($nodes) as $node) {
            if ($this->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $this->matchesOid($this->content($node), self::TIMESTAMP_TOKEN_OID)) {
                $foundTokenOid = true;
                continue;
            }

            if (!$foundTokenOid || $this->type($node) !== ASN1::TYPE_SET) {
                continue;
            }

            foreach ($this->children($node['content'] ?? null) as $candidate) {
                $content = $this->content($candidate);
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
        foreach ($this->walk($nodes) as $node) {
            if ($this->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $this->matchesOid($this->content($node), $oid)) {
                $foundOid = true;
                continue;
            }

            $content = $this->content($node);
            if ($foundOid && $this->type($node) === $expectedType && is_string($content)) {
                return $content;
            }
        }

        return null;
    }

    /** @param array<string, string> $certificateSubject */
    private function parseTstInfo(string $tstInfo, array $certificateSubject): ?TimestampToken
    {
        try {
            $root = ASN1::decodeBER($tstInfo);
        } catch (UnexpectedValueException) {
            return null;
        }

        if (($root['type'] ?? null) !== ASN1::TYPE_SEQUENCE) {
            return null;
        }

        $policyOid = null;
        $serialNumber = null;
        $generatedAt = null;
        $messageImprintFound = false;

        foreach ($this->children($root['content'] ?? null) as $node) {
            $type = $this->type($node);
            $content = $this->content($node);
            if ($policyOid === null && $type === ASN1::TYPE_OBJECT_IDENTIFIER && is_string($content)) {
                $policyOid = ASN1::getOIDFromName($content);
                continue;
            }
            if (!$messageImprintFound && $type === ASN1::TYPE_SEQUENCE && $this->isMessageImprint($node)) {
                $messageImprintFound = true;
                continue;
            }
            if ($messageImprintFound && $serialNumber === null && $type === ASN1::TYPE_INTEGER) {
                $serialNumber = $this->integerToString($content);
                continue;
            }
            if (($type === ASN1::TYPE_GENERALIZED_TIME || $type === ASN1::TYPE_UTC_TIME) && is_string($content)) {
                try {
                    $generatedAt = new \DateTimeImmutable($content);
                } catch (\Exception) {
                    return null;
                }
            }
        }

        return new TimestampToken($generatedAt, $policyOid, $serialNumber, $certificateSubject);
    }

    /** @param array<array-key, mixed> $node */
    private function isMessageImprint(array $node): bool
    {
        $hasAlgorithm = false;
        $hasDigest = false;
        foreach ($this->children($node['content'] ?? null) as $part) {
            if (($part['type'] ?? null) === ASN1::TYPE_SEQUENCE) {
                foreach ($this->children($part['content'] ?? null) as $algorithmPart) {
                    if (($algorithmPart['type'] ?? null) === ASN1::TYPE_OBJECT_IDENTIFIER) {
                        $hasAlgorithm = true;
                    }
                }
            }
            if (($part['type'] ?? null) === ASN1::TYPE_OCTET_STRING) {
                $hasDigest = true;
            }
        }

        return $hasAlgorithm && $hasDigest;
    }

    /** @param list<array<array-key, mixed>> $nodes
     * @return array<string, string>
     */
    private function extractCertificateSubject(array $nodes): array
    {
        $subject = [];
        $attributeOid = null;
        foreach ($this->walk($nodes) as $node) {
            $content = $this->content($node);
            $oid = is_string($content) ? ASN1::getOIDFromName($content) : null;
            if ($this->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER
                && $oid !== null && isset(self::CERTIFICATE_ATTRIBUTE_OIDS[$oid])) {
                $attributeOid = $oid;
                continue;
            }
            if ($attributeOid !== null && is_string($content) && $this->isValidUtf8($content)) {
                $subject[self::CERTIFICATE_ATTRIBUTE_OIDS[$attributeOid]] = $content;
                $attributeOid = null;
            }
        }

        return $subject;
    }

    /** @param list<array<array-key, mixed>> $nodes
    * @return \Generator<array<array-key, mixed>>
     */
    private function walk(array $nodes): \Generator
    {
        $pending = $nodes;
        while ($pending !== []) {
            $node = array_shift($pending);
            yield $node;
            array_unshift($pending, ...$this->children($node['content'] ?? null));
        }
    }

    /** @return list<array<array-key, mixed>> */
    private function children(mixed $content): array
    {
        if (is_array($content)) {
            return array_values(array_filter($content, 'is_array'));
        }
        if (!$content instanceof Constructed) {
            return [];
        }

        $encoded = $content->getEncodedWithoutHeader();
        $children = [];
        $offset = 0;
        while ($offset < strlen($encoded)) {
            try {
                $child = ASN1::decodeBER(substr($encoded, $offset));
            } catch (UnexpectedValueException) {
                break;
            }
            $headerLength = $child['headerlength'] ?? null;
            $length = $child['length'] ?? null;
            if (!is_int($headerLength) || !is_int($length)) {
                break;
            }
            $children[] = $child;
            $offset += $headerLength + $length;
        }

        return $children;
    }

    /** @param array<array-key, mixed> $node */
    private function content(array $node): array|Constructed|string|null
    {
        if (!isset($node['content'])) {
            return null;
        }
        if ($node['content'] instanceof Constructed) {
            return $node['content'];
        }
        if ($node['content'] instanceof BaseType) {
            return $this->primitiveContent(ASN1::convertToPrimitive($node['content']));
        }

        return is_array($node['content']) || is_string($node['content'])
            ? $node['content']
            : null;
    }

    private function primitiveContent(mixed $content): array|Constructed|string|null
    {
        return is_array($content) || $content instanceof Constructed || is_string($content) ? $content : null;
    }

    /** @return list<array<array-key, mixed>> */
    private function normalizeNodes(array $decoded): array
    {
        if (isset($decoded['type'])) {
            return [$decoded];
        }

        return array_values(array_filter($decoded, 'is_array'));
    }

    /** @param array<array-key, mixed> $node */
    private function type(array $node): ?int
    {
        return isset($node['type']) && is_int($node['type']) ? $node['type'] : null;
    }

    private function matchesOid(mixed $candidate, string $expected): bool
    {
        return is_string($candidate)
            && ASN1::getOIDFromName($candidate) === ASN1::getOIDFromName($expected);
    }

    private function integerToString(mixed $value): ?string
    {
        return match (true) {
            $value instanceof BigInteger => $value->toString(),
            is_int($value) => (string) $value,
            is_string($value) && ctype_digit($value) => $value,
            default => null,
        };
    }

    private function isValidUtf8(string $value): bool
    {
        return mb_check_encoding($value, 'UTF-8')
            && preg_match('/[\P{C}]/u', $value) === 1
            && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) !== 1;
    }
}
