<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use DateTimeImmutable;
use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\File\ASN1;
use phpseclib4\Math\BigInteger;

/** @internal */
final class TstInfoParser
{
    public function __construct(
        private readonly Asn1NodeReader $reader,
    ) {
    }

    /**
     * @param array<string, string> $certificateSubject
     */
    public function parse(string $encoded, array $certificateSubject): ?TimestampToken
    {
        try {
            $root = ASN1::decodeBER($encoded);
        } catch (UnexpectedValueException) {
            return null;
        }
        if (($root['type'] ?? null) !== ASN1::TYPE_SEQUENCE) {
            return null;
        }

        $fields = $this->readFields($this->reader->children($root['content'] ?? null));
        return new TimestampToken(
            $fields['generatedAt'],
            $fields['policyOid'],
            $fields['serialNumber'],
            $certificateSubject,
        );
    }

    /**
     * @param list<array<array-key, mixed>> $nodes
     * @return array{generatedAt:?DateTimeImmutable,policyOid:?string,serialNumber:?string}
     */
    private function readFields(array $nodes): array
    {
        $policyOid = $this->findPolicyOid($nodes);
        $messageImprintIndex = $this->findMessageImprintIndex($nodes);

        return [
            'generatedAt' => $this->findGeneratedAt($nodes),
            'policyOid' => $policyOid,
            'serialNumber' => $messageImprintIndex === null ? null : $this->findSerialNumber($nodes, $messageImprintIndex),
        ];
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findPolicyOid(array $nodes): ?string
    {
        foreach ($nodes as $node) {
            $content = $this->reader->content($node);
            if ($this->reader->type($node) === ASN1::TYPE_OBJECT_IDENTIFIER && is_string($content)) {
                return ASN1::getOIDFromName($content);
            }
        }
        return null;
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findMessageImprintIndex(array $nodes): ?int
    {
        foreach ($nodes as $index => $node) {
            if ($this->reader->type($node) === ASN1::TYPE_SEQUENCE && $this->isMessageImprint($node)) {
                return $index;
            }
        }
        return null;
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findSerialNumber(array $nodes, int $afterIndex): ?string
    {
        foreach (array_slice($nodes, $afterIndex + 1) as $node) {
            if ($this->reader->type($node) === ASN1::TYPE_INTEGER) {
                return $this->integerToString($this->reader->content($node));
            }
        }
        return null;
    }

    /** @param list<array<array-key, mixed>> $nodes */
    private function findGeneratedAt(array $nodes): ?DateTimeImmutable
    {
        foreach ($nodes as $node) {
            $type = $this->reader->type($node);
            $content = $this->reader->content($node);
            if (($type === ASN1::TYPE_GENERALIZED_TIME || $type === ASN1::TYPE_UTC_TIME) && is_string($content)) {
                try {
                    return new DateTimeImmutable($content);
                } catch (\Exception) {
                    return null;
                }
            }
        }
        return null;
    }

    /** @param array<array-key, mixed> $node */
    private function isMessageImprint(array $node): bool
    {
        $hasAlgorithm = false;
        $hasDigest = false;
        foreach ($this->reader->children($node['content'] ?? null) as $part) {
            if ($this->reader->type($part) === ASN1::TYPE_SEQUENCE) {
                foreach ($this->reader->children($part['content'] ?? null) as $algorithmPart) {
                    $hasAlgorithm = $hasAlgorithm || $this->reader->type($algorithmPart) === ASN1::TYPE_OBJECT_IDENTIFIER;
                }
            }
            $hasDigest = $hasDigest || $this->reader->type($part) === ASN1::TYPE_OCTET_STRING;
        }
        return $hasAlgorithm && $hasDigest;
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
}
