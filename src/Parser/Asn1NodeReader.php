<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use phpseclib4\Exception\UnexpectedValueException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Types\BaseType;

/** @internal */
final class Asn1NodeReader
{
    /** @return list<array<array-key, mixed>> */
    public function decode(string $encoded): array
    {
        return $this->normalize(ASN1::decodeBER($encoded));
    }

    /**
     * @param list<array<array-key, mixed>> $nodes
     * @return \Generator<array<array-key, mixed>>
     */
    public function walk(array $nodes): \Generator
    {
        $pending = $nodes;
        while ($pending !== []) {
            $node = array_shift($pending);
            yield $node;
            array_unshift($pending, ...$this->children($node['content'] ?? null));
        }
    }

    /** @return list<array<array-key, mixed>> */
    public function children(mixed $content): array
    {
        if (is_array($content)) {
            return array_values(array_filter($content, 'is_array'));
        }
        if (!$content instanceof Constructed) {
            return [];
        }

        $children = [];
        $encoded = $content->getEncodedWithoutHeader();
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
    public function content(array $node): array|Constructed|string|null
    {
        if (!isset($node['content'])) {
            return null;
        }
        if ($node['content'] instanceof Constructed) {
            return $node['content'];
        }
        if ($node['content'] instanceof BaseType) {
            $content = ASN1::convertToPrimitive($node['content']);
            return is_string($content) ? $content : null;
        }

        return is_array($node['content']) || is_string($node['content']) ? $node['content'] : null;
    }

    /** @param array<array-key, mixed> $node */
    public function type(array $node): ?int
    {
        return isset($node['type']) && is_int($node['type']) ? $node['type'] : null;
    }

    public function matchesOid(mixed $candidate, string $expected): bool
    {
        return is_string($candidate)
            && ASN1::getOIDFromName($candidate) === ASN1::getOIDFromName($expected);
    }

    /** @return list<array<array-key, mixed>> */
    private function normalize(array $decoded): array
    {
        return isset($decoded['type']) ? [$decoded] : array_values(array_filter($decoded, 'is_array'));
    }
}
