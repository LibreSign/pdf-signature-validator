<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/**
 * Immutable live object map for a revision. No object is resolved from bytes
 * beyond the signed revision when constructing the original map.
 *
 * @psalm-import-type PdfObject from PdfIncrementalRevisionReader
 * @psalm-import-type SignedRevision from PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from PdfIncrementalRevisionReader
 * @phpstan-import-type SignedRevision from PdfIncrementalRevisionReader
 */
final class PdfRevisionObjects
{
    /** @param array<int,PdfObject> $objects */
    private function __construct(
        public readonly array $objects,
        public readonly int $originalSize,
    ) {
    }

    /** @param SignedRevision $signed */
    public static function fromSigned(
        string $signedContent,
        array $signed,
        PdfIncrementalRevisionReader $reader,
    ): ?self {
        $numbers = array_unique(array_merge(
            array_keys($signed['offsets']),
            array_keys($signed['compressedObjects'] ?? []),
        ));
        $objects = [];
        foreach ($numbers as $number) {
            $object = $reader->readSignedObject($signedContent, $signed, $number);
            if ($object === null || $object['end'] > strlen($signedContent)) {
                return null;
            }
            $objects[$number] = $object;
        }

        return new self($objects, $signed['size']);
    }

    /** @param array<int,PdfObject> $updates */
    public function apply(array $updates): ?self
    {
        foreach ($updates as $number => $object) {
            $old = $this->objects[$number] ?? null;
            if (($old !== null && $old['gen'] !== $object['gen'])
                || ($old === null && ($number < $this->originalSize || $object['gen'] !== 0))) {
                return null;
            }
        }

        return new self(array_replace($this->objects, $updates), $this->originalSize);
    }

    /** @return PdfObject|null */
    public function resolve(string $reference): ?array
    {
        if (!preg_match('/^(\d+) (\d+) R$/D', $reference, $match)) {
            return null;
        }
        $object = $this->objects[(int) $match[1]] ?? null;

        return $object !== null && $object['gen'] === (int) $match[2] ? $object : null;
    }

    /** @return array<string,string>|null */
    public function dictionary(string $value): ?array
    {
        if (str_starts_with($value, '<<')) {
            return (new PdfSyntaxReader())->parseDictionaryEntries($value);
        }
        $object = $this->resolve($value);

        return $object !== null && $object['stream'] === null ? $object['entries'] : null;
    }

    /** @return list<string>|null */
    public function referenceArray(string $value): ?array
    {
        if (!str_starts_with($value, '[')) {
            $object = $this->resolve($value);
            if ($object === null || $object['stream'] !== null) {
                return null;
            }
            $value = $object['value'];
        }
        if (!preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/D', $value, $match)) {
            return null;
        }
        preg_match_all('/\d+ \d+ R/', $match[1], $references);
        $result = [];
        foreach ($references[0] as $reference) {
            $object = $this->resolve($reference);
            if ($object === null) {
                return null;
            }
            $result[] = $object['num'] . ' ' . $object['gen'] . ' R';
        }

        return count($result) === count(array_unique($result)) ? $result : null;
    }

    /**
     * @param PdfObject $a
     * @param PdfObject $b
     */
    public static function same(array $a, array $b): bool
    {
        return $a['gen'] === $b['gen'] && $a['value'] === $b['value'] && $a['stream'] === $b['stream'];
    }

    /** @param array<string,string> $entries */
    public static function dictionaryValue(array $entries): string
    {
        ksort($entries);
        $values = [];
        foreach ($entries as $key => $value) {
            $values[] = $key . ' ' . $value;
        }

        return '<<' . implode(' ', $values) . '>>';
    }
}
