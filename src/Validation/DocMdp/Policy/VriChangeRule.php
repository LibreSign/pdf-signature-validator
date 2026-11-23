<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/**
 * Validate newly introduced DSS /VRI dictionaries and their evidence references.
 *
 * @psalm-import-type PdfObject from DocMdpRevisionState
 * @phpstan-import-type PdfObject from DocMdpRevisionState
 */
final class VriChangeRule
{
    private PdfSyntaxReader $syntax;

    public function __construct(?PdfSyntaxReader $syntax = null)
    {
        $this->syntax = $syntax ?? new PdfSyntaxReader();
    }

    /**
     * @param array<int,PdfObject> $objects
     * @param array<int,int> $introducedAt
     */
    public function allowsVri(string $vriValue, array $objects, array $introducedAt, int $revision): bool
    {
        $entries = $this->entriesFor($vriValue, $objects, $introducedAt, $revision);
        if ($entries === null || $entries === []) {
            return false;
        }

        foreach ($entries as $hash => $entryRef) {
            if (!preg_match('/^\/[A-Fa-f0-9]{40}$/', $hash)
                || !$this->allowsVriEntry($entryRef, $objects, $introducedAt, $revision)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<int,PdfObject> $objects
     * @param array<int,int> $introducedAt
     * @return array<string,string>|null
     */
    private function entriesFor(string $value, array $objects, array $introducedAt, int $revision): ?array
    {
        if (str_starts_with($value, '<<')) {
            return $this->syntax->parseDictionaryEntries($value);
        }
        if (!preg_match('/^(\d+) (\d+) R$/', $value, $ref)) {
            return null;
        }

        $number = (int) $ref[1];
        $object = $objects[$number] ?? null;
        if ($object === null || $object['gen'] !== (int) $ref[2]
            || $object['stream'] !== null
            || ($introducedAt[$number] ?? PHP_INT_MAX) > $revision) {
            return null;
        }

        return $object['entries'];
    }

    /**
     * @param array<int,PdfObject> $objects
     * @param array<int,int> $introducedAt
     */
    private function allowsVriEntry(string $value, array $objects, array $introducedAt, int $revision): bool
    {
        $data = $this->entriesFor($value, $objects, $introducedAt, $revision);
        if ($data === null || ($data['/Type'] ?? '/VRI') !== '/VRI') {
            return false;
        }
        foreach (array_keys($data) as $key) {
            if (!in_array($key, ['/Type', '/TU', '/TS', '/Cert', '/CRL', '/OCSP'], true)) {
                return false;
            }
        }

        $hasEvidence = false;
        foreach (['/Cert', '/CRL', '/OCSP'] as $key) {
            if (!isset($data[$key])) {
                continue;
            }
            $refs = $this->streamReferences($data[$key]);
            if ($refs === null) {
                return false;
            }
            foreach ($refs as $ref) {
                if (!$this->isAvailableStream($ref, $objects, $introducedAt, $revision)) {
                    return false;
                }
                $hasEvidence = true;
            }
        }

        return $hasEvidence;
    }

    /**
     * @return list<array{0:string,1:string,2:string}>|null
     */
    private function streamReferences(string $value): ?array
    {
        if (!preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $value, $array)) {
            return null;
        }
        preg_match_all('/(\d+) (\d+) R/', $array[1], $matches, PREG_SET_ORDER);

        $refs = [];
        foreach ($matches as $match) {
            $refs[] = [$match[0], $match[1], $match[2]];
        }

        return $refs;
    }

    /**
     * @param array{0:string,1:string,2:string} $reference
     * @param array<int,PdfObject> $objects
     * @param array<int,int> $introducedAt
     */
    private function isAvailableStream(array $reference, array $objects, array $introducedAt, int $revision): bool
    {
        $number = (int) $reference[1];
        $object = $objects[$number] ?? null;

        return $object !== null
            && $object['gen'] === (int) $reference[2]
            && $object['stream'] !== null
            && ($introducedAt[$number] ?? PHP_INT_MAX) <= $revision;
    }
}
