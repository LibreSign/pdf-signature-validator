<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Whitelist rules for catalog, form and annotation changes.
 */
final class DocMdpEntryChangePolicy
{
    private PdfSyntaxReader $syntax;

    public function __construct(?PdfSyntaxReader $syntax = null)
    {
        $this->syntax = $syntax ?? new PdfSyntaxReader();
    }

    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     * @param array<string,true> $timestampFields
     */
    public function allowsChangedEntries(
        DocMdpRevisionState $state,
        int $number,
        array $old,
        array $new,
        array $timestampFields,
    ): bool {
        return match (true) {
            $number === $state->rootNumber => $this->isAllowedCatalogChange($old, $new, $timestampFields),
            $number === $state->acroFormNumber => $this->isAllowedAcroFormChange($old, $new, $timestampFields),
            $number === $state->infoNumber => $this->isAllowedEntriesChange($old, $new, [], ['/ModDate', '/Producer'], $timestampFields),
            ($old['/Type'] ?? null) === '/Page' => $this->isAllowedEntriesChange($old, $new, ['/Annots'], [], $timestampFields),
            default => false,
        };
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param array<string, true> $timestampFields
     */
    private function isAllowedCatalogChange(array $old, array $new, array $timestampFields): bool
    {
        if (!$this->isAllowedEntriesChange($old, $new, [], ['/DSS', '/Extensions', '/Version', '/AcroForm'], $timestampFields)) {
            return false;
        }
        if (($old['/AcroForm'] ?? null) === ($new['/AcroForm'] ?? null)) {
            return true;
        }

        $oldAcroForm = $this->syntax->parseDictionaryEntries($old['/AcroForm'] ?? '<<>>');
        $newAcroForm = $this->syntax->parseDictionaryEntries($new['/AcroForm'] ?? '');
        return $oldAcroForm !== null
            && $newAcroForm !== null
            && $this->isAllowedAcroFormChange($oldAcroForm, $newAcroForm, $timestampFields);
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param array<string, true> $timestampFields
     */
    private function isAllowedAcroFormChange(array $old, array $new, array $timestampFields): bool
    {
        return $this->isAllowedEntriesChange($old, $new, ['/Fields'], ['/SigFlags'], $timestampFields);
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param list<string> $appendOnlyKeys Keys whose array may only gain timestamp fields
     * @param list<string> $freeKeys Keys whose value may change freely (checked elsewhere if needed)
     * @param array<string, true> $timestampFields References to the new timestamp fields
     */
    private function isAllowedEntriesChange(array $old, array $new, array $appendOnlyKeys, array $freeKeys, array $timestampFields): bool
    {
        foreach (array_keys($old + $new) as $key) {
            $oldValue = $old[$key] ?? null;
            $newValue = $new[$key] ?? null;
            if ($oldValue === $newValue || in_array($key, $freeKeys, true)) {
                continue;
            }
            if (!in_array($key, $appendOnlyKeys, true) || $newValue === null
                || !$this->isTimestampFieldAppend($oldValue ?? '[]', $newValue, $timestampFields)) {
                return false;
            }
        }
        return true;
    }

    /**
     * An array of references that keeps every old entry and only gains
     * references to the new timestamp fields.
     *
     * @param array<string, true> $timestampFields
     */
    private function isTimestampFieldAppend(string $old, string $new, array $timestampFields): bool
    {
        $oldRefs = $this->parseReferenceArray($old);
        $newRefs = $this->parseReferenceArray($new);
        if ($oldRefs === null || $newRefs === null || array_slice($newRefs, 0, count($oldRefs)) !== $oldRefs) {
            return false;
        }

        foreach (array_slice($newRefs, count($oldRefs)) as $ref) {
            if (!isset($timestampFields[$ref])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return list<string>|null References like "5 0 R", or null when the value is not an array of references only
     */
    private function parseReferenceArray(string $canonicalArray): ?array
    {
        if (!preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $canonicalArray, $match)) {
            return null;
        }
        preg_match_all('/\d+ \d+ R/', $match[1], $refs);
        return $refs[0];
    }
}
