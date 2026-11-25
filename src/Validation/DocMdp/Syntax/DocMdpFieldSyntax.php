<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Syntax;

/** Canonical PDF field value and dictionary checks. */
final class DocMdpFieldSyntax
{
    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     * @param list<string> $keys
     */
    public function onlyChanges(array $old, array $new, array $keys): bool
    {
        foreach (array_keys($old + $new) as $key) {
            if (($old[$key] ?? null) !== ($new[$key] ?? null) && !in_array($key, $keys, true)) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string,string> $entries */
    public function appearanceStateIsValid(array $entries): bool
    {
        return (!isset($entries['/AS']) || $this->isName($entries['/AS']))
            && (!isset($entries['/M']) || $this->isText($entries['/M']));
    }

    public function isText(string $value): bool
    {
        return preg_match('/^<[0-9a-f]*>$/D', $value) === 1;
    }

    public function isName(string $value): bool
    {
        return preg_match('/^\/[^ \[\]()<>{}\/%]*$/D', $value) === 1;
    }
}
