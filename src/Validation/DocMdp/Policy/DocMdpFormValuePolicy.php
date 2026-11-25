<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Syntax\DocMdpFieldSyntax;

/** Authorization of value and appearance changes to an existing form field. */
final class DocMdpFormValuePolicy
{
    public function __construct(private readonly DocMdpFieldSyntax $syntax = new DocMdpFieldSyntax())
    {
    }

    public function isMutable(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number): bool
    {
        $field = $after->fields[$number];

        return in_array($field['type'], ['/Tx', '/Ch', '/Btn'], true)
            && $this->isWritable($before, $number)
            && $before->hasOnlyRoleReferences($number)
            && $after->hasOnlyRoleReferences($number)
            && ($field['entries']['/Subtype'] ?? '/Widget') === '/Widget';
    }

    private function isWritable(DocMdpDocumentGraph $graph, int $number): bool
    {
        while (true) {
            $field = $graph->fields[$number];
            if (isset($field['entries']['/Ff'])) {
                $flags = $field['entries']['/Ff'];
                return ctype_digit($flags) && ((int) $flags & 1) === 0;
            }
            if ($field['parent'] === null) {
                return true;
            }
            $number = $field['parent'];
        }
    }

    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     */
    public function allowsValueChange(array $old, array $new, string $type, ?int $parent): bool
    {
        $keys = ['/AP', '/AS', '/M'];
        if ($parent === null || isset($old['/T']) || isset($old['/FT'])) {
            $keys[] = '/V';
            if ($type === '/Ch') {
                $keys[] = '/I';
            }
        }
        if (!$this->syntax->onlyChanges($old, $new, $keys) || !$this->syntax->appearanceStateIsValid($new)) {
            return false;
        }
        $value = $new['/V'] ?? 'null';
        if ($value !== 'null') {
            $valid = match ($type) {
                '/Tx' => $this->syntax->isText($value),
                '/Ch' => $this->syntax->isText($value) || preg_match('/^\[(?:<[0-9a-f]*>(?: |(?=\])))*\]$/D', $value) === 1,
                '/Btn' => $this->syntax->isName($value),
                default => false,
            };
            if (!$valid) {
                return false;
            }
        }

        return !isset($new['/I']) || preg_match('/^\[(?:\d+(?: |(?=\])))*\]$/D', $new['/I']) === 1;
    }
}
