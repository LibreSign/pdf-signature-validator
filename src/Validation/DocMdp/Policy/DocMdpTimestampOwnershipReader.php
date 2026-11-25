<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;

/** Resolves timestamp fields and their signature values from the live form. */
final class DocMdpTimestampOwnershipReader
{
    /**
     * @param array<string,true> $available
     * @return array{owner:int,path:string,timestamps:array<int,true>,values:array<int,int>}|null
     */
    public function read(PdfRevisionObjects $live, int $root, string $formValue, array $available): ?array
    {
        $form = $live->dictionary($formValue);
        if ($form === null) {
            return null;
        }
        $formOwner = $live->resolve($formValue)['num'] ?? $root;
        $fieldPath = $formOwner === $root ? '/AcroForm/Fields[]' : '/Fields[]';
        $fields = $live->referenceArray($form['/Fields'] ?? '[]');
        if ($fields === null) {
            return null;
        }
        $timestamps = [];
        $values = [];
        foreach (array_keys($available) as $reference) {
            if (!in_array($reference, $fields, true)) {
                continue;
            }
            $field = $live->resolve($reference);
            $value = $live->resolve($field['entries']['/V'] ?? '');
            if ($field === null || $value === null || isset($values[$value['num']])) {
                return null;
            }
            $timestamps[$field['num']] = true;
            $values[$value['num']] = $field['num'];
        }

        return ['owner' => $formOwner, 'path' => $fieldPath, 'timestamps' => $timestamps, 'values' => $values];
    }
}
