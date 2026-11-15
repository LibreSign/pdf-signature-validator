<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use RuntimeException;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\PDFObject;
use SignerPHP\PdfCore\PdfValue\PDFValue;
use SignerPHP\PdfCore\PdfValue\PDFValueList;
use SignerPHP\PdfCore\PdfValue\PDFValueObject;
use SignerPHP\PdfCore\PdfValue\PDFValueSimple;
use SignerPHP\PdfCore\PdfValue\PDFValueType;

/**
 * Follows indirect references in a parsed PDF and reads typed values.
 *
 * Anything that does not have the expected shape throws, so callers can
 * treat the document as unreadable instead of guessing.
 *
 * @internal
 */
final class PdfObjectResolver
{
    public function __construct(
        private readonly PdfDocument $document,
    ) {
    }

    /**
     * @param int|PDFValue|null $value an inline dictionary, a reference or an object number
     */
    public function dictionary(int|PDFValue|null $value): ?PDFValueObject
    {
        if ($value === null || $this->isNull($value)) {
            return null;
        }

        if ($value instanceof PDFValueObject) {
            return $value;
        }

        $objectNumber = $this->reference($value);
        if ($objectNumber === null) {
            throw new RuntimeException('Expected a dictionary or a reference to one.');
        }

        $object = $this->document->getObject($objectNumber);
        if (!$object instanceof PDFObject) {
            throw new RuntimeException(sprintf('Object %d is missing.', $objectNumber));
        }

        return $object->getValue();
    }

    /**
     * The items of an array, with each indirect reference as an object number.
     *
     * pdf-core keeps adjacent references in one token, such as "7 0 R 8 0 R".
     *
     * @return list<int|PDFValue>
     */
    public function items(?PDFValue $value): array
    {
        if (!$value instanceof PDFValue || $this->isNull($value)) {
            return [];
        }

        $items = [];
        foreach ($this->arrayEntries($value) as $item) {
            if (!$item instanceof PDFValue) {
                throw new RuntimeException('Unexpected array item.');
            }

            if (!$item instanceof PDFValueSimple || preg_match('/^\s*(?:\d+\s+\d+\s+R\s*)+$/', (string)$item) !== 1) {
                $items[] = $item;
                continue;
            }

            preg_match_all('/(\d+)\s+\d+\s+R/', (string)$item, $matches);
            foreach ($matches[1] as $objectNumber) {
                $items[] = (int)$objectNumber;
            }
        }

        return $items;
    }

    /**
     * The numbers of an array, such as a /ByteRange.
     *
     * @return list<int>
     */
    public function integers(?PDFValue $value): array
    {
        if (!$value instanceof PDFValueList) {
            throw new RuntimeException('Expected an array of integers.');
        }

        $numbers = [];
        foreach ($value->val(true) as $item) {
            if (!is_string($item) || preg_match('/^\d+$/', $item) !== 1) {
                throw new RuntimeException('Expected an array of integers.');
            }

            $numbers[] = (int)$item;
        }

        return $numbers;
    }

    public function reference(int|PDFValue|null $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (!$value instanceof PDFValueSimple) {
            return null;
        }

        $objectNumber = $value->asObjectReferenceOrNull();

        return is_int($objectNumber) ? $objectNumber : null;
    }

    public function name(?PDFValue $value): ?string
    {
        return $value instanceof PDFValueType ? (string)$value->val() : null;
    }

    /**
     * ISO 32000-1, 7.3.9: a null entry is the same as an omitted one.
     */
    private function isNull(int|PDFValue $value): bool
    {
        return $value instanceof PDFValueSimple && (string)$value->val() === 'null';
    }

    /**
     * A direct array, or an indirect one. pdf-core stores an indirect array
     * as a dictionary keyed 0, 1, 2 and so on.
     *
     * @return array<array-key, mixed>
     */
    private function arrayEntries(PDFValue $value): array
    {
        if ($value instanceof PDFValueList) {
            return $value->val();
        }

        $objectNumber = $this->reference($value);
        $entries = $objectNumber === null ? null : $this->dictionary($objectNumber)?->val();
        if (!is_array($entries) || !array_is_list($entries)) {
            throw new RuntimeException('Expected an array.');
        }

        return $entries;
    }
}
