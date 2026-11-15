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
        if ($value === null) {
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
        if (!$value instanceof PDFValue) {
            return [];
        }

        if (!$value instanceof PDFValueList) {
            throw new RuntimeException('Expected an array.');
        }

        $items = [];
        foreach ($value->val() as $item) {
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
}
