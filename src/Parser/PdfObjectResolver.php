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
     * A reference to a missing object throws instead of counting as null
     * (ISO 32000-1, 7.3.9), since a broken cross-reference table could hide
     * a real signature.
     *
     * @param PDFValue|null $value an inline dictionary or a reference
     */
    public function dictionary(?PDFValue $value): ?PDFValueObject
    {
        if (!$value instanceof PDFValue || $this->isNull($value)) {
            return null;
        }

        if ($value instanceof PDFValueObject) {
            return $value;
        }

        $object = $this->resolve($value);
        if (!$this->isWrappedValue($object)) {
            return $object;
        }

        $entries = $this->entries($object);
        if (count($entries) === 1 && $entries[0] instanceof PDFValue && $this->isNull($entries[0])) {
            return null;
        }

        throw new RuntimeException('Expected a dictionary.');
    }

    /**
     * The /Type of an object, or null when the object is not a dictionary.
     */
    public function typeOf(int $objectNumber): ?string
    {
        $object = $this->resolve($objectNumber);

        return $this->isWrappedValue($object) ? null : $this->name($this->get($object, 'Type'));
    }

    /**
     * A dictionary entry. pdf-core keeps the #xx escapes of a key (ISO
     * 32000-1, 7.3.5), so keys are compared decoded. Two keys that decode
     * to the same name are a duplicate key (7.3.7).
     */
    public function get(?PDFValueObject $dictionary, string $key): ?PDFValue
    {
        $found = array_filter(
            $this->entries($dictionary),
            fn (int|string $rawKey): bool => $this->decodeName((string)$rawKey) === $key,
            ARRAY_FILTER_USE_KEY,
        );
        if (count($found) > 1) {
            throw new RuntimeException(sprintf('The /%s key is repeated.', $key));
        }

        /** @var mixed $value */
        $value = reset($found);

        return $value instanceof PDFValue ? $value : null;
    }

    /**
     * The items of an array, with each indirect reference as its own value.
     *
     * pdf-core keeps adjacent references in one token, such as "7 0 R 8 0 R".
     *
     * @return list<PDFValue>
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

            preg_match_all('/\d+\s+\d+\s+R/', (string)$item, $matches);
            foreach ($matches[0] as $reference) {
                $items[] = new PDFValueSimple($reference);
            }
        }

        return $items;
    }

    /**
     * The non-negative integers of an array, such as a /ByteRange. ISO
     * 32000-1, 7.3.3, allows a leading plus sign.
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
            if (!is_string($item) || preg_match('/^\+?\d+\z/', $item) !== 1) {
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
        return $value instanceof PDFValueType ? $this->decodeName((string)$value->val()) : null;
    }

    /**
     * ISO 32000-1, 7.3.9: a null entry is the same as an omitted one.
     */
    public function isNull(PDFValue $value): bool
    {
        return $value instanceof PDFValueSimple && (string)$value->val() === 'null';
    }

    /**
     * A direct array, or an indirect one.
     *
     * @return array<array-key, mixed>
     */
    private function arrayEntries(PDFValue $value): array
    {
        if ($value instanceof PDFValueList) {
            return $value->val();
        }

        $entries = $this->entries($this->resolve($value));
        if (!array_is_list($entries)) {
            throw new RuntimeException('Expected an array.');
        }

        return $entries;
    }

    /**
     * A reference must name the generation of the object it reaches (ISO
     * 32000-1, 7.3.10). pdf-core reads that generation from the object header.
     * An object number on its own comes from the cross-reference table.
     */
    private function resolve(int|PDFValue $value): PDFValueObject
    {
        $objectNumber = $this->reference($value);
        if ($objectNumber === null) {
            throw new RuntimeException('Expected a reference.');
        }

        $object = $this->document->getObject($objectNumber);
        if (!$object instanceof PDFObject) {
            throw new RuntimeException(sprintf('Object %d is missing.', $objectNumber));
        }

        if (
            $value instanceof PDFValue
            && preg_match('/^\s*\d+\s+(\d+)\s+R\s*$/', (string)$value, $matches) === 1
            && (int)$matches[1] !== $object->getGeneration()
        ) {
            throw new RuntimeException(sprintf('Object %d has another generation.', $objectNumber));
        }

        return $object->getValue();
    }

    /**
     * A name writes a character as #xx (7.3.5) and cannot hold a raw %, which
     * starts a comment, so this is the same as URL percent decoding.
     */
    private function decodeName(string $name): string
    {
        return rawurldecode(strtr($name, '#', '%'));
    }

    /**
     * pdf-core stores an indirect object that is not a dictionary, such as an
     * array, a number or null, as a dictionary keyed 0, 1, 2 and so on.
     */
    private function isWrappedValue(PDFValueObject $object): bool
    {
        $entries = $this->entries($object);

        return $entries !== [] && array_is_list($entries);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function entries(?PDFValueObject $object): array
    {
        /** @var mixed $entries */
        $entries = $object?->val();

        return is_array($entries) ? $entries : [];
    }
}
