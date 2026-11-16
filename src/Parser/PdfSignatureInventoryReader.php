<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use RuntimeException;
use SignerPHP\PdfCore\PdfDocument;
use SignerPHP\PdfCore\PdfValue\PDFValue;
use SignerPHP\PdfCore\PdfValue\PDFValueObject;
use SignerPHP\PdfCore\PdfValue\PDFValueSimple;
use SignerPHP\PdfCore\Service\PdfDocumentPreparer;
use Throwable;

/**
 * Finds the signatures a PDF actually uses by following its object structure.
 */
final class PdfSignatureInventoryReader
{
    /**
     * @param resource $resource
     */
    public function readFromResource($resource): SignatureInventory
    {
        rewind($resource);

        return $this->readFromString((string) stream_get_contents($resource));
    }

    public function readFromString(string $pdfContent): SignatureInventory
    {
        try {
            $document = (new PdfDocumentPreparer())->prepare($pdfContent);
            $resolver = new PdfObjectResolver($document);
            $activeSignatures = $this->findActiveSignatures($document, $resolver);

            return new SignatureInventory(
                true,
                count($activeSignatures),
                $this->countOrphanedSignatures($document, $resolver, $activeSignatures),
                $this->findDocMdpPermission($resolver, $activeSignatures, strlen($pdfContent)),
            );
        } catch (Throwable) {
            return new SignatureInventory(false);
        }
    }

    /**
     * @return array<int|string, PDFValueObject> keyed by object number, or by
     *                                           a string for inline dictionaries
     */
    private function findActiveSignatures(PdfDocument $document, PdfObjectResolver $resolver): array
    {
        $trailer = $document->getTrailerObject();
        $catalog = $resolver->dictionary($trailer instanceof PDFValueObject ? $trailer->get('Root') : null);

        if (!$catalog instanceof PDFValueObject) {
            throw new RuntimeException('The document catalog is missing.');
        }

        $signatures = [];
        $permissions = $resolver->dictionary($catalog->get('Perms'));
        $this->addSignature($resolver, $permissions?->get('DocMDP'), $signatures);

        $acroForm = $resolver->dictionary($catalog->get('AcroForm'));
        $visited = [];
        $this->collectFieldSignatures($resolver, $acroForm?->get('Fields'), null, $signatures, $visited);

        return $signatures;
    }

    /**
     * Walks the field tree. /FT is inheritable, so kids get their parent's type.
     *
     * @param array<int|string, PDFValueObject> $signatures
     * @param array<int, true> $visited
     */
    private function collectFieldSignatures(
        PdfObjectResolver $resolver,
        ?PDFValue $fields,
        ?string $inheritedType,
        array &$signatures,
        array &$visited,
    ): void {
        foreach ($resolver->items($fields) as $fieldValue) {
            $objectNumber = $resolver->reference($fieldValue);
            if ($objectNumber !== null && isset($visited[$objectNumber])) {
                continue;
            }

            if ($objectNumber !== null) {
                $visited[$objectNumber] = true;
            }

            $field = $resolver->dictionary($fieldValue);
            if (!$field instanceof PDFValueObject) {
                continue;
            }

            $type = $resolver->name($field->get('FT')) ?? $inheritedType;
            if ($type === 'Sig') {
                $this->addSignature($resolver, $field->get('V'), $signatures);
            }

            $this->collectFieldSignatures($resolver, $field->get('Kids'), $type, $signatures, $visited);
        }
    }

    /**
     * @param array<int|string, PDFValueObject> $signatures
     */
    private function addSignature(PdfObjectResolver $resolver, ?PDFValue $value, array &$signatures): void
    {
        $signature = $resolver->dictionary($value);
        if (!$signature instanceof PDFValueObject) {
            return;
        }

        $signatures[$resolver->reference($value) ?? 'inline-' . count($signatures)] = $signature;
    }

    /**
     * @param array<int|string, PDFValueObject> $activeSignatures
     */
    private function countOrphanedSignatures(
        PdfDocument $document,
        PdfObjectResolver $resolver,
        array $activeSignatures,
    ): int {
        $count = 0;

        foreach ($document->getXrefEntries() as $objectNumber => $entry) {
            if ($entry->isFree() || isset($activeSignatures[$objectNumber])) {
                continue;
            }

            $type = $resolver->typeOf($objectNumber);
            if ($type === 'Sig' || $type === 'DocTimeStamp') {
                $count++;
            }
        }

        return $count;
    }

    /**
     * The DocMDP permission of the certification signature. ISO 32000-1,
     * 12.8.2.2.1 allows one certification, and it must be the first signature.
     *
     * @param array<int|string, PDFValueObject> $signatures
     */
    private function findDocMdpPermission(
        PdfObjectResolver $resolver,
        array $signatures,
        int $fileSize,
    ): ?DocMdpPermission {
        $permission = null;
        $certification = null;

        foreach ($signatures as $key => $signature) {
            $level = $this->docMdpPermissionOf($resolver, $signature);
            if (!$level instanceof DocMdpPermission) {
                continue;
            }

            if ($certification !== null) {
                throw new RuntimeException('More than one certification signature is active.');
            }

            $certification = $key;
            $permission = $level;
        }

        if ($certification !== null) {
            $this->assertSignedFirst($resolver, $signatures, $certification, $fileSize);
        }

        return $permission;
    }

    /**
     * Each signature covers the revisions before it, so the one whose
     * /ByteRange ends first was applied first.
     *
     * @param array<int|string, PDFValueObject> $signatures
     */
    private function assertSignedFirst(
        PdfObjectResolver $resolver,
        array $signatures,
        int|string $key,
        int $fileSize,
    ): void {
        if (count($signatures) === 1) {
            return;
        }

        $end = $this->signedRangeEnd($resolver, $signatures[$key], $fileSize);
        foreach ($signatures as $otherKey => $signature) {
            if ($otherKey !== $key && $this->signedRangeEnd($resolver, $signature, $fileSize) <= $end) {
                throw new RuntimeException('The certification signature is not the first signature.');
            }
        }
    }

    /**
     * The /ByteRange is a list of (offset, length) pairs, usually two (ISO
     * 32000-1, table 252). Pairs that overlap or end after the file cannot
     * describe the bytes that were signed.
     */
    private function signedRangeEnd(PdfObjectResolver $resolver, PDFValueObject $signature, int $fileSize): int
    {
        $byteRange = $resolver->integers($signature->get('ByteRange'));
        if ($byteRange === [] || count($byteRange) % 2 !== 0) {
            throw new RuntimeException('The signature /ByteRange is not a list of offset and length pairs.');
        }

        $end = 0;
        foreach (array_chunk($byteRange, 2) as [$offset, $length]) {
            if ($offset < $end || $offset + $length > $fileSize) {
                throw new RuntimeException('The signature /ByteRange overlaps itself or ends after the file.');
            }

            $end = $offset + $length;
        }

        return $end;
    }

    /**
     * ISO 32000-1 sets no precedence between two DocMDP transforms in one
     * signature, so transforms that disagree leave the permission unknown.
     */
    private function docMdpPermissionOf(PdfObjectResolver $resolver, PDFValueObject $signature): ?DocMdpPermission
    {
        $permission = null;

        foreach ($resolver->items($signature->get('Reference')) as $referenceValue) {
            $reference = $resolver->dictionary($referenceValue);
            if ($resolver->name($reference?->get('TransformMethod')) !== 'DocMDP') {
                continue;
            }

            $level = $this->permissionLevel($resolver, $resolver->dictionary($reference?->get('TransformParams')));
            if ($permission instanceof DocMdpPermission && $permission !== $level) {
                throw new RuntimeException('The DocMDP transforms of a signature disagree.');
            }

            $permission = $level;
        }

        return $permission;
    }

    /**
     * ISO 32000-1, table 254: /P is 1, 2 or 3, and defaults to 2.
     */
    private function permissionLevel(PdfObjectResolver $resolver, ?PDFValueObject $parameters): DocMdpPermission
    {
        $value = $parameters?->get('P');
        if (!$value instanceof PDFValue || $resolver->isNull($value)) {
            return DocMdpPermission::FORM_FILLING;
        }

        $number = $value instanceof PDFValueSimple ? (string)$value->val() : '';
        if (preg_match('/^[123]\z/', $number) !== 1) {
            throw new RuntimeException('The DocMDP /P value is not 1, 2 or 3.');
        }

        return DocMdpPermission::from((int)$number);
    }
}
