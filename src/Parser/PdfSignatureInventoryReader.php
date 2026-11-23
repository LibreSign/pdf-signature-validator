<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
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
            [$activeSignatures, $catalogCertification] = $this->findActiveSignatures($document, $resolver);

            [$permission, $details] = $this->findDocMdpPermission(
                $resolver,
                $activeSignatures,
                $catalogCertification,
                strlen($pdfContent),
            );

            return new SignatureInventory(
                true,
                count($activeSignatures),
                $this->countOrphanedSignatures($document, $resolver, $activeSignatures),
                $permission,
                $details,
            );
        } catch (Throwable) {
            return new SignatureInventory(false);
        }
    }

    /**
     * The active signatures, keyed by object number or by a string for inline
     * dictionaries, and the key of the one /Perms /DocMDP references.
     *
     * @return array{array<int|string, PDFValueObject>, int|string|null}
     */
    private function findActiveSignatures(PdfDocument $document, PdfObjectResolver $resolver): array
    {
        $trailer = $document->getTrailerObject();
        $catalog = $resolver->dictionary($trailer instanceof PDFValueObject ? $resolver->get($trailer, 'Root') : null);

        if (!$catalog instanceof PDFValueObject) {
            throw new RuntimeException('The document catalog is missing.');
        }

        $signatures = [];
        $permissions = $resolver->dictionary($resolver->get($catalog, 'Perms'));
        $catalogCertification = $this->addSignature($resolver, $resolver->get($permissions, 'DocMDP'), $signatures);

        $acroForm = $resolver->dictionary($resolver->get($catalog, 'AcroForm'));
        $visited = [];
        $this->collectFieldSignatures($resolver, $resolver->get($acroForm, 'Fields'), null, $signatures, $visited);

        return [$signatures, $catalogCertification];
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
            // Resolve before checking visited objects: an invalid generation must not be skipped.
            $field = $resolver->dictionary($fieldValue);
            $objectNumber = $resolver->reference($fieldValue);
            if ($objectNumber !== null && isset($visited[$objectNumber])) {
                continue;
            }

            if ($objectNumber !== null) {
                $visited[$objectNumber] = true;
            }

            if (!$field instanceof PDFValueObject) {
                continue;
            }

            $type = $resolver->name($resolver->get($field, 'FT')) ?? $inheritedType;
            if ($type === 'Sig') {
                $this->addSignature($resolver, $resolver->get($field, 'V'), $signatures);
            }

            $this->collectFieldSignatures($resolver, $resolver->get($field, 'Kids'), $type, $signatures, $visited);
        }
    }

    /**
     * @param array<int|string, PDFValueObject> $signatures
     */
    private function addSignature(PdfObjectResolver $resolver, ?PDFValue $value, array &$signatures): int|string|null
    {
        $signature = $resolver->dictionary($value);
        if (!$signature instanceof PDFValueObject) {
            return null;
        }

        $key = $resolver->reference($value) ?? 'inline-' . count($signatures);
        $signatures[$key] = $signature;

        return $key;
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
                continue;
            }

            // /Type is optional on signature dictionaries. Do not miss an
            // unreferenced one just because it lacks that discriminator.
            if ($type !== null) {
                continue;
            }
            $dictionary = $document->getObject($objectNumber)?->getValue();
            if ($dictionary instanceof PDFValueObject
                && $resolver->get($dictionary, 'ByteRange') instanceof PDFValue
                && $resolver->get($dictionary, 'Contents') instanceof PDFValue
                && $resolver->get($dictionary, 'Filter') instanceof PDFValue) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * The DocMDP permission of the certification signature. ISO 32000-1,
     * 12.8.2.2.1 allows one certification, and it must be the first signature.
     * The signature /Perms /DocMDP references must be that certification
     * (12.8.4, table 258).
     *
     * @param array<int|string, PDFValueObject> $signatures
     * @return array{?DocMdpPermission,list<ActiveSignature>}
     */
    private function findDocMdpPermission(
        PdfObjectResolver $resolver,
        array $signatures,
        int|string|null $catalogCertification,
        int $fileSize,
    ): array {
        $permission = null;
        $certification = null;
        $ends = [];
        $details = [];
        $byteRangeReader = new SignatureByteRangeReader();

        foreach ($signatures as $key => $signature) {
            $ranges = $byteRangeReader->read($resolver, $signature, $fileSize);
            $last = $ranges[count($ranges) - 1];
            $end = $last['offset'] + $last['length'];
            $ends[$key] = $end;
            $level = $this->docMdpPermissionOf($resolver, $signature);
            $details[] = new ActiveSignature(
                is_int($key) ? $key : null,
                $ranges,
                $end,
                $level instanceof DocMdpPermission,
                $resolver->name($resolver->get($signature, 'Type')) === 'DocTimeStamp',
            );
            if (!$level instanceof DocMdpPermission) {
                continue;
            }

            if ($certification !== null) {
                throw new RuntimeException('More than one certification signature is active.');
            }

            $certification = $key;
            $permission = $level;
        }

        if ($catalogCertification !== null && $catalogCertification !== $certification) {
            throw new RuntimeException('/Perms /DocMDP does not reference a DocMDP signature.');
        }

        // Each signature covers the revisions before it, so the one whose /ByteRange ends first was applied first
        foreach ($ends as $key => $end) {
            if ($certification !== null && $key !== $certification && $end <= $ends[$certification]) {
                throw new RuntimeException('The certification signature is not the first signature.');
            }
        }

        // Document object order and field order need not match signing order.
        usort($details, static fn (ActiveSignature $left, ActiveSignature $right): int => $left->signedRevisionEnd <=> $right->signedRevisionEnd);

        return [$permission, $details];
    }

    /**
     * ISO 32000-1 sets no precedence between two DocMDP transforms in one
     * signature, so transforms that disagree leave the permission unknown.
     */
    private function docMdpPermissionOf(PdfObjectResolver $resolver, PDFValueObject $signature): ?DocMdpPermission
    {
        $permission = null;

        foreach ($resolver->items($resolver->get($signature, 'Reference')) as $referenceValue) {
            $reference = $resolver->dictionary($referenceValue);
            if ($resolver->name($resolver->get($reference, 'TransformMethod')) !== 'DocMDP') {
                continue;
            }

            $level = $this->permissionLevel($resolver, $resolver->dictionary($resolver->get($reference, 'TransformParams')));
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
        $value = $resolver->get($parameters, 'P');
        if (!$value instanceof PDFValue || $resolver->isNull($value)) {
            return DocMdpPermission::FORM_FILLING;
        }

        // Any integer or real syntax (7.3.3), such as +2, 02 or 2.0, as long as the value is 1, 2 or 3
        $number = $value instanceof PDFValueSimple ? (string)$value->val() : '';
        if (preg_match('/^\+?0*([123])(?:\.0*)?\z/', $number, $matches) !== 1) {
            throw new RuntimeException('The DocMDP /P value is not 1, 2 or 3.');
        }

        return DocMdpPermission::from((int)$matches[1]);
    }
}
