<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;
use UnexpectedValueException;

/**
 * @psalm-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from \LibreSign\PdfSignatureValidator\Pdf\Revision\PdfIncrementalRevisionReader
 */
final class DocMdpFormProjection
{
    public function __construct(
        private readonly DocMdpReferenceArrayProjection $arrays = new DocMdpReferenceArrayProjection(),
        private readonly DocMdpProjectedDictionary $dictionary = new DocMdpProjectedDictionary(),
    ) {
    }

    /**
     * @param array<int,PdfObject> $remaining
     * @param array<int,true> $approvals
     * @param array<int,true> $timestamps
     */
    public function project(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        PdfRevisionObjects $shadow,
        array &$remaining,
        array $approvals,
        array $timestamps,
    ): void {
        $timestampRefs = $this->timestampFields($before, $after, $approvals, $timestamps);
        $this->checkFormEntries($before->form, $after->form, $approvals !== [] || $timestamps !== []);

        $oldFormValue = $before->catalog['/AcroForm'] ?? null;
        $newFormValue = $after->catalog['/AcroForm'] ?? null;
        $shadowCatalog = $shadow->objects[$before->root]['entries'] ?? [];
        $shadowFormValue = $shadowCatalog['/AcroForm'] ?? null;
        $shadowForm = $shadowFormValue === null ? [] : $shadow->dictionary($shadowFormValue);
        if ($shadowForm === null) {
            throw new UnexpectedValueException('Unresolved original AcroForm');
        }

        $projected = $after->form;
        $projectedFields = $this->arrays->project(
            $before,
            $after,
            $shadow,
            $remaining,
            $before->form['/Fields'] ?? null,
            $after->form['/Fields'] ?? null,
            $shadowForm['/Fields'] ?? null,
            $timestampRefs,
        );
        $this->dictionary->setEntry($projected, '/Fields', $projectedFields);
        if ($timestampRefs === []) {
            $this->dictionary->setEntry($projected, '/SigFlags', $shadowForm['/SigFlags'] ?? null);
        }

        $this->projectRepresentation($before, $after, $remaining, $projected, $oldFormValue, $newFormValue, $shadowFormValue, $timestampRefs);
    }

    /**
     * @param array<int,true> $approvals
     * @param array<int,true> $timestamps
     * @return list<string>
     */
    private function timestampFields(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array $approvals, array $timestamps): array
    {
        if (array_slice($after->topFields, 0, count($before->topFields)) !== $before->topFields) {
            throw new UnexpectedValueException('Existing fields must be retained');
        }
        $timestampRefs = [];
        foreach (array_slice($after->topFields, count($before->topFields)) as $ref) {
            $number = (int) $ref;
            if (isset($timestamps[$number])) {
                $timestampRefs[] = $ref;
            } elseif (!isset($approvals[$number])) {
                throw new UnexpectedValueException('Unapproved field addition');
            }
        }
        return $timestampRefs;
    }

    /**
     * @param array<int,PdfObject> $remaining
     * @param array<string,string> $projected
     * @param list<string> $timestampRefs
     */
    private function projectRepresentation(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array &$remaining, array $projected, ?string $oldFormValue, ?string $newFormValue, ?string $shadowFormValue, array $timestampRefs): void
    {
        // A new indirect form may be created for approval fields only.
        if ($before->formObject !== $after->formObject) {
            if ($oldFormValue !== null || $after->formObject === null || $timestampRefs !== []
                || isset($before->document->objects[$after->formObject])
                || !$this->onlyFormOwner($after, $after->formObject)) {
                throw new UnexpectedValueException('Unproven AcroForm replacement');
            }
            unset($remaining[$after->formObject]);
            $this->rewriteCatalogForm($remaining, $after, $shadowFormValue);
            return;
        }
        if ($after->formObject !== null) {
            $this->projectIndirectForm($before, $after, $remaining, $projected, $shadowFormValue, $timestampRefs, $after->formObject);
            $this->rewriteCatalogForm($remaining, $after, $shadowFormValue);
            return;
        }
        if (isset($remaining[$after->root])) {
            if ($newFormValue === null && $shadowFormValue !== null) {
                throw new UnexpectedValueException('AcroForm removal');
            }
            $value = $projected === [] && $shadowFormValue === null ? null : PdfRevisionObjects::dictionaryValue($projected);
            $this->rewriteCatalogForm($remaining, $after, $value);
        }
    }

    /**
     * @param array<int,PdfObject> $remaining
     * @param array<string,string> $projected
     * @param list<string> $timestampRefs
     */
    private function projectIndirectForm(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, array &$remaining, array $projected, ?string $shadowFormValue, array $timestampRefs, int $number): void
    {
        if (!isset($remaining[$number])) {
            return;
        }
        if ((!$this->onlyFormOwner($before, $number) || !$this->onlyFormOwner($after, $number))
            && !PdfRevisionObjects::same($before->document->objects[$number], $after->document->objects[$number])) {
            throw new UnexpectedValueException('Shared AcroForm');
        }
        if ($shadowFormValue !== null) {
            $remaining[$number] = $this->dictionary->withEntries($remaining[$number], $projected);
            return;
        }
        if ($timestampRefs !== []) {
            throw new UnexpectedValueException('Unsupported timestamp in a newly created indirect form');
        }
        unset($remaining[$number]);
    }

    /**
     * @param array<string,string> $old
     * @param array<string,string> $new
     */
    private function checkFormEntries(array $old, array $new, bool $newSignatures): void
    {
        foreach (array_keys($old + $new) as $key) {
            if (($old[$key] ?? null) !== ($new[$key] ?? null)
                && !in_array($key, ['/Fields', '/SigFlags'], true)) {
                throw new UnexpectedValueException('Unexpected AcroForm property change');
            }
        }
        if (($old['/SigFlags'] ?? null) !== ($new['/SigFlags'] ?? null)) {
            $previous = $old['/SigFlags'] ?? '0';
            $current = $new['/SigFlags'] ?? '';
            if (!$newSignatures || !ctype_digit($previous) || !ctype_digit($current)
                || (int) $current > 3 || (((int) $current & (int) $previous) !== (int) $previous)) {
                throw new UnexpectedValueException('Unexpected signature flag change');
            }
        }
    }

    private function onlyFormOwner(DocMdpDocumentGraph $graph, int $number): bool
    {
        return ($graph->incoming[$number] ?? []) === [['owner' => $graph->root, 'path' => '/AcroForm']];
    }

    /** @param array<int,PdfObject> $remaining */
    private function rewriteCatalogForm(array &$remaining, DocMdpDocumentGraph $after, ?string $form): void
    {
        if (!isset($remaining[$after->root])) {
            return;
        }
        $entries = $remaining[$after->root]['entries'] ?? [];
        $this->dictionary->setEntry($entries, '/AcroForm', $form);
        $remaining[$after->root] = $this->dictionary->withEntries($remaining[$after->root], $entries);
    }
}
