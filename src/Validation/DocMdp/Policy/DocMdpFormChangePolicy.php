<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
use LibreSign\PdfSignatureValidator\Model\SignatureInventory;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;

/** Form values and active approval-signature additions at P=2 or P=3. */
final class DocMdpFormChangePolicy
{
    public function __construct(
        private readonly DocMdpFormValuePolicy $values = new DocMdpFormValuePolicy(),
        private readonly DocMdpSignatureFieldPolicy $signatureFields = new DocMdpSignatureFieldPolicy(),
    ) {
    }

    /**
     * @return array{accepted:array<int,true>,approvals:array<int,true>,timestamps:array<int,true>,
     *     oldAppearances:array<int,true>,newAppearances:array<int,true>}|null
     */
    public function inspect(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        SignatureInventory $inventory,
        int $eof,
        int $end,
    ): ?array {
        if (!$inventory->isConclusive || array_diff_key($before->fields, $after->fields) !== []) {
            return null;
        }

        $signatures = $this->revisionSignatures($inventory, $eof, $end);
        $result = ['accepted' => [], 'approvals' => [], 'timestamps' => [], 'oldAppearances' => [], 'newAppearances' => []];
        foreach (array_keys($after->fields) as $number) {
            $change = isset($before->fields[$number])
                ? $this->inspectExistingField($before, $after, $number, $signatures)
                : $this->inspectNewField($before, $after, $number, $signatures);
            if ($change === null) {
                return null;
            }
            $result['accepted'] += $change['accepted'];
            $result['approvals'] += $change['approvals'];
            $result['timestamps'] += $change['timestamps'];
            $result['oldAppearances'] += $change['oldAppearances'];
            $result['newAppearances'] += $change['newAppearances'];
        }

        return $result;
    }

    /** @return array<int,ActiveSignature> */
    private function revisionSignatures(SignatureInventory $inventory, int $eof, int $end): array
    {
        $signatures = [];
        foreach ($inventory->activeSignatures as $signature) {
            if (!$signature->isCertifying && $signature->objectNumber !== null
                && $signature->signedRevisionEnd >= $eof && $signature->signedRevisionEnd <= $end) {
                $signatures[$signature->objectNumber] = $signature;
            }
        }

        return $signatures;
    }

    /**
     * @param array<int,ActiveSignature> $signatures
     * @return array{accepted:array<int,true>,approvals:array<int,true>,timestamps:array<int,true>,oldAppearances:array<int,true>,newAppearances:array<int,true>}|null
     */
    private function inspectNewField(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number, array $signatures): ?array
    {
        if (!$this->signatureFields->allowsNewField($before, $after, $number)) {
            return null;
        }
        $signature = $this->signatureFields->newSignature($before, $after, $number, $after->fields[$number]['entries']['/V'] ?? '', $signatures);
        if (!$signature instanceof \LibreSign\PdfSignatureValidator\Model\ActiveSignature || $signature->objectNumber === null) {
            return null;
        }
        if ($signature->isDocumentTimestamp) {
            return ['accepted' => [], 'approvals' => [], 'timestamps' => [$number => true], 'oldAppearances' => [], 'newAppearances' => []];
        }

        return ['accepted' => [$number => true, $signature->objectNumber => true], 'approvals' => [$number => true], 'timestamps' => [], 'oldAppearances' => [], 'newAppearances' => [$number => true]];
    }

    /**
     * @param array<int,ActiveSignature> $signatures
     * @return array{accepted:array<int,true>,approvals:array<int,true>,timestamps:array<int,true>,oldAppearances:array<int,true>,newAppearances:array<int,true>}|null
     */
    private function inspectExistingField(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number, array $signatures): ?array
    {
        $old = $before->fields[$number];
        $field = $after->fields[$number];
        if ($old['type'] !== $field['type'] || $old['parent'] !== $field['parent']
            || $old['children'] !== $field['children']) {
            return null;
        }
        $mutable = $this->values->isMutable($before, $after, $number);
        $appearances = $mutable ? [$number => true] : [];
        if (PdfRevisionObjects::same($before->document->objects[$number], $after->document->objects[$number])) {
            return ['accepted' => [], 'approvals' => [], 'timestamps' => [], 'oldAppearances' => $appearances, 'newAppearances' => $appearances];
        }
        if ($mutable && $field['type'] !== null && $this->values->allowsValueChange($old['entries'], $field['entries'], $field['type'], $field['parent'])) {
            return ['accepted' => [$number => true], 'approvals' => [], 'timestamps' => [], 'oldAppearances' => $appearances, 'newAppearances' => $appearances];
        }

        return $this->inspectExistingSignatureField($before, $after, $number, $signatures);
    }

    /**
     * @param array<int,ActiveSignature> $signatures
     * @return array{accepted:array<int,true>,approvals:array<int,true>,timestamps:array<int,true>,oldAppearances:array<int,true>,newAppearances:array<int,true>}|null
     */
    private function inspectExistingSignatureField(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number, array $signatures): ?array
    {
        if (!$this->signatureFields->allowsExistingField($before, $after, $number)) {
            return null;
        }
        $signature = $this->signatureFields->newSignature($before, $after, $number, $after->fields[$number]['entries']['/V'] ?? '', $signatures);
        if (!$signature instanceof \LibreSign\PdfSignatureValidator\Model\ActiveSignature || $signature->objectNumber === null || $signature->isDocumentTimestamp) {
            return null;
        }

        return ['accepted' => [$number => true, $signature->objectNumber => true], 'approvals' => [], 'timestamps' => [], 'oldAppearances' => [$number => true], 'newAppearances' => [$number => true]];
    }
}
