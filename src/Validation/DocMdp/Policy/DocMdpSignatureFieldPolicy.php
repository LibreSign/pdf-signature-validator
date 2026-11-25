<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Model\ActiveSignature;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;

/** Authorization of a new approval or document-timestamp field. */
final class DocMdpSignatureFieldPolicy
{
    public function __construct(private readonly DocMdpFieldSyntax $syntax = new DocMdpFieldSyntax())
    {
    }

    public function allowsNewField(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number): bool
    {
        $field = $after->fields[$number];

        return !isset($before->document->objects[$number])
            && $field['parent'] === null && $field['children'] === []
            && $field['type'] === '/Sig' && $after->hasOnlyRoleReferences($number)
            && $this->isNewSignatureField($after, $number, $field['entries']);
    }

    public function allowsExistingField(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number): bool
    {
        $field = $after->fields[$number];
        $old = $before->fields[$number]['entries'];
        $new = $field['entries'];

        return $field['type'] === '/Sig' && ($old['/V'] ?? 'null') === 'null'
            && $before->hasOnlyRoleReferences($number) && $after->hasOnlyRoleReferences($number)
            && $this->syntax->onlyChanges($old, $new, ['/V', '/AP', '/AS', '/M'])
            && $this->syntax->appearanceStateIsValid($new);
    }

    /** @param array<string,string> $entries */
    private function isNewSignatureField(DocMdpDocumentGraph $graph, int $number, array $entries): bool
    {
        if (($entries['/FT'] ?? null) !== '/Sig'
            || !$this->syntax->isText($entries['/T'] ?? '')
            || array_diff(array_keys($entries), [
                '/FT', '/Type', '/Subtype', '/Rect', '/V', '/T', '/TU',
                '/F', '/Ff', '/P', '/M', '/NM', '/AP', '/AS', '/MK', '/BS', '/Border',
            ]) !== [] || !$this->syntax->appearanceStateIsValid($entries)) {
            return false;
        }
        if (($entries['/Type'] ?? '/Annot') !== '/Annot'
            || ($entries['/Subtype'] ?? '/Widget') !== '/Widget') {
            return false;
        }
        return $this->hasOnlyExpectedReferences($entries) && $this->hasValidWidget($graph, $number, $entries);
    }

    /** @param array<string,string> $entries */
    private function hasOnlyExpectedReferences(array $entries): bool
    {
        $reader = new PdfReferencePaths();
        foreach ($entries as $key => $value) {
            if (!in_array($key, ['/V', '/P', '/AP'], true) && $reader->read($value) !== []) {
                return false;
            }
        }

        return true;
    }

    /** @param array<string,string> $entries */
    private function hasValidWidget(DocMdpDocumentGraph $graph, int $number, array $entries): bool
    {
        if (!isset($entries['/Rect'])) {
            return !isset($entries['/Subtype']) && !isset($entries['/P']) && !isset($entries['/AP']) && !isset($graph->annotations[$number]);
        }
        if (preg_match('/^\[-?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+)\]$/D', $entries['/Rect']) !== 1) {
            return false;
        }

        return isset($graph->annotations[$number])
            && (!isset($entries['/P']) || $entries['/P'] === $graph->pages[$graph->annotations[$number]['page']]['reference']);
    }

    /**
     * @param array<int,ActiveSignature> $signatures
     */
    public function newSignature(
        DocMdpDocumentGraph $before,
        DocMdpDocumentGraph $after,
        int $field,
        string $reference,
        array $signatures,
    ): ?ActiveSignature {
        $object = $after->document->resolve($reference);
        if ($object === null || $object['entries'] === null || $object['stream'] !== null
            || isset($before->document->objects[$object['num']])) {
            return null;
        }
        $number = $object['num'];
        $signature = $signatures[$number] ?? null;
        if ($signature === null
            || ($object['entries']['/Type'] ?? '/Sig') !== ($signature->isDocumentTimestamp ? '/DocTimeStamp' : '/Sig')
            || array_diff(array_keys($object['entries']), [
                '/Type', '/Filter', '/SubFilter', '/ByteRange', '/Contents', '/M', '/Name',
                '/Reason', '/Location', '/ContactInfo', '/Prop_Build', '/Reference',
                '/Cert', '/Changes', '/R', '/V', '/AuthTime', '/AuthType',
            ]) !== []) {
            return null;
        }
        $edges = $after->incoming[$number] ?? [];
        if ($edges !== [['owner' => $field, 'path' => '/V']]) {
            return null;
        }
        return $signature;
    }
}
