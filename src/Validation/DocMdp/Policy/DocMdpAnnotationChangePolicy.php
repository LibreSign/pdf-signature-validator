<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;

/** Ordinary, page-owned, non-widget markup annotations at P=3. */
final class DocMdpAnnotationChangePolicy
{
    private const SUBTYPES = [
        '/Text', '/FreeText', '/Line', '/Square', '/Circle', '/Polygon', '/PolyLine',
        '/Highlight', '/Underline', '/Squiggly', '/StrikeOut', '/Stamp', '/Caret', '/Ink', '/Redact',
    ];

    private const PROPERTIES = [
        '/Type', '/Subtype', '/Rect', '/Contents', '/P', '/NM', '/M', '/F',
        '/AP', '/AS', '/Border', '/C', '/CA', '/T', '/CreationDate', '/Subj',
        '/IT', '/Name', '/Open', '/State', '/StateModel', '/DA', '/Q', '/DS',
        '/CL', '/LE', '/RD', '/BS', '/BE', '/L', '/LL', '/LLE', '/LLO',
        '/Cap', '/CP', '/CO', '/IC', '/Vertices', '/QuadPoints', '/InkList',
        '/Sy', '/OverlayText', '/Repeat', '/RO',
    ];

    /**
     * @return array{accepted:array<int,true>,oldAppearances:array<int,true>,newAppearances:array<int,true>}|null
     */
    public function inspect(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, bool $allowAnnotations): ?array
    {
        $accepted = $oldAppearances = $newAppearances = [];
        foreach (array_keys($before->annotations + $after->annotations) as $number) {
            if (isset($before->fields[$number]) || isset($after->fields[$number])) {
                continue;
            }
            $change = $this->inspectAnnotation($before, $after, $number, $allowAnnotations);
            if ($change === null) {
                return null;
            }
            if ($change['accepted']) {
                $accepted[$number] = true;
            }
            if ($change['oldAppearance']) {
                $oldAppearances[$number] = true;
            }
            if ($change['newAppearance']) {
                $newAppearances[$number] = true;
            }
        }

        return ['accepted' => $accepted, 'oldAppearances' => $oldAppearances, 'newAppearances' => $newAppearances];
    }

    /** @return array{accepted:bool,oldAppearance:bool,newAppearance:bool}|null */
    private function inspectAnnotation(DocMdpDocumentGraph $before, DocMdpDocumentGraph $after, int $number, bool $allowAnnotations): ?array
    {
        $old = $before->annotations[$number] ?? null;
        $new = $after->annotations[$number] ?? null;
        $oldObject = $before->document->objects[$number] ?? null;
        $newObject = $after->document->objects[$number] ?? null;
        $sameObject = $oldObject !== null && $newObject !== null && PdfRevisionObjects::same($oldObject, $newObject);
        $changed = $old === null || $new === null || $old['page'] !== $new['page'] || !$sameObject;
        if (!$allowAnnotations) {
            return $changed ? null : ['accepted' => false, 'oldAppearance' => false, 'newAppearance' => false];
        }
        $oldSafe = $old !== null && $before->hasOnlyRoleReferences($number) && $this->isMarkup($old['entries']);
        $newSafe = $new !== null && $after->hasOnlyRoleReferences($number) && $this->isMarkup($new['entries']);
        $accepted = false;
        if ($changed) {
            if (!$this->allowsChange($old, $new, $oldObject !== null, $sameObject, $oldSafe, $newSafe)) {
                return null;
            }
            $accepted = $new !== null;
        }

        return ['accepted' => $accepted, 'oldAppearance' => $oldSafe, 'newAppearance' => $newSafe];
    }

    /**
     * @param array{reference:string,entries:array<string,string>,page:int}|null $old
     * @param array{reference:string,entries:array<string,string>,page:int}|null $new
     */
    private function allowsChange(?array $old, ?array $new, bool $oldObjectExists, bool $sameObject, bool $oldSafe, bool $newSafe): bool
    {
        if ($new === null) {
            // Removal from /Annots is allowed, not rewriting an unrelated object.
            return $oldSafe && $sameObject;
        }
        if (!$newSafe) {
            return false;
        }
        if ($old === null) {
            return !$oldObjectExists;
        }

        return $oldSafe && $old['page'] === $new['page']
            && ($old['entries']['/Subtype'] ?? null) === ($new['entries']['/Subtype'] ?? null);
    }

    /** @param array<string,string> $entries */
    private function isMarkup(array $entries): bool
    {
        if (($entries['/Type'] ?? '/Annot') !== '/Annot'
            || !in_array($entries['/Subtype'] ?? '', self::SUBTYPES, true)
            || array_diff(array_keys($entries), self::PROPERTIES) !== []
            || !preg_match('/^\[-?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+) -?(?:\d+\.?\d*|\.\d+)\]$/D', $entries['/Rect'] ?? '')) {
            return false;
        }

        $reader = new PdfReferencePaths();
        foreach ($entries as $key => $value) {
            if (in_array($key, ['/AP', '/P'], true)) {
                continue;
            }
            // These are direct annotation properties, not arbitrary references
            // to content, actions or other document objects.
            if ($reader->read($value) !== []) {
                return false;
            }
        }
        return true;
    }
}
