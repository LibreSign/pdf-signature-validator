<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Model;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionObjects;
use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionReferenceIndex;
use UnexpectedValueException;

/**
 * Identifies fields and annotations by their structural ownership, never by
 * a type name found in the document's bytes. Incoming edges are also recorded
 * so a shared object cannot be modified under just one of its usages.
 */
final class DocMdpDocumentGraph
{
    /** @var array<int,array{reference:string,entries:array<string,string>,type:?string,parent:?int,children:list<string>}> */
    public array $fields = [];

    /** @var array<int,array{reference:string,entries:array<string,string>,annotations:list<string>}> */
    public array $pages = [];

    /** @var array<int,array{reference:string,entries:array<string,string>,page:int}> */
    public array $annotations = [];

    /** @var array<int,list<array{owner:int,path:string}>> */
    public array $incoming = [];

    /** @var array<int,array<string,true>> */
    private array $roleEdges = [];

    /** @var array<int,true> */
    private array $visitedPages = [];

    public readonly int $root;

    /** @var array<string,string> */
    public readonly array $catalog;

    public readonly ?int $formObject;

    /** @var array<string,string> */
    public readonly array $form;

    /** @var list<string> */
    public readonly array $topFields;

    private function __construct(public readonly PdfRevisionObjects $document, string $root)
    {
        $catalog = $this->requireDictionary($root);
        $this->root = $catalog['num'];
        $this->catalog = $catalog['entries'];
        if (($this->catalog['/Type'] ?? null) !== '/Catalog') {
            throw new UnexpectedValueException('Invalid catalog');
        }

        $this->walkPages($this->catalog['/Pages'] ?? '', null);
        $formValue = $this->catalog['/AcroForm'] ?? '<<>>';
        $form = $document->dictionary($formValue);
        if ($form === null) {
            throw new UnexpectedValueException('Unreadable AcroForm');
        }
        $this->form = $form;
        $formObject = $document->resolve($formValue);
        $this->formObject = $formObject['num'] ?? null;
        $this->topFields = $this->listReferences(
            $form['/Fields'] ?? '[]',
            $this->formObject ?? $this->root,
            $this->formObject === null ? '/AcroForm/Fields' : '/Fields',
        );
        foreach ($this->topFields as $reference) {
            $this->walkField($reference, null, null);
        }

        $this->validateRoles();
        $incoming = (new PdfRevisionReferenceIndex())->read($document);
        if ($incoming === null) {
            throw new UnexpectedValueException('Unreadable reference path');
        }
        $this->incoming = $incoming;
    }

    private function validateRoles(): void
    {
        if (isset($this->visitedPages[$this->root]) || isset($this->fields[$this->root]) || isset($this->annotations[$this->root])
            || ($this->formObject !== null && ($this->formObject === $this->root || isset($this->visitedPages[$this->formObject]) || isset($this->fields[$this->formObject]) || isset($this->annotations[$this->formObject])))
            || array_intersect_key($this->visitedPages, $this->fields + $this->annotations) !== []) {
            throw new UnexpectedValueException('Ambiguous object roles');
        }
    }

    public static function read(PdfRevisionObjects $document, string $root): ?self
    {
        try {
            return new self($document, $root);
        } catch (UnexpectedValueException) {
            return null;
        }
    }

    private function walkPages(string $reference, ?string $parent): int
    {
        $object = $this->requireDictionary($reference);
        $number = $object['num'];
        $entries = $object['entries'];
        if (isset($this->visitedPages[$number]) || ($parent !== null && ($entries['/Parent'] ?? null) !== $parent)) {
            throw new UnexpectedValueException('Ambiguous page tree');
        }
        $this->visitedPages[$number] = true;

        if (($entries['/Type'] ?? null) === '/Pages') {
            $count = 0;
            foreach ($this->listReferences($entries['/Kids'] ?? '', $number, '/Kids') as $child) {
                $count += $this->walkPages($child, $reference);
            }
            if (($entries['/Count'] ?? '') !== (string) $count) {
                throw new UnexpectedValueException('Inconsistent page count');
            }
            return $count;
        }
        if (($entries['/Type'] ?? null) !== '/Page') {
            throw new UnexpectedValueException('Unexpected page object');
        }

        $annotations = $this->listReferences($entries['/Annots'] ?? '[]', $number, '/Annots');
        $this->pages[$number] = ['reference' => $reference, 'entries' => $entries, 'annotations' => $annotations];
        foreach ($annotations as $annotation) {
            $value = $this->requireDictionary($annotation);
            if (isset($this->annotations[$value['num']])
                || (isset($value['entries']['/P']) && $value['entries']['/P'] !== $reference)) {
                throw new UnexpectedValueException('Ambiguous annotation ownership');
            }
            $this->annotations[$value['num']] = ['reference' => $annotation, 'entries' => $value['entries'], 'page' => $number];
        }
        return 1;
    }

    private function walkField(string $reference, ?int $parent, ?string $inheritedType): void
    {
        $object = $this->requireDictionary($reference);
        $number = $object['num'];
        $entries = $object['entries'];
        if (isset($this->fields[$number])) {
            throw new UnexpectedValueException('Ambiguous field tree');
        }
        $parentReference = $entries['/Parent'] ?? null;
        if ($parent !== null) {
            if ($parentReference === null || ($this->document->resolve($parentReference)['num'] ?? null) !== $parent) {
                throw new UnexpectedValueException('Invalid field parent');
            }
            $this->roleEdges[$parent][$number . ':/Parent'] = true;
        } elseif ($parentReference !== null) {
            throw new UnexpectedValueException('Unexpected field parent');
        }
        $type = $entries['/FT'] ?? $inheritedType;
        $children = $this->listReferences($entries['/Kids'] ?? '[]', $number, '/Kids');
        $this->fields[$number] = [
            'reference' => $reference, 'entries' => $entries,
            'type' => $type, 'parent' => $parent, 'children' => $children,
        ];
        foreach ($children as $child) {
            $this->walkField($child, $number, $type);
        }
    }

    /** @return list<string> */
    private function listReferences(string $value, int $owner, string $path): array
    {
        $references = $this->document->referenceArray($value);
        if ($references === null) {
            throw new UnexpectedValueException('Invalid structural array');
        }
        $array = $this->document->resolve($value);
        if ($array !== null) {
            $this->roleEdges[$array['num']][$owner . ':' . $path] = true;
            $owner = $array['num'];
            $path = '';
        }
        foreach ($references as $reference) {
            $number = $this->document->resolve($reference)['num'] ?? null;
            if ($number === null) {
                throw new UnexpectedValueException('Unresolved structural reference');
            }
            $this->roleEdges[$number][$owner . ':' . $path . '[]'] = true;
        }
        return $references;
    }

    /** @return array{num:int,gen:int,entries:array<string,string>} */
    private function requireDictionary(string $reference): array
    {
        $object = $this->document->resolve($reference);
        if ($object === null || $object['entries'] === null || $object['stream'] !== null) {
            throw new UnexpectedValueException('Invalid structural dictionary');
        }
        return ['num' => $object['num'], 'gen' => $object['gen'], 'entries' => $object['entries']];
    }

    /** A field/annotation must not also be used through an unrelated path. */
    public function hasOnlyRoleReferences(int $number): bool
    {
        foreach ($this->incoming[$number] ?? [] as $edge) {
            if (!isset($this->roleEdges[$number][$edge['owner'] . ':' . $edge['path']])) {
                return false;
            }
        }
        return true;
    }
}
