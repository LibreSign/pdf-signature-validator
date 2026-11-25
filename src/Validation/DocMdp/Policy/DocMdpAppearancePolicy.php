<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpDocumentGraph;

/**
 * Appearance streams may be updated only in a proven form/annotation scope.
 * Shared resources and their descendants remain immutable.
 */
final class DocMdpAppearancePolicy
{
    /**
     * @param array<int,true> $roots
     * @return array{reachable:array<int,true>,exclusive:array<int,true>}|null
     */
    public function inspect(DocMdpDocumentGraph $graph, array $roots): ?array
    {
        $pending = $this->appearanceRoots($graph, $roots);
        if ($pending === null) {
            return null;
        }
        $reachable = $this->reachableResources($graph, $pending);
        if ($reachable === null) {
            return null;
        }

        return ['reachable' => $reachable, 'exclusive' => $this->exclusiveResources($graph, $roots, $reachable)];
    }

    /**
     * @param array<int,true> $roots
     * @return list<string>|null
     */
    private function appearanceRoots(DocMdpDocumentGraph $graph, array $roots): ?array
    {
        $pending = [];
        $reader = new PdfReferencePaths();
        foreach (array_keys($roots) as $number) {
            $appearance = $graph->document->objects[$number]['entries']['/AP'] ?? null;
            if ($appearance === null) {
                continue;
            }
            if (!$this->isAppearanceDictionary($graph, $appearance)) {
                return null;
            }
            $references = $reader->read($appearance);
            if ($references === null) {
                return null;
            }
            array_push($pending, ...array_column($references, 'reference'));
        }

        return $pending;
    }

    /**
     * @param list<string> $pending
     * @return array<int,true>|null
     */
    private function reachableResources(DocMdpDocumentGraph $graph, array $pending): ?array
    {
        $reader = new PdfReferencePaths();
        $reachable = [];
        while ($pending !== []) {
            $reference = array_pop($pending);
            $object = $graph->document->resolve($reference);
            if ($object === null) {
                return null;
            }
            $number = $object['num'];
            if (isset($reachable[$number])) {
                continue;
            }
            if (!$this->isAppearanceResource($graph, $number)) {
                return null;
            }
            $reachable[$number] = true;
            $references = $reader->read($object['value']);
            if ($references === null) {
                return null;
            }
            array_push($pending, ...array_column($references, 'reference'));
        }

        return $reachable;
    }

    /**
     * Removing an externally referenced node also removes permission to
     * modify any descendants it references. Cycles cannot confer ownership.
     *
     * @param array<int,true> $roots
     * @param array<int,true> $exclusive
     * @return array<int,true>
     */
    private function exclusiveResources(DocMdpDocumentGraph $graph, array $roots, array $exclusive): array
    {
        do {
            $removed = false;
            foreach (array_keys($exclusive) as $number) {
                foreach ($graph->incoming[$number] ?? [] as $edge) {
                    $owner = $edge['owner'];
                    $isRootEdge = isset($roots[$owner])
                        && ($edge['path'] === '/AP' || str_starts_with($edge['path'], '/AP/'));
                    if (!$isRootEdge && !isset($exclusive[$owner])) {
                        unset($exclusive[$number]);
                        $removed = true;
                        break;
                    }
                }
            }
        } while ($removed);

        return $exclusive;
    }

    private function isAppearanceDictionary(DocMdpDocumentGraph $graph, string $value): bool
    {
        $appearance = $graph->document->dictionary($value);
        if ($appearance === null || !isset($appearance['/N'])
            || array_diff(array_keys($appearance), ['/N', '/R', '/D']) !== []) {
            return false;
        }
        foreach ($appearance as $entry) {
            if ($this->isFormStream($graph, $entry)) {
                continue;
            }
            $states = $graph->document->dictionary($entry);
            if ($states === null || $states === []) {
                return false;
            }
            foreach ($states as $state) {
                if (!$this->isFormStream($graph, $state)) {
                    return false;
                }
            }
        }
        return true;
    }

    private function isFormStream(DocMdpDocumentGraph $graph, string $value): bool
    {
        $object = $graph->document->resolve($value);

        return $object !== null && $object['stream'] !== null
            && ($object['entries']['/Subtype'] ?? null) === '/Form'
            && ($object['entries']['/Type'] ?? '/XObject') === '/XObject';
    }

    private function isAppearanceResource(DocMdpDocumentGraph $graph, int $number): bool
    {
        if ($number === $graph->root || $number === $graph->formObject
            || isset($graph->pages[$number]) || isset($graph->fields[$number]) || isset($graph->annotations[$number])) {
            return false;
        }
        $entries = $graph->document->objects[$number]['entries'] ?? [];
        if (in_array($entries['/Type'] ?? '', [
            '/Catalog', '/Pages', '/Page', '/Annot', '/Sig', '/DocTimeStamp',
            '/DSS', '/Action', '/Filespec', '/EmbeddedFile', '/ObjStm', '/XRef',
        ], true) || isset($entries['/FT']) || isset($entries['/ByteRange'])) {
            return false;
        }

        return array_intersect(array_keys($entries), [
            '/A', '/AA', '/JS', '/JavaScript', '/OpenAction', '/Launch',
            '/RichMediaContent', '/EF', '/EmbeddedFiles',
        ]) === [];
    }
}
