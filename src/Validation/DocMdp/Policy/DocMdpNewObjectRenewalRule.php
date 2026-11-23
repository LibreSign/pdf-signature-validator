<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Model\DocMdpRevisionState;

/** Strict renewal of DSS and ancillary Info objects introduced after signing. */
final class DocMdpNewObjectRenewalRule
{
    public function __construct(private readonly DssChangeRule $dssRule)
    {
    }

    /**
     * A subsequent LTA renewal may append DSS evidence to a DSS dictionary
     * introduced after certification. Never permit arbitrary new-object
     * rewriting: especially not stream evidence or timestamp dictionaries.
     *
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $object
     * @return bool|null
     */
    public function allowsRewritingNewObject(
        DocMdpRevisionState $state,
        int $revisionIndex,
        int $number,
        array $object,
    ): ?bool {
        $old = $state->currentObjects[$number] ?? $state->newObjects[$number] ?? null;
        if ($old === null || $old['gen'] !== $object['gen']) {
            return null;
        }
        if ($old['value'] === $object['value'] && $old['stream'] === $object['stream']) {
            $state->currentObjects[$number] = $object;
            return false;
        }
        if (!$this->areCompatibleDictionaries($old, $object)) {
            return null;
        }

        $reference = $number . ' ' . $object['gen'] . ' R';
        if ($state->dssReference === $reference) {
            return $this->allowDssRewrite($state, $revisionIndex, $number, $object, $old);
        }

        // /Info objects introduced after certification can be rewritten for
        // ancillary producer/date metadata, but never for content metadata.
        if ($this->isAncillaryInfo($old['entries'] ?? []) && $this->isAncillaryInfo($object['entries'] ?? [])) {
            $state->currentObjects[$number] = $object;
            return false;
        }

        return null;
    }

    /**
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $old
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $new
     */
    private function areCompatibleDictionaries(array $old, array $new): bool
    {
        return $old['stream'] === null && $new['stream'] === null
            && $old['entries'] !== null && $new['entries'] !== null;
    }

    /**
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $object
     * @param array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int} $old
     */
    private function allowDssRewrite(
        DocMdpRevisionState $state,
        int $revisionIndex,
        int $number,
        array $object,
        array $old,
    ): ?bool {
        $reference = $number . ' ' . $object['gen'] . ' R';
        if ($old['entries'] === null || $object['entries'] === null) {
            return null;
        }
        if (!$this->isAppendOnlyDssChange(
            $old['entries'],
            $object['entries'],
            $state,
            $revisionIndex,
        ) || !$this->dssRule->allowsNewDss(
            $reference,
            array_replace($state->newObjects, [$number => $object]),
            $state->newObjectRevisions,
            $revisionIndex,
        )) {
            return null;
        }
        $state->currentObjects[$number] = $object;

        return true;
    }

    /** @param array<string,string> $entries */
    private function isAncillaryInfo(array $entries): bool
    {
        return $entries !== [] && array_diff(array_keys($entries), ['/ModDate', '/Producer']) === [];
    }

    /** @param array<string,string> $old
     *  @param array<string,string> $new */
    private function isAppendOnlyDssChange(
        array $old,
        array $new,
        DocMdpRevisionState $state,
        int $revisionIndex,
    ): bool {
        foreach (array_keys($old + $new) as $key) {
            $previous = $old[$key] ?? null;
            $current = $new[$key] ?? null;
            if ($previous === $current) {
                continue;
            }
            if (!$this->allowsChangedDssEntry($key, $previous, $current, $state, $revisionIndex)) {
                return false;
            }
        }

        return true;
    }

    private function allowsChangedDssEntry(
        string $key,
        ?string $previous,
        ?string $current,
        DocMdpRevisionState $state,
        int $revisionIndex,
    ): bool {
        if ($previous === $current) {
            return true;
        }
        if ($key === '/VRI') {
            return $previous !== null && $current !== null
                && $this->dssRule->preservesVriEvidence(
                    $previous,
                    $current,
                    $state->newObjects,
                    $state->newObjectRevisions,
                    $revisionIndex,
                );
        }
        if (!in_array($key, ['/Certs', '/CRLs', '/OCSPs'], true)
            || $current === null
            || !preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $previous ?? '[]', $oldRefs)
            || !preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $current, $newRefs)) {
            return false;
        }
        preg_match_all('/\d+ \d+ R/', $oldRefs[1], $before);
        preg_match_all('/\d+ \d+ R/', $newRefs[1], $after);

        return array_slice($after[0], 0, count($before[0])) === $before[0];
    }

}
