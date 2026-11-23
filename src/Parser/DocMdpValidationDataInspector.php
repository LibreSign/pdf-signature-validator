<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Inspects post-certification PDF revisions for the DocMDP DSS/DocTimeStamp
 * exception. This is a structural decision, not cryptographic validation of
 * signatures, timestamp tokens or revocation data.
 *
 * Deliberately fails closed on unsupported revision formats (including xref
 * streams) rather than making a security assertion from a lenient PDF parse.
 *
 * Based on the regression work contributed in LibreSign/libresign#9556.
 *
 * @psalm-type PdfObject = array{num: int, gen: int, value: string, entries: ?array<string, string>, stream: ?string, end: int}
 * @psalm-type SignedRevision = array{startxref: int, offsets: array<int, int>, size: int, root: string, info: ?string}
 */
final class DocMdpValidationDataInspector
{
    private const int MAX_NESTING_DEPTH = 64;
    private const int MAX_REVISIONS = 128;

    /**
     * Whether *every* update after the certifying signature contains only
     * permitted validation data and its associated structural adjustments.
     *
     * The caller must supply the end of the certifying signature's ByteRange,
     * not the end of a later approval signature. False means "not proven to be
     * validation-data-only", and should leave normal DocMDP checks in effect.
     */
    public function hasOnlyValidationDataUpdates(string $content, int $certifiedEnd): bool
    {
        if ($certifiedEnd <= 0 || $certifiedEnd >= strlen($content)) {
            return false;
        }

        $signed = $this->readSignedRevision($content, $certifiedEnd);
        if ($signed === null) {
            return false;
        }

        $revisions = $this->readIncrementalUpdates($content, $certifiedEnd, $signed);
        if ($revisions === null || $revisions === [] || count($revisions) > self::MAX_REVISIONS) {
            return false;
        }

        if (!preg_match('/^(\d+) \d+ R$/', $signed['root'], $rootMatch)) {
            return false;
        }
        $rootNumber = (int) $rootMatch[1];
        $catalog = $this->readSignedObject($content, $signed, $rootNumber);
        if ($catalog === null || $catalog['entries'] === null) {
            return false;
        }

        $acroFormRef = $catalog['entries']['/AcroForm'] ?? '';
        $acroFormNumber = preg_match('/^(\d+) \d+ R$/', $acroFormRef, $acroFormMatch)
            ? (int) $acroFormMatch[1]
            : null;
        $infoNumber = $signed['info'] === null ? null : (int) $signed['info'];

        // Objects first introduced after certification must not be redefined
        // by later revisions. A revision may otherwise hide an unauthorized
        // intermediate state from a final-state-only comparison.
        $newObjects = [];
        foreach ($revisions as $revision) {
            foreach ($revision as $number => $object) {
                if ($number >= $signed['size']) {
                    if (isset($newObjects[$number])) {
                        return false;
                    }
                    $newObjects[$number] = $object;
                }
            }
        }

        $timestampFields = [];
        foreach ($newObjects as $number => $object) {
            $entries = $object['entries'];
            if ($entries === null) {
                continue;
            }

            $type = $entries['/Type'] ?? null;
            if (in_array($type, ['/Sig', '/ObjStm', '/XRef'], true)
                || (isset($entries['/ByteRange']) && $type !== '/DocTimeStamp')) {
                return false;
            }
            if ($type === '/DocTimeStamp'
                && (($entries['/SubFilter'] ?? null) !== '/ETSI.RFC3161'
                    || !isset($entries['/ByteRange'], $entries['/Contents']))) {
                return false;
            }

            if (isset($entries['/FT'])) {
                if (!$this->isTimestampField($entries, $newObjects)) {
                    return false;
                }
                $timestampFields[$number . ' 0 R'] = true;
                continue;
            }
            if ($type === '/Annot' || ($entries['/Subtype'] ?? null) === '/Widget') {
                return false;
            }
        }

        $currentDssReference = $catalog['entries']['/DSS'] ?? null;
        foreach ($revisions as $revision) {
            $containsValidationUpdate = false;

            foreach ($revision as $number => $object) {
                if ($number >= $signed['size']) {
                    continue;
                }

                $original = $this->readSignedObject($content, $signed, $number);
                if ($original === null) {
                    return false;
                }
                if ($original['value'] === $object['value'] && $original['stream'] === $object['stream']) {
                    continue;
                }
                if ($original['stream'] !== null || $object['stream'] !== null
                    || $original['entries'] === null || $object['entries'] === null) {
                    return false;
                }

                $oldEntries = $original['entries'];
                $newEntries = $object['entries'];

                $allowed = match (true) {
                    $number === $rootNumber => $this->isAllowedCatalogChange($oldEntries, $newEntries, $timestampFields),
                    $number === $acroFormNumber => $this->isAllowedAcroFormChange($oldEntries, $newEntries, $timestampFields),
                    $number === $infoNumber => $this->isAllowedEntriesChange($oldEntries, $newEntries, [], ['/ModDate', '/Producer'], $timestampFields),
                    ($oldEntries['/Type'] ?? null) === '/Page' => $this->isAllowedEntriesChange($oldEntries, $newEntries, ['/Annots'], [], $timestampFields),
                    default => false,
                };

                if (!$allowed) {
                    return false;
                }

                if ($number === $rootNumber) {
                    $dss = $newEntries['/DSS'] ?? null;
                    if ($currentDssReference !== null && $dss === null) {
                        return false;
                    }
                    if ($dss !== null && $dss !== $currentDssReference) {
                        if (!$this->isNewDssDictionary($dss, $newObjects)) {
                            return false;
                        }
                        $containsValidationUpdate = true;
                    }
                    $currentDssReference = $dss;

                    // An inline AcroForm can hold the timestamp field list.
                    if (($oldEntries['/AcroForm'] ?? null) !== ($newEntries['/AcroForm'] ?? null)) {
                        $containsValidationUpdate = true;
                    }
                } elseif ($number === $acroFormNumber) {
                    if (($oldEntries['/Fields'] ?? null) !== ($newEntries['/Fields'] ?? null)) {
                        $containsValidationUpdate = true;
                    }
                } elseif (($oldEntries['/Type'] ?? null) === '/Page') {
                    if (($oldEntries['/Annots'] ?? null) !== ($newEntries['/Annots'] ?? null)) {
                        $containsValidationUpdate = true;
                    }
                }
            }

            // A version/producer/extension-only revision is not exempt from
            // DocMDP, even if a later revision eventually adds DSS data.
            if (!$containsValidationUpdate) {
                return false;
            }
        }

        return true;
    }

    /**
     * A newly added DSS must actually reference a DSS dictionary. Allowing
     * arbitrary /Version changes or an unreferenced object is not enough.
     *
     * @param array<int, PdfObject> $newObjects
     */
    private function isNewDssDictionary(string $reference, array $newObjects): bool
    {
        if (!preg_match('/^(\d+) \d+ R$/', $reference, $match)) {
            return false;
        }
        $dss = $newObjects[(int) $match[1]]['entries'] ?? null;
        if ($dss === null || !in_array($dss['/Type'] ?? '/DSS', ['/DSS'], true)) {
            return false;
        }
        foreach (array_keys($dss) as $key) {
            if (!in_array($key, ['/Type', '/VRI', '/Certs', '/CRLs', '/OCSPs'], true)) {
                return false;
            }
        }
        return isset($dss['/VRI']) || isset($dss['/Certs']) || isset($dss['/CRLs']) || isset($dss['/OCSPs']);
    }

    /**
     * A document timestamp field: merged field and widget without kids or
     * actions, invisible (zero-area /Rect), whose value is a new
     * /DocTimeStamp dictionary with /SubFilter /ETSI.RFC3161.
     *
     * @param array<string, string> $entries
     * @param array<int, PdfObject> $newObjects
     */
    private function isTimestampField(array $entries, array $newObjects): bool {
        if (($entries['/FT'] ?? null) !== '/Sig'
            || isset($entries['/Kids']) || isset($entries['/Parent']) || isset($entries['/A']) || isset($entries['/AA'])
            || ($entries['/Type'] ?? '/Annot') !== '/Annot'
            || ($entries['/Subtype'] ?? '/Widget') !== '/Widget') {
            return false;
        }

        $rect = $entries['/Rect'] ?? null;
        $number = '(-?(?:\d+\.?\d*|\.\d+))';
        if ($rect === null || !preg_match("/^\\[{$number} {$number} {$number} {$number}\\]$/", $rect, $corners)
            || abs(((float)$corners[3] - (float)$corners[1]) * ((float)$corners[4] - (float)$corners[2])) > 0.0) {
            return false;
        }

        if (!preg_match('/^(\d+) \d+ R$/', $entries['/V'] ?? '', $match)) {
            return false;
        }
        $value = $newObjects[(int)$match[1]]['entries'] ?? null;
        return $value !== null
            && ($value['/Type'] ?? null) === '/DocTimeStamp'
            && ($value['/SubFilter'] ?? null) === '/ETSI.RFC3161';
    }

    /**
     * Trailer and object offsets of the certified revision, read through its
     * classic xref tables.
     *
     * @return SignedRevision|null
     */
    private function readSignedRevision(string $content, int $coveredEnd): ?array {
        $signedContent = substr($content, 0, $coveredEnd);
        $startxrefPos = strrpos($signedContent, 'startxref');
        if ($startxrefPos === false
            || !preg_match('/\Gstartxref\s+(\d+)\s+%%EOF\s*$/', $signedContent, $match, 0, $startxrefPos)) {
            return null;
        }
        $startxref = (int)$match[1];

        $offsets = [];
        $newestTrailer = null;
        $visited = [];
        $offset = $startxref;
        while ($offset !== null) {
            if (isset($visited[$offset]) || count($visited) >= 1000 || $offset >= $coveredEnd) {
                return null;
            }
            $visited[$offset] = true;
            $section = $this->readXrefSection($signedContent, $offset);
            if ($section === null || isset($section['trailer']['/XRefStm'])) {
                return null;
            }
            $newestTrailer ??= $section['trailer'];
            foreach ($section['entries'] as $num => [$entryOffset, , $inUse]) {
                if (!array_key_exists($num, $offsets)) {
                    $offsets[$num] = $inUse ? $entryOffset : null;
                }
            }
            $prev = $section['trailer']['/Prev'] ?? null;
            $offset = $prev === null ? null : (ctype_digit($prev) ? (int)$prev : -1);
            if ($offset === -1) {
                return null;
            }
        }

        $size = $newestTrailer['/Size'] ?? '';
        $root = $newestTrailer['/Root'] ?? '';
        $info = $newestTrailer['/Info'] ?? null;
        if (!ctype_digit($size) || !preg_match('/^\d+ \d+ R$/', $root)
            || ($info !== null && !preg_match('/^\d+ \d+ R$/', $info))) {
            return null;
        }

        return [
            'startxref' => $startxref,
            'offsets' => array_filter($offsets, static fn (?int $entryOffset): bool => $entryOffset !== null),
            'size' => (int)$size,
            'root' => $root,
            'info' => $info,
        ];
    }

    /**
     * @param SignedRevision $signed
     * @return PdfObject|null
     */
    private function readSignedObject(string $content, array $signed, int $num): ?array {
        if (!isset($signed['offsets'][$num])) {
            return null;
        }
        $object = $this->readIndirectObject($content, $signed['offsets'][$num]);
        return $object !== null && $object['num'] === $num ? $object : null;
    }

    /**
     * Parse every incremental update after the certified revision.
     *
     * @param SignedRevision $signed
     * @return list<array<int, PdfObject>>|null Each revision is retained separately
     */
    private function readIncrementalUpdates(string $content, int $coveredEnd, array $signed): ?array {
        $length = strlen($content);
        $pos = $coveredEnd;
        $prev = $signed['startxref'];
        $revisions = [];

        while (true) {
            $pos += strspn($content, "\x00\t\n\x0c\r ", $pos);
            if ($pos >= $length) {
                return $revisions;
            }

            $revision = [];
            $offsets = [];
            while (preg_match('/\G\d+\s+\d+\s+obj\b/', $content, $match, 0, $pos)) {
                $object = $this->readIndirectObject($content, $pos);
                if ($object === null || isset($revision[$object['num']])) {
                    return null;
                }
                $revision[$object['num']] = $object;
                $offsets[$object['num']] = [$pos, $object['gen']];
                $pos = $object['end'];
                $pos += strspn($content, "\x00\t\n\x0c\r ", $pos);
            }

            $xrefOffset = $pos;
            $section = $this->readXrefSection($content, $pos);
            if ($section === null) {
                return null;
            }
            $pos = $section['end'];
            if (!preg_match('/\G\s*startxref\s+(\d+)\s+%%EOF/', $content, $match, 0, $pos)
                || (int)$match[1] !== $xrefOffset) {
                return null;
            }
            $pos += strlen($match[0]);

            $trailer = $section['trailer'];
            if (($trailer['/Prev'] ?? null) !== (string)$prev
                || ($trailer['/Root'] ?? null) !== $signed['root']
                || ($trailer['/Info'] ?? $signed['info']) !== $signed['info']
                || isset($trailer['/Encrypt']) || isset($trailer['/XRefStm'])) {
                return null;
            }

            $listed = 0;
            foreach ($section['entries'] as $num => [$entryOffset, $generation, $inUse]) {
                if (!$inUse) {
                    if ($num !== 0) {
                        return null;
                    }
                    continue;
                }
                if (($offsets[$num] ?? null) !== [$entryOffset, $generation]) {
                    return null;
                }
                $listed++;
            }
            if ($listed !== count($revision)) {
                return null;
            }

            $revisions[] = $revision;
            $prev = $xrefOffset;
        }
    }

    /**
     * Classic cross-reference table and its trailer at $pos.
     *
     * @return array{entries: array<int, array{0: int, 1: int, 2: bool}>, trailer: array<string, string>, end: int}|null
     */
    private function readXrefSection(string $content, int $pos): ?array {
        if (!preg_match('/\Gxref[ \t]*(?:\r\n|\r|\n)/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);

        $entries = [];
        while (preg_match('/\G[ \t]*(\d+) (\d+)[ \t]*(?:\r\n|\r|\n)/', $content, $header, 0, $pos)) {
            $pos += strlen($header[0]);
            $first = (int)$header[1];
            for ($i = 0; $i < (int)$header[2]; $i++) {
                if (!preg_match('/\G(\d{10}) (\d{5}) ([nf])(?: \r| \n|\r\n)/', $content, $entry, 0, $pos)) {
                    return null;
                }
                $pos += 20;
                $entries[$first + $i] = [(int)$entry[1], (int)$entry[2], $entry[3] === 'n'];
            }
        }

        if (!preg_match('/\G\s*trailer\b/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);
        $this->skipPdfWhitespace($content, $pos);
        if (substr($content, $pos, 2) !== '<<') {
            return null;
        }
        $trailer = $this->readPdfDictionary($content, $pos, 0);
        if ($trailer === null) {
            return null;
        }

        return ['entries' => $entries, 'trailer' => $trailer, 'end' => $pos];
    }

    /**
     * Indirect object at $pos: "N G obj", one value, an optional stream with a
     * direct /Length, "endobj".
     *
     * @return PdfObject|null
     */
    private function readIndirectObject(string $content, int $pos): ?array {
        if (!preg_match('/\G(\d+)\s+(\d+)\s+obj\b/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);

        $this->skipPdfWhitespace($content, $pos);
        $entries = null;
        if (substr($content, $pos, 2) === '<<') {
            $valueStart = $pos;
            $entries = $this->readPdfDictionary($content, $pos, 0);
            $value = $entries === null ? null : $this->readPdfValue($content, $valueStart, 0);
        } else {
            $value = $this->readPdfValue($content, $pos, 0);
        }
        if ($value === null) {
            return null;
        }

        $stream = null;
        if (preg_match('/\G\s*stream(?:\r\n|\n)/', $content, $streamStart, 0, $pos)) {
            $length = $entries['/Length'] ?? '';
            if (!ctype_digit($length)) {
                return null;
            }
            $pos += strlen($streamStart[0]);
            $stream = substr($content, $pos, (int)$length);
            $pos += (int)$length;
            if (strlen($stream) !== (int)$length || !preg_match('/\G\s*endstream\b/', $content, $streamEnd, 0, $pos)) {
                return null;
            }
            $pos += strlen($streamEnd[0]);
        }

        if (!preg_match('/\G\s*endobj\b/', $content, $end, 0, $pos)) {
            return null;
        }

        return [
            'num' => (int)$match[1],
            'gen' => (int)$match[2],
            'value' => $value,
            'entries' => $entries,
            'stream' => $stream,
            'end' => $pos + strlen($end[0]),
        ];
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param array<string, true> $timestampFields
     */
    private function isAllowedCatalogChange(array $old, array $new, array $timestampFields): bool {
        if (!$this->isAllowedEntriesChange($old, $new, [], ['/DSS', '/Extensions', '/Version', '/AcroForm'], $timestampFields)) {
            return false;
        }
        if (($old['/AcroForm'] ?? null) === ($new['/AcroForm'] ?? null)) {
            return true;
        }

        $oldAcroForm = $this->parseDictionaryEntries($old['/AcroForm'] ?? '<<>>');
        $newAcroForm = $this->parseDictionaryEntries($new['/AcroForm'] ?? '');
        return $oldAcroForm !== null
            && $newAcroForm !== null
            && $this->isAllowedAcroFormChange($oldAcroForm, $newAcroForm, $timestampFields);
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param array<string, true> $timestampFields
     */
    private function isAllowedAcroFormChange(array $old, array $new, array $timestampFields): bool {
        return $this->isAllowedEntriesChange($old, $new, ['/Fields'], ['/SigFlags'], $timestampFields);
    }

    /**
     * @param array<string, string> $old
     * @param array<string, string> $new
     * @param list<string> $appendOnlyKeys Keys whose array may only gain timestamp fields
     * @param list<string> $freeKeys Keys whose value may change freely (checked elsewhere if needed)
     * @param array<string, true> $timestampFields References to the new timestamp fields
     */
    private function isAllowedEntriesChange(array $old, array $new, array $appendOnlyKeys, array $freeKeys, array $timestampFields): bool {
        foreach (array_keys($old + $new) as $key) {
            $oldValue = $old[$key] ?? null;
            $newValue = $new[$key] ?? null;
            if ($oldValue === $newValue || in_array($key, $freeKeys, true)) {
                continue;
            }
            if (!in_array($key, $appendOnlyKeys, true) || $newValue === null
                || !$this->isTimestampFieldAppend($oldValue ?? '[]', $newValue, $timestampFields)) {
                return false;
            }
        }
        return true;
    }

    /**
     * An array of references that keeps every old entry and only gains
     * references to the new timestamp fields.
     *
     * @param array<string, true> $timestampFields
     */
    private function isTimestampFieldAppend(string $old, string $new, array $timestampFields): bool {
        $oldRefs = $this->parseReferenceArray($old);
        $newRefs = $this->parseReferenceArray($new);
        if ($oldRefs === null || $newRefs === null || array_slice($newRefs, 0, count($oldRefs)) !== $oldRefs) {
            return false;
        }

        foreach (array_slice($newRefs, count($oldRefs)) as $ref) {
            if (!isset($timestampFields[$ref])) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return list<string>|null References like "5 0 R", or null when the value is not an array of references only
     */
    private function parseReferenceArray(string $canonicalArray): ?array {
        if (!preg_match('/^\[((?:\d+ \d+ R ?)*)\]$/', $canonicalArray, $match)) {
            return null;
        }
        preg_match_all('/\d+ \d+ R/', $match[1], $refs);
        return $refs[0];
    }

    /**
     * Top-level entries of a PDF dictionary, each value in canonical form.
     *
     * @return array<string, string>|null Null when the object is not a dictionary
     */
    private function parseDictionaryEntries(string $object): ?array {
        $pos = 0;
        $this->skipPdfWhitespace($object, $pos);
        if (substr($object, $pos, 2) !== '<<') {
            return null;
        }
        return $this->readPdfDictionary($object, $pos, 0);
    }

    /**
     * @return array<string, string>|null Null on malformed input or a duplicate key
     */
    private function readPdfDictionary(string $pdf, int &$pos, int $depth): ?array {
        if ($depth > self::MAX_NESTING_DEPTH) {
            return null;
        }
        $pos += 2;
        $entries = [];
        while (true) {
            $this->skipPdfWhitespace($pdf, $pos);
            if ($pos >= strlen($pdf) || $pdf[$pos] !== '/') {
                if (substr($pdf, $pos, 2) !== '>>') {
                    return null;
                }
                $pos += 2;
                return $entries;
            }
            $key = $this->readPdfValue($pdf, $pos, $depth + 1);
            $value = $this->readPdfValue($pdf, $pos, $depth + 1);
            if ($key === null || $value === null || isset($entries[$key])) {
                return null;
            }
            $entries[$key] = $value;
        }
    }

    /**
     * Read one PDF object at $pos and return it in a canonical form: single
     * spaces between tokens, dictionary keys sorted, names with #xx escapes
     * decoded and strings compared by their bytes, so a rewritten but
     * unchanged object compares equal regardless of the writer's formatting.
     */
    private function readPdfValue(string $pdf, int &$pos, int $depth): ?string {
        if ($depth > self::MAX_NESTING_DEPTH) {
            return null;
        }
        $this->skipPdfWhitespace($pdf, $pos);
        $length = strlen($pdf);
        if ($pos >= $length) {
            return null;
        }

        if (substr($pdf, $pos, 2) === '<<') {
            $entries = $this->readPdfDictionary($pdf, $pos, $depth + 1);
            if ($entries === null) {
                return null;
            }
            ksort($entries);
            $parts = [];
            foreach ($entries as $key => $value) {
                $parts[] = $key . ' ' . $value;
            }
            return '<<' . implode(' ', $parts) . '>>';
        }

        $char = $pdf[$pos];
        if ($char === '[') {
            $pos++;
            $items = [];
            while (true) {
                $this->skipPdfWhitespace($pdf, $pos);
                if ($pos >= $length) {
                    return null;
                }
                if ($pdf[$pos] === ']') {
                    $pos++;
                    return '[' . implode(' ', $items) . ']';
                }
                $item = $this->readPdfValue($pdf, $pos, $depth + 1);
                if ($item === null) {
                    return null;
                }
                $items[] = $item;
            }
        }

        if ($char === '(') {
            $bytes = '';
            $nesting = 0;
            for (; $pos < $length; $pos++) {
                $current = $pdf[$pos];
                if ($current === '\\') {
                    $next = $pdf[++$pos] ?? '';
                    if (preg_match('/\G[0-7]{1,3}/', $pdf, $octal, 0, $pos)) {
                        $bytes .= chr((int)octdec($octal[0]) & 0xff);
                        $pos += strlen($octal[0]) - 1;
                    } elseif ($next === "\r" && ($pdf[$pos + 1] ?? '') === "\n") {
                        $pos++;
                    } elseif ($next !== "\r" && $next !== "\n") {
                        $bytes .= strtr($next, 'nrtbf', "\n\r\t\x08\x0c");
                    }
                    continue;
                }
                if ($current === '(' && $nesting++ === 0) {
                    continue;
                }
                if ($current === ')' && --$nesting === 0) {
                    $pos++;
                    return '<' . bin2hex($bytes) . '>';
                }
                $bytes .= $current;
            }
            return null;
        }

        if ($char === '<') {
            $end = strpos($pdf, '>', $pos);
            if ($end === false) {
                return null;
            }
            $hex = strtolower((string)preg_replace('/\s+/', '', substr($pdf, $pos + 1, $end - $pos - 1)));
            if (!ctype_xdigit($hex) && $hex !== '') {
                return null;
            }
            $pos = $end + 1;
            return '<' . $hex . (strlen($hex) % 2 === 1 ? '0' : '') . '>';
        }

        if (!preg_match('/\G\/?[^\x00\t\n\x0c\r ()<>\[\]{}\/%]*/', $pdf, $token, 0, $pos) || $token[0] === '') {
            return null;
        }
        $pos += strlen($token[0]);

        if ($char === '/') {
            return $this->canonicalName(substr($token[0], 1));
        }

        if (ctype_digit($token[0]) && preg_match('/\G\s+(\d+)\s+R(?![^\x00\t\n\x0c\r ()<>\[\]{}\/%])/', $pdf, $ref, 0, $pos)) {
            $pos += strlen($ref[0]);
            return $token[0] . ' ' . $ref[1] . ' R';
        }

        return $token[0];
    }

    /**
     * Name with #xx escapes decoded, then re-escaped only where needed, so
     * /ObjStm and /Obj#53tm compare equal.
     */
    private function canonicalName(string $name): string {
        $decoded = (string)preg_replace_callback(
            '/#([0-9A-Fa-f]{2})/',
            static fn (array $match): string => chr((int)hexdec($match[1])),
            $name,
        );
        return '/' . (string)preg_replace_callback(
            '/[^\x21-\x7e]|[#()<>\[\]{}\/%]/',
            static fn (array $match): string => sprintf('#%02X', ord($match[0])),
            $decoded,
        );
    }

    private function skipPdfWhitespace(string $pdf, int &$pos): void {
        $length = strlen($pdf);
        while ($pos < $length) {
            if (str_contains("\x00\t\n\x0c\r ", $pdf[$pos])) {
                $pos++;
            } elseif ($pdf[$pos] === '%') {
                $pos += strcspn($pdf, "\r\n", $pos);
            } else {
                return;
            }
        }
    }

}
