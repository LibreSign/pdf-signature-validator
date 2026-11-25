<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

/** Reads physical EOF boundaries without interpreting signature policy. */
final class PdfRevisionBoundaryReader
{
    private const MAX_REVISIONS = 128;
    private const MAX_PREFIX_BYTES = 536_870_912;

    public function __construct(
        private readonly PdfCrossReferenceReader $xref = new PdfCrossReferenceReader(),
        private readonly PdfHistoricalReferenceValidator $references = new PdfHistoricalReferenceValidator(),
    ) {
    }

    /** @return list<array{eof:int,end:int,xref:int}>|null */
    public function read(string $content): ?array
    {
        $position = strrpos($content, 'startxref');
        if ($position === false || !preg_match('/\Gstartxref\s+(\d+)\s+%%EOF\s*$/D', $content, $last, 0, $position)) {
            return null;
        }
        $boundaries = $this->linkedBoundaries($content, (int) $last[1]);
        if ($boundaries === null || $this->hasUnlinkedBoundary($content, array_column($boundaries, 'xref'))) {
            return null;
        }

        return array_reverse($boundaries);
    }

    /** @return list<array{eof:int,end:int,xref:int}>|null */
    private function linkedBoundaries(string $content, int $offset): ?array
    {
        $boundaries = [];
        $nextOffset = strlen($content);
        $totalBytes = 0;
        while ($offset !== null) {
            if (count($boundaries) >= self::MAX_REVISIONS || $offset >= $nextOffset
                || $offset < 0) {
                return null;
            }
            $link = $this->readLink($content, $offset, $nextOffset);
            if ($link === null) {
                return null;
            }
            $boundary = $link['boundary'];
            if ($boundaries === [] && $boundary['end'] !== strlen($content)) {
                return null;
            }
            $totalBytes += $boundary['end'];
            if ($totalBytes > self::MAX_PREFIX_BYTES) {
                return null;
            }
            $boundaries[] = $boundary;
            $nextOffset = $offset;
            $offset = $link['previous'];
        }

        return $boundaries;
    }

    /** @return array{boundary:array{eof:int,end:int,xref:int},previous:?int}|null */
    private function readLink(string $content, int $offset, int $nextOffset): ?array
    {
        $section = $this->xref->readSection($content, $offset);
        if ($section === null || isset($section['trailer']['/XRefStm'])) {
            return null;
        }
        $boundary = $this->boundary($content, $section['end'], $offset);
        if ($boundary === null || $boundary['end'] > $nextOffset
            || !$this->references->entriesMatchObjectHeaders(substr($content, 0, $boundary['end']), $section['entries'])) {
            return null;
        }
        $previous = $section['trailer']['/Prev'] ?? null;
        if ($previous !== null && !ctype_digit($previous)) {
            return null;
        }

        return ['boundary' => $boundary, 'previous' => $previous === null ? null : (int) $previous];
    }

    /** @return array{eof:int,end:int,xref:int}|null */
    private function boundary(string $content, int $position, int $offset): ?array
    {
        if (!preg_match('/\G[\x00\t\n\x0c\r ]*startxref\s+(\d+)\s+%%EOF/', $content, $marker, 0, $position)
            || (int) $marker[1] !== $offset) {
            return null;
        }
        $eof = $position + strlen($marker[0]);

        return ['eof' => $eof, 'end' => $eof + strspn($content, "\x00\t\n\x0c\r ", $eof), 'xref' => $offset];
    }

    /** @param list<int> $linkedOffsets */
    private function hasUnlinkedBoundary(string $content, array $linkedOffsets): bool
    {
        $position = 0;
        $candidates = 0;
        while (preg_match('/startxref\s+(\d+)\s+%%EOF/', $content, $candidate, PREG_OFFSET_CAPTURE, $position)) {
            if (++$candidates > 256) {
                return true;
            }
            $candidateOffset = (int) $candidate[1][0];
            $position = $candidate[0][1] + strlen($candidate[0][0]);
            if (in_array($candidateOffset, $linkedOffsets, true) || $candidateOffset >= $candidate[0][1]) {
                continue;
            }
            $section = $this->xref->readSection($content, $candidateOffset);
            if ($section !== null && $section['end'] <= $candidate[0][1]
                && preg_match('/^[\x00\t\n\x0c\r ]*$/D', substr($content, $section['end'], $candidate[0][1] - $section['end']))) {
                return true;
            }
        }

        return false;
    }
}
