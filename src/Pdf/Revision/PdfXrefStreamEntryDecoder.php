<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

/**
 * Decodes uncompressed PDF xref entries without recovery heuristics.
 * Type 2 entries are returned with their object-stream/index locators for
 * subsequent strict historical resolution.
 */
final class PdfXrefStreamEntryDecoder
{
    private const MAX_DECODED_BYTES = 16_777_216;
    private const MAX_ENTRIES = 250_000;

    /** @param array<string,string> $trailer
     *  @return array{entries:array<int,array{int,int,bool}>,compressed:array<int,array{int,int}>}|null */
    public function decode(string $pdf, array $trailer, string $stream): ?array
    {
        $size = (int) ($trailer['/Size'] ?? 0);
        $widths = $this->widths($trailer['/W'] ?? '');
        if ($size < 1 || $size > self::MAX_ENTRIES || $widths === null) {
            return null;
        }
        $indices = $this->indexPairs($trailer['/Index'] ?? null, $size);
        if ($indices === null) {
            return null;
        }
        $expectedBytes = $this->expectedBytes($widths, $indices);
        if ($expectedBytes === null) {
            return null;
        }
        $decoded = $this->decodeStream($stream, isset($trailer['/Filter']));
        if ($decoded === null || strlen($decoded) !== $expectedBytes) {
            return null;
        }
        $result = $this->readEntries($decoded, $widths, $indices);
        if ($result === null || !$this->offsetsMatchHeaders($pdf, $result['entries'])) {
            return null;
        }

        return $result;
    }

    /**
     * @param array{int,int,int} $widths
     * @param list<array{int,int}> $indices
     */
    private function expectedBytes(array $widths, array $indices): ?int
    {
        $count = array_sum(array_column($indices, 1));
        $bytes = $count * array_sum($widths);

        return $count > self::MAX_ENTRIES || $bytes > self::MAX_DECODED_BYTES ? null : $bytes;
    }

    /** @return array{int,int,int}|null */
    private function widths(string $value): ?array
    {
        if (!preg_match('/^\[(\d+) (\d+) (\d+)\]$/', $value, $match)) {
            return null;
        }
        $widths = [(int) $match[1], (int) $match[2], (int) $match[3]];
        $total = array_sum($widths);

        return $total >= 1 && $total <= 24 && max($widths) <= 8 ? $widths : null;
    }

    /** @return list<array{int,int}>|null */
    private function indexPairs(?string $index, int $size): ?array
    {
        if ($index === null) {
            return [[0, $size]];
        }
        if (!preg_match('/^\[((?:\d+ ?)*)\]$/', $index, $value)) {
            return null;
        }
        preg_match_all('/\d+/', $value[1], $matches);
        $numbers = array_map('intval', $matches[0]);
        if ($numbers === [] || count($numbers) % 2 !== 0) {
            return null;
        }

        $pairs = [];
        $seen = [];
        foreach (array_chunk($numbers, 2) as [$first, $length]) {
            if ($length < 1 || $first < 0 || $first > $size
                || $length > $size - $first) {
                return null;
            }
            for ($number = $first; $number < $first + $length; $number++) {
                if (isset($seen[$number])) {
                    return null;
                }
                $seen[$number] = true;
            }
            $pairs[] = [$first, $length];
        }

        return $pairs;
    }

    /** @SuppressWarnings(PHPMD.ErrorControlOperator) Invalid compressed input is an expected rejection. */
    private function decodeStream(string $stream, bool $flate): ?string
    {
        if (!$flate) {
            return $stream;
        }
        if (!function_exists('gzuncompress')) {
            return null;
        }
        $decoded = @gzuncompress($stream, self::MAX_DECODED_BYTES);

        return is_string($decoded) ? $decoded : null;
    }

    /**
     * @param array{int,int,int} $widths
     * @param list<array{int,int}> $indices
     * @return array{entries:array<int,array{int,int,bool}>,compressed:array<int,array{int,int}>}|null
     */
    private function readEntries(string $binary, array $widths, array $indices): ?array
    {
        $entries = [];
        $compressed = [];
        $cursor = 0;
        foreach ($indices as [$first, $span]) {
            for ($index = 0; $index < $span; $index++) {
                $values = [];
                foreach ($widths as $width) {
                    $value = 0;
                    for ($i = 0; $i < $width; $i++) {
                        $byte = ord($binary[$cursor++]);
                        if ($value > intdiv(PHP_INT_MAX - $byte, 256)) {
                            return null;
                        }
                        $value = $value * 256 + $byte;
                    }
                    $values[] = $value;
                }

                $type = $widths[0] === 0 ? 1 : $values[0];
                $number = $first + $index;
                if ($type === 2) {
                    if ($values[1] <= 0) {
                        return null;
                    }
                    $compressed[$number] = [$values[1], $values[2]];
                    continue;
                }
                if ($type !== 0 && $type !== 1) {
                    return null;
                }
                $entries[$number] = [$values[1], $values[2], $type === 1];
            }
        }

        return ['entries' => $entries, 'compressed' => $compressed];
    }

    /** @param array<int,array{int,int,bool}> $entries */
    private function offsetsMatchHeaders(string $pdf, array $entries): bool
    {
        foreach ($entries as $number => [$offset, $generation, $inUse]) {
            if (!$inUse) {
                continue;
            }
            $pattern = '/\G' . $number . '\s+' . $generation . '\s+obj\b/';
            if ($offset >= strlen($pdf)
                || preg_match($pattern, $pdf, $header, 0, $offset) !== 1) {
                return false;
            }
        }

        return true;
    }
}
