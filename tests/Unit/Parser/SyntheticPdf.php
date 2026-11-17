<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

/**
 * Builds small PDFs for the inventory tests.
 */
final class SyntheticPdf
{
    private const PAGES = [
        2 => '<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
        3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] >>',
    ];

    /** Filled in by fillByteRanges() once the revision is written. */
    private const BYTE_RANGE_PLACEHOLDER = '/ByteRange [0 0000000000 0000000000 0000000000]';

    /** A /ByteRange that covers the file except the /Contents that follows it. */
    public const SIGNED_BYTES = self::BYTE_RANGE_PLACEHOLDER . ' /Contents <0000>';

    public static function signature(?int $permission): string
    {
        return self::signatureWithReferences(
            $permission === null ? null : [self::docMdpReference('/P ' . $permission)],
        );
    }

    /**
     * @param list<string>|null $references
     */
    public static function signatureWithReferences(?array $references): string
    {
        $dictionary = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ' . self::SIGNED_BYTES;

        if ($references !== null) {
            $dictionary .= ' /Reference [' . implode(' ', $references) . ']';
        }

        return $dictionary . ' >>';
    }

    public static function docMdpReference(string $permissionEntry): string
    {
        return '<< /Type /SigRef /TransformMethod /DocMDP'
            . ' /TransformParams << /Type /TransformParams ' . $permissionEntry . ' /V /1.2 >> >>';
    }

    /**
     * One active certification, referenced from /Perms and from a field.
     */
    public static function certifiedPdf(string $signature): string
    {
        return self::pdf([
            1 => '<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> /AcroForm << /Fields [7 0 R] >> >>',
            5 => $signature,
            7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
        ]);
    }

    /**
     * Rewrites the last /ByteRange in place, keeping its serialized length.
     *
     * @param callable(list<int>): list<int> $change
     */
    public static function changeLastByteRange(string $pdf, callable $change): string
    {
        $position = (int)strrpos($pdf, '/ByteRange [');
        $length = (int)strpos($pdf, ']', $position) + 1 - $position;
        preg_match_all('/\d+/', substr($pdf, $position, $length), $matches);
        $byteRange = vsprintf('/ByteRange [%d %010d %010d %010d]', $change(array_map('intval', $matches[0])));

        return substr_replace($pdf, $byteRange, $position, $length);
    }

    /**
     * A PDF with a classic cross-reference table. Objects 2 and 3 are the page tree.
     *
     * @param array<int, string> $objects
     * @param array<int, int> $generations of the objects that are not generation 0,
     *                                     written in the object header and in the table
     */
    public static function pdf(array $objects, array $generations = []): string
    {
        $objects += self::PAGES;
        ksort($objects);

        $pdf = "%PDF-1.7\n";
        $offsets = [];
        foreach ($objects as $number => $body) {
            $offsets[$number] = strlen($pdf);
            $pdf .= sprintf("%d %d obj\n%s\nendobj\n", $number, $generations[$number] ?? 0, $body);
        }

        $size = max(array_keys($objects)) + 1;
        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n0 $size\n0000000000 65535 f \n";
        for ($number = 1; $number < $size; $number++) {
            $pdf .= isset($offsets[$number])
                ? sprintf("%010d %05d n \n", $offsets[$number], $generations[$number] ?? 0)
                : "0000000000 65535 f \n";
        }

        return self::fillByteRanges($pdf . "trailer\n<< /Size $size /Root 1 0 R >>\nstartxref\n$xrefOffset\n%%EOF\n", 0);
    }

    /**
     * Appends a revision that replaces or adds the given objects.
     *
     * @param array<int, string> $objects
     */
    public static function incrementalUpdate(string $pdf, array $objects): string
    {
        $revisionStart = strlen($pdf);
        preg_match_all('/startxref\s+(\d+)/', $pdf, $matches);
        $previous = (int)end($matches[1]);
        preg_match_all('/\/Size (\d+)/', $pdf, $sizes);
        $size = max((int)end($sizes[1]), max(array_keys($objects)) + 1);

        $xref = "xref\n";
        foreach ($objects as $number => $body) {
            $xref .= sprintf("%d 1\n%010d 00000 n \n", $number, strlen($pdf));
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }

        $xrefOffset = strlen($pdf);

        return self::fillByteRanges(
            $pdf . $xref . "trailer\n<< /Size $size /Root 1 0 R /Prev $previous >>\nstartxref\n$xrefOffset\n%%EOF\n",
            $revisionStart,
        );
    }

    /**
     * Fills the /ByteRange placeholders written from $offset on, so each
     * signature covers the whole file except its own /Contents. The numbers
     * keep the placeholder width, so no offset moves.
     */
    private static function fillByteRanges(string $pdf, int $offset): string
    {
        while (($position = strpos($pdf, self::BYTE_RANGE_PLACEHOLDER, $offset)) !== false) {
            $contentsStart = (int)strpos($pdf, '<', (int)strpos($pdf, '/Contents', $position));
            $contentsEnd = (int)strpos($pdf, '>', $contentsStart) + 1;
            $byteRange = sprintf(
                '/ByteRange [0 %010d %010d %010d]',
                $contentsStart,
                $contentsEnd,
                strlen($pdf) - $contentsEnd,
            );
            $pdf = substr_replace($pdf, $byteRange, $position, strlen($byteRange));
            $offset = $position + strlen($byteRange);
        }

        return $pdf;
    }

    /**
     * A PDF 1.5 file whose $compressed objects live in a Flate-encoded object
     * stream, indexed by a cross-reference stream.
     *
     * @param array<int, string> $direct
     * @param array<int, string> $compressed
     */
    public static function withObjectStream(array $direct, array $compressed): string
    {
        $direct += self::PAGES;
        $streamNumber = max(array_keys($direct + $compressed)) + 1;
        $xrefNumber = $streamNumber + 1;

        $pdf = "%PDF-1.5\n";
        $entries = [0 => pack('CNn', 0, 0, 65535)];
        foreach ($direct as $number => $body) {
            $entries[$number] = pack('CNn', 1, strlen($pdf), 0);
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }

        $index = '';
        $bodies = '';
        $position = 0;
        foreach ($compressed as $number => $body) {
            $index .= $number . ' ' . strlen($bodies) . ' ';
            $bodies .= $body . "\n";
            $entries[$number] = pack('CNn', 2, $streamNumber, $position++);
        }

        $data = gzcompress($index . $bodies);
        $entries[$streamNumber] = pack('CNn', 1, strlen($pdf), 0);
        $pdf .= "$streamNumber 0 obj\n<< /Type /ObjStm /N " . count($compressed) . ' /First ' . strlen($index)
            . ' /Filter /FlateDecode /Length ' . strlen($data) . " >>\nstream\n$data\nendstream\nendobj\n";

        $xrefOffset = strlen($pdf);
        $entries[$xrefNumber] = pack('CNn', 1, $xrefOffset, 0);
        ksort($entries);
        $table = '';
        for ($number = 0; $number <= $xrefNumber; $number++) {
            $table .= $entries[$number] ?? pack('CNn', 0, 0, 0);
        }

        $pdf .= "$xrefNumber 0 obj\n<< /Type /XRef /Size " . ($xrefNumber + 1) . ' /W [1 4 2] /Root 1 0 R /Length '
            . strlen($table) . " >>\nstream\n$table\nendstream\nendobj\n";

        return $pdf . "startxref\n$xrefOffset\n%%EOF\n";
    }
}
