<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Fixtures;

use RuntimeException;
use SignerPHP\PdfCore\Service\PdfDocumentPreparer;

/**
 * Builds post-certification PDF revisions from a real certified document.
 *
 * Preserve original catalog bytes: reserializing its PDF strings can change
 * significant bytes unrelated to the DSS being tested.
 */
final class CertifiedPdfRevisionFixture
{
    /**
     * @return array{string, string} original PDF and incrementally updated PDF
     */
    public static function withDss(): array
    {
        return self::createDssRevision(null);
    }

    /** @return array{string,string} */
    public static function withDssAndChangedPageTree(): array
    {
        return self::createDssRevision(self::changePageTree(...));
    }

    /** @param (\Closure(string): string)|null $catalogChange
     * @return array{string,string}
     */
    private static function createDssRevision(?\Closure $catalogChange): array
    {
        $pdf = file_get_contents(__DIR__ . '/pdfs/real_jsignpdf_level1.pdf');
        if ($pdf === false) {
            throw new RuntimeException('Certified PDF test fixture is missing');
        }

        $document = (new PdfDocumentPreparer())->prepare($pdf);
        $trailer = $document->getTrailerObject();
        $root = (string) $trailer['Root'];
        $rootNumber = (int) $trailer['Root']->asObjectReferenceOrNull();
        $offset = $document->getXrefTable()[$rootNumber] ?? null;
        $size = $trailer['Size']->asIntOrNull();
        if (!is_int($offset) || !is_int($size)) {
            throw new RuntimeException('Certified PDF fixture has no readable catalog');
        }

        $catalog = self::catalogAt($pdf, $offset);
        if ($catalogChange instanceof \Closure) {
            $catalog = $catalogChange($catalog);
        }
        $catalog = substr_replace($catalog, "/DSS $size 0 R>>", (int) strrpos($catalog, '>>'), 2);
        $objects = [
            $rootNumber => $catalog,
            $size => '<< /Type /DSS /Certs [' . ($size + 1) . ' 0 R] >>',
            $size + 1 => "<< /Length 4 >>\nstream\nABCD\nendstream",
        ];

        return [$pdf, self::appendRevision($pdf, $objects, $root, $size + 2, isset($trailer['Info']) ? (string) $trailer['Info'] : null)];
    }

    private static function catalogAt(string $pdf, int $offset): string
    {
        if (!preg_match('/^\d+\s+\d+\s+obj\s*(.*?)\s*endobj/s', substr($pdf, $offset), $match)) {
            throw new RuntimeException('Certified PDF catalog is unreadable');
        }

        return $match[1];
    }

    private static function changePageTree(string $catalog): string
    {
        $updated = preg_replace('/\/Pages\s+\d+\s+\d+\s+R/', '/Pages 99 0 R', $catalog, 1, $count);
        if ($count !== 1 || $updated === null) {
            throw new RuntimeException('Certified PDF has no page tree reference');
        }

        return $updated;
    }

    /** @param array<int, string> $objects */
    private static function appendRevision(
        string $pdf,
        array $objects,
        string $rootReference,
        int $size,
        ?string $infoReference,
    ): string {
        preg_match_all('/startxref\s+(\d+)/', $pdf, $matches);
        if ($matches[1] === []) {
            throw new RuntimeException('Certified PDF is missing startxref');
        }
        $previous = (int) end($matches[1]);
        ksort($objects);
        $offsets = [];

        foreach ($objects as $number => $value) {
            $offsets[$number] = strlen($pdf);
            $pdf .= "$number 0 obj\n$value\nendobj\n";
        }

        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n";
        foreach ($offsets as $number => $offset) {
            $pdf .= sprintf("%d 1\n%010d 00000 n \n", $number, $offset);
        }

        $info = $infoReference === null ? '' : "/Info $infoReference ";
        return $pdf . "trailer\n<< /Size $size /Root $rootReference $info/Prev $previous >>\n"
            . "startxref\n$xrefOffset\n%%EOF\n";
    }
}
