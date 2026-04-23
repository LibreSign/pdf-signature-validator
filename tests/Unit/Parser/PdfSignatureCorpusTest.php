<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;

final class PdfSignatureCorpusTest extends TestCase
{
    #[DataProvider('corpusPdfProvider')]
    public function testExtractorProcessesAllAvailableCorpusPdfs(string $pdfPath): void
    {
        $extractor = new PdfSignatureExtractor();

        $content = file_get_contents($pdfPath);
        $this->assertIsString($content, $pdfPath);

        $signatures = $extractor->extractFromString($content);

        // Core business guarantee: a signature corpus file must produce at least one signature.
        $this->assertNotEmpty($signatures, $pdfPath);

        foreach ($signatures as $signature) {
            $this->assertNotNull($signature->binarySignature, $pdfPath);
            $this->assertNotSame('', $signature->binarySignature, $pdfPath);
            $this->assertNotNull($signature->metadata->signatureType, $pdfPath);
            $this->assertNotSame('', $signature->metadata->signatureType, $pdfPath);
        }
    }

    #[DataProvider('corpusPdfProvider')]
    public function testPdfsigParityWhenToolIsAvailable(string $pdfPath): void
    {
        if (!is_executable('/usr/bin/pdfsig')) {
            $this->markTestSkipped('pdfsig is not available in this environment.');
        }

        $extractor = new PdfSignatureExtractor();
        $content = file_get_contents($pdfPath);
        $this->assertIsString($content, $pdfPath);

        $native = $extractor->extractFromString($content);
        $nativeCount = count($native);

        $output = shell_exec('env TZ=UTC /usr/bin/pdfsig ' . escapeshellarg($pdfPath) . ' 2>&1');
        $this->assertIsString($output, $pdfPath);

        $poppler = $this->parsePdfsigOutput($output);
        $this->assertSame(count($poppler), $nativeCount, $pdfPath . ': signature count mismatch with pdfsig');

        if ($nativeCount === 0) {
            return;
        }

        $firstNative = $native[0];
        $firstPoppler = $poppler[0] ?? [];

        if (isset($firstPoppler['field'])) {
            $this->assertSame($firstPoppler['field'], $firstNative->metadata->field, $pdfPath . ': field mismatch');
        }

        if (isset($firstPoppler['signature_type'])) {
            $this->assertSame($firstPoppler['signature_type'], $firstNative->metadata->signatureType, $pdfPath . ': signature type mismatch');
        }

        if (isset($firstPoppler['signing_hash_algorithm']) && $firstNative->hashAlgorithm !== null) {
            $this->assertSame($firstPoppler['signing_hash_algorithm'], $firstNative->hashAlgorithm, $pdfPath . ': hash algorithm mismatch');
        }
    }

    public function testDiscoversLargeExternalCorpusWhenPresent(): void
    {
        $external = self::resolvePopplerCorpusPath();
        if ($external === null) {
            $this->markTestSkipped('Poppler corpus submodule is not available in this workspace.');
        }

        $files = self::collectPdfFiles($external);
        $this->assertGreaterThanOrEqual(20, count($files), 'Expected a large corpus in poppler test submodule.');
    }

    /**
     * @return iterable<string, array{0:string}>
     */
    public static function corpusPdfProvider(): iterable
    {
        $paths = [];

        foreach (self::candidateCorpusRoots() as $root) {
            foreach (self::collectPdfFiles($root) as $file) {
                $paths[$file] = [$file];
            }
        }

        if ($paths === []) {
            throw new RuntimeException('No PDF corpus files were found.');
        }

        foreach ($paths as $file => $case) {
            yield basename($file) . ' @ ' . dirname($file) => $case;
        }
    }

    /**
     * @return list<string>
     */
    private static function candidateCorpusRoots(): array
    {
        $popplerCorpus = self::resolvePopplerCorpusPath();

        $roots = [
            realpath(__DIR__ . '/../../Fixtures/pdfs') ?: '',
            $popplerCorpus ?? '',
        ];

        $valid = [];
        foreach ($roots as $root) {
            if ($root !== '' && is_dir($root)) {
                $valid[$root] = $root;
            }
        }

        return array_values($valid);
    }

    private static function resolvePopplerCorpusPath(): ?string
    {
        $path = realpath(__DIR__ . '/../../Fixtures/corpus/poppler-test/unittestcases/signature');
        if (is_string($path) && is_dir($path)) {
            return $path;
        }

        $override = getenv('POPLER_TEST_CORPUS_PATH');
        if (is_string($override) && $override !== '' && is_dir($override)) {
            return $override;
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private static function collectPdfFiles(string $root): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            if (strtolower($file->getExtension()) !== 'pdf') {
                continue;
            }

            // This suite validates signed-corpus behavior; unsigned fixtures are tested separately.
            if ($file->getFilename() === 'small_valid.pdf') {
                continue;
            }

            $files[] = $file->getPathname();
        }

        sort($files);
        return $files;
    }

    /**
     * @return list<array{field?:string,signature_type?:string,signing_hash_algorithm?:string}>
     */
    private function parsePdfsigOutput(string $output): array
    {
        $signatures = [];
        $current = null;

        foreach (preg_split('/\R/', $output) ?: [] as $line) {
            $line = trim($line);

            if (preg_match('/^Signature #(\d+):$/', $line)) {
                if ($current !== null) {
                    $signatures[] = $current;
                }
                $current = [];
                continue;
            }

            if ($current === null) {
                continue;
            }

            if (preg_match('/^- Signature Field Name:\s*(.+)$/', $line, $m)) {
                $current['field'] = $m[1];
                continue;
            }

            if (preg_match('/^- Signature Type:\s*(.+)$/', $line, $m)) {
                $current['signature_type'] = $m[1];
                continue;
            }

            if (preg_match('/^- Signing Hash Algorithm:\s*(.+)$/', $line, $m)) {
                $current['signing_hash_algorithm'] = $m[1];
                continue;
            }
        }

        if ($current !== null) {
            $signatures[] = $current;
        }

        return $signatures;
    }
}
