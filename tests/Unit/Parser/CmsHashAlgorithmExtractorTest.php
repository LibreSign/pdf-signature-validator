<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\CmsHashAlgorithmExtractor;
use PHPUnit\Framework\TestCase;

final class CmsHashAlgorithmExtractorTest extends TestCase
{
    public function testReturnsNullForInvalidCmsPayload(): void
    {
        $extractor = new CmsHashAlgorithmExtractor();
        $this->assertNull($extractor->extract('not-der'));
    }
}
