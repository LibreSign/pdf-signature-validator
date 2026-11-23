<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

/**
 * Decodes PDF literal strings and their escape sequences.
 */
final class PdfLiteralStringReader
{
    /**
     * Canonicalizes literal PDF strings as hexadecimal bytes.
     * Offsets are advanced in place; malformed input returns null.
     */
    public function read(string $pdf, int &$pos): ?string
    {
        $bytes = '';
        $nesting = 0;
        for (; $pos < strlen($pdf); $pos++) {
            $current = $pdf[$pos];
            if ($current === '\\') {
                $this->consumeStringEscape($pdf, $pos, $bytes);
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

    private function consumeStringEscape(string $pdf, int &$pos, string &$bytes): void
    {
        $next = $pdf[++$pos] ?? '';
        if (preg_match('/\G[0-7]{1,3}/', $pdf, $octal, 0, $pos)) {
            $bytes .= chr((int) octdec($octal[0]) & 0xff);
            $pos += strlen($octal[0]) - 1;
        } elseif ($next === "\r" && ($pdf[$pos + 1] ?? '') === "\n") {
            $pos++;
        } elseif ($next !== "\r" && $next !== "\n") {
            $bytes .= strtr($next, 'nrtbf', "\n\r\t\x08\x0c");
        }
    }
}
