<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

/**
 * The DocMDP /P value of a certification signature (ISO 32000-1, 12.8.2.2).
 */
enum DocMdpPermission: int
{
    case NO_CHANGES = 1;
    case FORM_FILLING = 2;
    case FORM_FILLING_AND_ANNOTATIONS = 3;
}
