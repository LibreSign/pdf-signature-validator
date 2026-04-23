<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

use Rector\Config\RectorConfig;

return static function (RectorConfig $rectorConfig): void {
	$rectorConfig->paths([
		__DIR__ . '/src',
		__DIR__ . '/tests',
	]);

	$rectorConfig->phpVersion(\Rector\ValueObject\PhpVersion::PHP_82);
	$rectorConfig->sets([
		\Rector\Set\ValueObject\SetList::CODE_QUALITY,
		\Rector\Set\ValueObject\SetList::TYPE_DECLARATION,
	]);
};
