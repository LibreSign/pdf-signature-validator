<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
	->in([__DIR__ . '/src', __DIR__ . '/tests'])
	->name('*.php');

return (new PhpCsFixer\Config())
	->setRiskyAllowed(true)
	->setRules([
		'@PSR12' => true,
		'declare_strict_types' => true,
		'no_unused_imports' => true,
		'ordered_imports' => true,
		'array_syntax' => ['syntax' => 'short'],
	])
	->setFinder($finder);
