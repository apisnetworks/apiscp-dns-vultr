<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
	 */

	namespace Opcenter\Dns\Providers\Vultr;

	use GuzzleHttp\Exception\RequestException;
	use Opcenter\Dns\Contracts\ServiceProvider;
	use Opcenter\Service\ConfigurationContext;

	class Validator implements ServiceProvider
	{
		public function valid(ConfigurationContext $ctx, &$var): bool
		{
			return ctype_alnum($var) && strtoupper($var) === $var && static::keyValid((string)$var);
		}

		public static function keyValid(string $key): bool
		{
			try {
				(new Api($key))->do('GET', 'account');
			} catch (RequestException $e) {
				$status = $e->getResponse()->getStatusCode();
				if (403 === $status) {
					return error('Vultr key failed: invalid key');
				}

				return error("Unable to verify Vultr key. Unknown HTTP status `%d' returned", $status);
			}

			return true;
		}
	}
