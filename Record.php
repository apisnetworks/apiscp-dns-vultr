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
	 * Written by Matt Saladna <matt@apisnetworks.com>, March 2019
	 */

	namespace Opcenter\Dns\Providers\Vultr;

	class Record extends \Opcenter\Dns\Record
	{

		/**
		 * Override broken CAA formatting in Linode
		 */
		protected function formatCaa()
		{
			$data = $this->getMeta('data');
			if ($data[-1] === '"') {
				// prevent doubly-escaping
				return;
			}
			$this->setMeta('data', '"' . rtrim($data, '.') . '"');
			$this->parameter = $this->getMeta('flags') . ' ' .
				$this->getMeta('tag') . ' ' . $this->getMeta('data');
		}
	}