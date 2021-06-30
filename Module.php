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

	use GuzzleHttp\Exception\ClientException;
	use Illuminate\Support\Arr;
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Dns\Record as BaseRecord;

	class Module extends \Dns_Module implements ProviderInterface
	{
		use \NamespaceUtilitiesTrait;

		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = false;
		protected static $permitted_records = [
			'A',
			'AAAA',
			'CAA',
			'CNAME',
			'MX',
			'NS',
			'SSHFP',
			'SRV',
			'TXT',
		];

		// @var array API credentials
		private $key;

		public function __construct()
		{
			parent::__construct();
			$this->key = $this->getServiceValue('dns', 'key', DNS_PROVIDER_KEY);
		}

		/**
		 * Add a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		public function add_record(
			string $zone,
			string $subdomain,
			string $rr,
			string $param,
			int $ttl = self::DNS_TTL
		): bool {
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			if (!$this->owned_zone($zone)) {
				return error("Domain `%s' not owned by account", $zone);
			}
			$api = $this->makeApi();
			$record = new Record($zone, [
				'name'      => $subdomain,
				'rr'        => $rr,
				'parameter' => $param,
				'ttl'       => $ttl
			]);
			if ($record['name'] === '@') {
				$record['name'] = '';
			}
			try {
				// success returns nothing (wtf...)
				$api->do('POST', 'domains/' . $zone . '/records', $this->formatRecord($record));
				$this->addCache($record);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				if ($e->getResponse()->getStatusCode() === 412 &&
					false !== strpos($e->getResponse()->getBody()->getContents(), 'Duplicate records not allowed')) {
					return warn("Duplicate record for `%s' type %s %s skipped", $fqdn, $rr, $param);
				}

				return error("Failed to create record `%s' type %s: %s", $fqdn, $rr, $e->getMessage());
			}

			return $api->getResponse()->getStatusCode() === 201;
		}

		/**
		 * @inheritDoc
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = ''): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			if (!$this->owned_zone($zone)) {
				return error("Domain `%s' not owned by account", $zone);
			}
			$api = $this->makeApi();

			$id = $this->getRecordId($r = new Record($zone,
				['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]));
			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Record `%s' (rr: `%s', param: `%s')  does not exist", $fqdn, $rr, $param);
			}

			try {
				$api->do('DELETE', 'domains/' . $zone . '/records/' . $id);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to delete record `%s' type %s", $fqdn, $rr);
			}

			array_forget_first($this->zoneCache[$r->getZone()], $this->getCacheKey($r), static function ($v) use ($r) {
				return $v['id'] === $r['id'];
			});

			return $api->getResponse()->getStatusCode() === 204;
		}

		/**
		 * Add DNS zone to service
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool
		{
			/**
			 * @var Zones $api
			 */
			$api = $this->makeApi();
			try {
				$api->do('POST', 'domains', [
					'domain'   => $domain
				]);
			} catch (ClientException $e) {
				return error("Failed to add zone `%s', error: %s", $domain, $e->getMessage());
			}

			return true;
		}

		/**
		 * Remove DNS zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			$api = $this->makeApi();
			try {
				$api->do('DELETE', 'domains/' . $domain);
			} catch (ClientException $e) {
				return error("Failed to remove zone `%s', error: %s", $domain, $e->getMessage());
			}

			return true;
		}

		/**
		 * Get raw zone data
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr(string $domain): ?string
		{
			$client = $this->makeApi();
			try {
				$client->do('GET', 'domains/' . $domain . '/soa');
			} catch (ClientException $e) {
				return null;
			}

			try {
				// Vultr/Choopa's SOA support sucks
				$soa = $this->get_records_external('', 'SOA', $domain,
						$this->get_hosting_nameservers($domain))[0] ?? null;
				if (!$soa) {
					return null;
				}
				$zoneText = [$soa['name'] . '. ' . $soa['ttl'] . ' IN SOA ' . $soa['parameter']];
				$records = $client->do('GET', 'domains/' . $domain . '/records', ['per_page' => 500]);
			} catch (ClientException $e) {
				error('Failed to transfer DNS records from Vultr - try again later');

				return null;
			}

			$this->zoneCache[$domain] = [];
			foreach (array_get($records, 'records', []) as $r) {
				switch ($r['type']) {
					case 'SRV':
					case 'MX':
						$parameter = $r['priority'] . ' ' . $r['data'];
						break;
					default:
						$parameter = $r['data'];
				}
				$robj = new Record($domain,
					[
						'name'      => $r['name'],
						'rr'        => $r['type'],
						'ttl'       => $r['ttl'] ?? static::DNS_TTL,
						'parameter' => $parameter,
						'meta'      => [
							'id' => $r['id']
						]
					]
				);
				$this->addCache($robj);
				$zoneText[] = (string)$robj;
			}

			return implode("\n", $zoneText);
		}

		private function makeApi(): Api
		{
			return new Api($this->key);
		}

		/**
		 * Get hosting nameservers
		 *
		 * @param string|null $domain
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			return ['ns1.vultr.com', 'ns2.vultr.com'];
		}

		public function record_exists(string $zone, string $subdomain, string $rr = 'ANY', string $parameter = ''): bool
		{
			if (strtoupper($rr) === 'ANY') {
				$records = $this->get_zone_data($zone);

				foreach (Arr::collapse($records) as $r) {
					if ($r['subdomain'] === $subdomain && (!$parameter || $parameter === $r['parameter'])) {
						return true;
					}
				}

				return false;
			}
			return parent::record_exists($zone, $subdomain, $rr, $parameter); // TODO: Change the autogenerated stub
		}


		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, BaseRecord $old, BaseRecord $new): bool
		{
			if (!$this->canonicalizeRecord($zone, $old['name'], $old['rr'], $old['parameter'], $old['ttl'])) {
				return false;
			}
			if (!$this->getRecordId($old)) {
				return error("failed to find record ID in Vultr zone `%s' - does `%s' (rr: `%s', parameter: `%s') exist?",
					$zone, $old['name'], $old['rr'], $old['parameter']);
			}
			if (!$this->canonicalizeRecord($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'])) {
				return false;
			}
			$api = $this->makeApi();
			try {
				$merged = clone $old;
				$new = $merged->merge($new);
				$id = $this->getRecordId($old);
				$api->do('PATCH', 'domains/' . $zone . '/records/' . $id, $this->formatRecord($new));
			} catch (ClientException $e) {
				$reason = \json_decode($e->getResponse()->getBody()->getContents());

				return error("Failed to update record `%s' on zone `%s' (old - rr: `%s', param: `%s'; new - rr: `%s', param: `%s'): %s",
					$old['name'],
					$zone,
					$old['rr'],
					$old['parameter'], $new['name'] ?? $old['name'], $new['parameter'] ?? $old['parameter'],
					$reason->errors[0]->message
				);
			}

			array_forget_first($this->zoneCache[$old->getZone()], $this->getCacheKey($old), static function ($v) use ($old) {
				return $v['id'] === $old['id'];
			});

			$this->addCache($new);

			return true;
		}

		/**
		 * Normalize record
		 *
		 * @param string   $zone
		 * @param string   $subdomain
		 * @param string   $rr
		 * @param string   $param
		 * @param int|null $ttl
		 * @return bool
		 */
		protected function canonicalizeRecord(
			string &$zone,
			string &$subdomain,
			string &$rr,
			string &$param,
			int &$ttl = null
		): bool {
			$rr = strtoupper($rr);
			if ($rr === 'SSHFP') {
				$param = strtolower($param);
			} else if ($rr === 'MX' && $param[-1] !== '.') {
				$param .= '.';
			}
			return parent::canonicalizeRecord($zone, $subdomain, $rr, $param,
				$ttl);
		}


		/**
		 * Format record before sending to API
		 *
		 * @param Record $r
		 * @return array
		 */
		protected function formatRecord(Record $r)
		{
			$args = [
				'name' => $r['name'],
				'type' => strtoupper($r['rr']),
				'ttl'  => $r['ttl'] ?? static::DNS_TTL
			];
			switch ($args['type']) {
				case 'CAA':
					$r['parameter'] = $r->getMeta('flags') . ' ' . $r->getMeta('tag') . ' ' . $r->getMeta('data');
				case 'A':
				case 'AAAA':
				case 'CNAME':
				case 'NS':
				case 'SSHFP':
				case 'TXT':
					return $args + ['data' => $r['parameter']];
				case 'MX':
					return $args + [
						'priority' => (int)$r->getMeta('priority'),
						'data'     => rtrim($r->getMeta('data'), '.') . '.'
					];
				case 'SRV':
					return $args + [
						'name'     => $r['name'],
						'priority' => $r->getMeta('priority'),
						'data'     => $r->getMeta('weight') . ' ' . $r->getMeta('port') . ' ' . $r->getMeta('data')
					];
				default:
					fatal("Unsupported DNS RR type `%s'", $r['type']);
			}
		}

		protected function hasCnameApexRestriction(): bool
		{
			return true;
		}


	}