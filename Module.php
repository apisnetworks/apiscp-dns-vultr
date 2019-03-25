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
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Dns\Record;

	class Module extends \Dns_Module implements ProviderInterface
	{
		use \NamespaceUtilitiesTrait;

		const DNS_TTL = 1800;

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
				$api->do('POST', 'dns/create_record', ['domain' => $zone] + $this->formatRecord($record));
				$this->addCache($record);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				if ($e->getResponse()->getStatusCode() === 412 &&
					false !== strpos($e->getResponse()->getBody()->getContents(), 'Duplicate records not allowed')) {
					return warn("Duplicate record for `%s' type %s %s skipped", $fqdn, $rr, $param);
				}

				return error("Failed to create record `%s' type %s: %s", $fqdn, $rr, $e->getMessage());
			}

			return $api->getResponse()->getStatusCode() === 200;
		}

		/**
		 * Remove a DNS record
		 *
		 * @param string      $zone
		 * @param string      $subdomain
		 * @param string      $rr
		 * @param string|null $param
		 * @return bool
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = null): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			$api = $this->makeApi();

			$id = $this->getRecordId($r = new Record($zone,
				['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]));
			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Record `%s' (rr: `%s', param: `%s')  does not exist", $fqdn, $rr, $param);
			}

			try {
				$api->do('POST', 'dns/delete_record', ['domain' => $zone, 'RECORDID' => $id]);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');

				return error("Failed to delete record `%s' type %s", $fqdn, $rr);
			}
			array_forget($this->zoneCache[$r->getZone()], $this->getCacheKey($r));

			return $api->getResponse()->getStatusCode() === 200;
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
				$api->do('POST', 'dns/create_domain', [
					'domain'   => $domain,
					'serverip' => $ip
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
				$api->do('POST', "dns/delete_domain", ['domain' => $domain]);
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
		protected function zoneAxfr($domain): ?string
		{
			$client = $this->makeApi();
			try {
				$client->do('GET', "dns/soa_info", ['domain' => $domain]);
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
				$records = $client->do('GET', 'dns/records', ['domain' => $domain]);
			} catch (ClientException $e) {
				error("Failed to transfer DNS records from Vultr - try again later");

				return null;
			}

			$this->zoneCache[$domain] = [];
			foreach ($records as $r) {
				switch ($r['type']) {
					case 'SRV':
					case 'MX':
						$parameter = $r['priority'] . " " . $r['data'];
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
							'id' => $r['RECORDID']
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

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, Record $old, Record $new): bool
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
				$api->do('POST', 'dns/update_record',
					['domain' => $zone, 'RECORDID' => $id] + $this->formatRecord($new));
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
			array_forget($this->zoneCache[$old->getZone()], $this->getCacheKey($old));
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
			if (strtoupper($rr) === 'SSHFP') {
				$param = strtolower($param);
			}
			return parent::canonicalizeRecord($zone, $subdomain, $rr, $param,
				$ttl);
		}


		protected function formatRecord(Record $r)
		{
			$args = [
				'type' => strtoupper($r['rr']),
				'ttl'  => $r['ttl'] ?? static::DNS_TTL
			];
			switch ($args['type']) {
				case 'A':
				case 'AAAA':
				case 'CAA':
				case 'CNAME':
				case 'NS':
				case 'SSHFP':
				case 'TXT':
					return $args + ['name' => $r['name'], 'data' => $r['parameter']];
				case 'MX':
					return $args + ['name'     => $r['name'],
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