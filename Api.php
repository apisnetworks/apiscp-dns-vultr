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

use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Response;

class Api {
	protected const VULTR_ENDPOINT = 'https://api.vultr.com/v1/';
	/**
	 * @var \GuzzleHttp\Client
	 */
	protected $client;
	/**
	 * @var string
	 */
	protected $key;

	/**
	 * @var Response
	 */
	protected $lastResponse;

	/**
	 * Api constructor.
	 *
	 * @param string $key API key
	 */
	public function __construct(string $key)
	{
		$this->key = $key;
		$this->client = new \GuzzleHttp\Client([
			'base_uri' => static::VULTR_ENDPOINT,
		]);
	}

	public function do(string $method, string $endpoint, array $params = []): array
	{
		$method = strtoupper($method);
		if (!\in_array($method, ['GET', 'POST'])) {
			error("Unknown method `%s'", $method);
			return [];
		}
		if ($endpoint[0] === '/') {
			warn("Stripping `/' from endpoint `%s'", $endpoint);
			$endpoint = ltrim($endpoint, '/');
		}
		$paramKey = $method === 'POST' ? 'form_params' : 'query';
		try {
			$this->lastResponse = $this->client->request($method, $endpoint, [
				'headers' => [
					'User-Agent' => PANEL_BRAND . " " . APNSCP_VERSION,
					'API-Key' => $this->key,
					'Accept' => 'application/json'
				],
				$paramKey => $params
			]);
		} catch (ServerException $e) {
			if ($e->getResponse()->getStatusCode() === 503) {
				// 2 req/s is stupid.
				usleep(500000);
				return $this->do($method, $endpoint, $params);
			}
			throw $e;
		}
		return \json_decode($this->lastResponse->getBody()->getContents(), true) ?? [];
	}

	public function getResponse(): ?Response
	{
		return $this->lastResponse;
	}
}