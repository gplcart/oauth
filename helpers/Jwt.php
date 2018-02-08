<?php

/**
 * @package Oauth
 * @author Iurii Makukh <gplcart.software@gmail.com>
 * @copyright Copyright (c) 2017, Iurii Makukh
 * @license https://www.gnu.org/licenses/gpl.html GNU/GPLv3
 */

namespace gplcart\modules\oauth\helpers;

use DateTime;
use InvalidArgumentException;
use LengthException;
use OutOfRangeException;
use UnexpectedValueException;

/**
 * JSON Web Token implementation
 */
class Jwt
{

    /**
     * Extra leeway time when checking nbf, iat or expiration times
     */
    protected $leeway = 0;

    /**
     * The current time
     */
    protected $timestamp;

    /**
     * An array of supported algorithms
     * @var array
     */
    protected $algorithms;

    /**
     * Jwt constructor
     */
    public function __construct()
    {
        $this->algorithms = array(
            'HS256' => array('hash_hmac', 'SHA256'),
            'HS512' => array('hash_hmac', 'SHA512'),
            'HS384' => array('hash_hmac', 'SHA384'),
            'RS256' => array('openssl', 'SHA256'),
            'RS384' => array('openssl', 'SHA384'),
            'RS512' => array('openssl', 'SHA512'),
        );
    }

    /**
     * Sets leeway time
     * @param int $time
     * @return $this
     */
    public function setLeeway($time)
    {
        $this->leeway = $time;
        return $this;
    }

    /**
     * Sets the current timestamp
     * @param $timestamp
     * @return $this
     */
    public function setTimestamp($timestamp)
    {
        $this->timestamp = $timestamp;
        return $this;
    }

    /**
     * Sets a supported algorithm
     * @param string $name
     * @param string $function
     * @param string $hash_method
     * @return $this
     */
    public function setAlgorithm($name, $function, $hash_method)
    {
        $this->algorithms[strtoupper($name)] = array($function, strtoupper($hash_method));
        return $this;
    }

    /**
     * Returns an array of supported algorithms
     * @return array
     */
    public function getAlgorithms()
    {
        return $this->algorithms;
    }

    /**
     * Decodes a JWT string into a PHP object
     * @param string $jwt
     * @param mixed $key
     * @param array $allowed_algs
     * @return object
     * @throws LengthException
     * @throws OutOfRangeException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    public function decode($jwt, $key, array $allowed_algs = array())
    {
        if (!isset($this->timestamp)) {
            $this->timestamp = time();
        }

        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }

        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            throw new LengthException('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        $header = $this->jsonDecode($this->decodeBase64($headb64));

        if (!isset($header)) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        $payload = $this->jsonDecode($this->decodeBase64($bodyb64));

        if (!isset($payload)) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        $sig = $this->decodeBase64($cryptob64);

        if ($sig === false) {
            throw new UnexpectedValueException('Invalid signature encoding');
        }

        if (empty($header->alg)) {
            throw new OutOfRangeException('Empty algorithm');
        }

        if (empty($this->algorithms[$header->alg])) {
            throw new OutOfRangeException('Algorithm not supported');
        }

        if (!in_array($header->alg, $allowed_algs)) {
            throw new OutOfRangeException('Algorithm not allowed');
        }

        if (is_array($key) || $key instanceof \ArrayAccess) {

            if (!isset($header->kid)) {
                throw new OutOfRangeException('"kid" empty, unable to lookup correct key');
            }

            if (!isset($key[$header->kid])) {
                throw new OutOfRangeException('"kid" invalid, unable to lookup correct key');
            }

            $key = $key[$header->kid];
        }

        if (!$this->verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new UnexpectedValueException('Signature verification failed');
        }

        if (isset($payload->nbf) && $payload->nbf > ($this->timestamp + $this->leeway)) {
            throw new UnexpectedValueException('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf));
        }

        if (isset($payload->iat) && $payload->iat > ($this->timestamp + $this->leeway)) {
            throw new UnexpectedValueException('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat));
        }

        if (isset($payload->exp) && ($this->timestamp - $this->leeway) >= $payload->exp) {
            throw new UnexpectedValueException('Expired token');
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string
     * @param object|array $payload
     * @param string $key
     * @param string $alg
     * @param mixed $key_id
     * @param array $head
     * @return string
     */
    public function encode($payload, $key, $alg = 'HS256', $key_id = null, $head = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);

        if (isset($key_id)) {
            $header['kid'] = $key_id;
        }

        if (isset($head) && is_array($head)) {
            $header = array_merge($head, $header);
        }

        $segments = array();
        $segments[] = $this->encodeBase64($this->jsonEncode($header));
        $segments[] = $this->encodeBase64($this->jsonEncode($payload));

        $signing_input = implode('.', $segments);

        $signature = $this->sign($signing_input, $key, $alg);
        $segments[] = $this->encodeBase64($signature);

        return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm
     * @param string $msg
     * @param string|resource $key
     * @param string $alg
     * @return string
     * @throws OutOfRangeException
     * @throws UnexpectedValueException
     */
    public function sign($msg, $key, $alg = 'HS256')
    {
        if (empty($this->algorithms[$alg])) {
            throw new OutOfRangeException('Algorithm not supported');
        }

        list($function, $algorithm) = $this->algorithms[$alg];

        if ($function === 'hash_hmac') {
            return hash_hmac($algorithm, $msg, $key, true);
        }

        if ($function === 'openssl') {

            $signature = '';
            $success = openssl_sign($msg, $signature, $key, $algorithm);

            if ($success) {
                return $signature;
            }

            throw new UnexpectedValueException('OpenSSL unable to sign data');
        }

        throw new UnexpectedValueException('Unknown signer');
    }

    /**
     * Verify a signature with the message, key and method
     * @param string $msg
     * @param string $signature
     * @param string|resource $key
     * @param string $alg
     * @return bool
     * @throws OutOfRangeException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    public function verify($msg, $signature, $key, $alg)
    {
        if (empty($this->algorithms[$alg])) {
            throw new OutOfRangeException('Algorithm not supported');
        }

        list($function, $algorithm) = $this->algorithms[$alg];

        if ($function === 'openssl') {

            $success = openssl_verify($msg, $signature, $key, $algorithm);

            if ($success === 1) {
                return true;
            }

            if ($success === 0) {
                return false;
            }

            throw new InvalidArgumentException('OpenSSL error: ' . openssl_error_string());
        }

        if ($function === 'hash_hmac') {
            $hash = hash_hmac($algorithm, $msg, $key, true);
            return gplcart_string_equals($signature, $hash);
        }

        throw new UnexpectedValueException('Unknown verifier');
    }

    /**
     * Decode a JSON string into a PHP object
     * @param string $input
     * @return object
     * @throws InvalidArgumentException
     */
    public function jsonDecode($input)
    {
        $object = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if (json_last_error() === JSON_ERROR_NONE) {
            return $object;
        }

        throw new InvalidArgumentException('Failed to decode JSON string');
    }

    /**
     * Encode a PHP object into a JSON string
     * @param object|array $input
     * @return string
     * @throws InvalidArgumentException
     */
    public function jsonEncode($input)
    {
        $json = json_encode($input);

        if (json_last_error() === JSON_ERROR_NONE) {
            return $json;
        }

        throw new InvalidArgumentException('Failed to encode JSON string');
    }

    /**
     * Decodes data encoded with MIME base64
     * @param string $string
     * @return string
     */
    protected function decodeBase64($string)
    {
        $remainder = strlen($string) % 4;

        if ($remainder) {
            $padlen = 4 - $remainder;
            $string .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($string, '-_', '+/'));
    }

    /**
     * Safe URL base64 encoding
     * @param string $string
     * @return string
     */
    protected function encodeBase64($string)
    {
        return str_replace('=', '', strtr(base64_encode($string), '+/', '-_'));
    }
}