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
use LogicException;
use OutOfRangeException;
use RuntimeException;
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
    protected $algs;

    /**
     * Jwt constructor
     */
    public function __construct()
    {
        $this->algs = array(
            'HS256' => array('SHA256', array($this, 'signHmac'), array($this, 'verifyHmac')),
            'HS512' => array('SHA512', array($this, 'signHmac'), array($this, 'verifyHmac'))
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
     * Sets an algorithm
     * @param string $name
     * @param string $hash_method
     * @param callable $signer
     * @param callable $verifier
     * @return $this
     */
    public function setAlg($name, $hash_method, callable $signer, callable $verifier)
    {
        $this->algs[strtoupper($name)] = array(strtoupper($hash_method), $signer, $verifier);
        return $this;
    }

    /**
     * Returns an array of supported algorithms
     * @return array
     */
    public function getAlgs()
    {
        return $this->algs;
    }

    /**
     * Decodes a JWT string into a PHP object
     * @param string $jwt
     * @param string $key
     * @param array $allowed_algs
     * @return object
     * @throws RuntimeException
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
            throw new UnexpectedValueException('Wrong number of segments');
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
            throw new UnexpectedValueException('Empty algorithm');
        }

        if (empty($this->algs[$header->alg])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }

        if (!empty($allowed_algs) && !in_array($header->alg, $allowed_algs)) {
            throw new RuntimeException('Algorithm not allowed');
        }

        if (!$this->verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new RuntimeException('Signature verification failed');
        }

        if (isset($payload->nbf) && $payload->nbf > ($this->timestamp + $this->leeway)) {
            throw new RuntimeException('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf));
        }

        if (isset($payload->iat) && $payload->iat > ($this->timestamp + $this->leeway)) {
            throw new RuntimeException('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat));
        }

        if (isset($payload->exp) && ($this->timestamp - $this->leeway) >= $payload->exp) {
            throw new RuntimeException('Expired token');
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string
     * @param object|array $payload
     * @param string $key
     * @param string $alg
     * @param null|string $key_id
     * @param array $head
     * @return string
     */
    public function encode($payload, $key, $alg = 'HS256', $key_id = null, array $head = array())
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);

        if (isset($key_id)) {
            $header['kid'] = $key_id;
        }

        if (!empty($head)) {
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
     * @param string $data
     * @param string|resource $key
     * @param string $alg
     * @return string
     * @throws OutOfRangeException
     * @throws RuntimeException
     * @throws LogicException
     */
    public function sign($data, $key, $alg = 'HS256')
    {
        if (empty($this->algs[$alg])) {
            throw new OutOfRangeException('Algorithm not supported');
        }

        list($func_alg, $function) = $this->algs[$alg];

        if (is_callable($function)) {
            return $function($data, $key, $func_alg);
        }

        throw new LogicException('Unknown signer');
    }

    /**
     * Generate signature using HMAC method
     * @param string $data
     * @param string $key
     * @param string $alg
     * @return string
     * @throws RuntimeException
     */
    protected function signHmac($data, $key, $alg)
    {
        $hash = hash_hmac($alg, $data, $key, true);

        if (empty($hash)) {
            throw new RuntimeException('Unable to sign data using HMAC method');
        }

        return $hash;
    }

    /**
     * Verify a signature with the message, key and method
     * @param string $data
     * @param string $hash
     * @param string|resource $key
     * @param string $alg
     * @return bool
     * @throws OutOfRangeException
     * @throws LogicException
     */
    public function verify($data, $hash, $key, $alg)
    {
        if (empty($this->algs[$alg])) {
            throw new OutOfRangeException('Algorithm not supported');
        }

        $func_alg = $this->algs[$alg][0];
        $function = $this->algs[$alg][2];

        if (is_callable($function)) {
            return $function($data, $hash, $key, $func_alg);
        }

        throw new LogicException('Unsupported verifier');
    }

    /**
     * Verify signature using HMAC method
     * @param string $data
     * @param string $hash
     * @param string $key
     * @param string $alg
     * @return bool
     * @throws RuntimeException
     */
    protected function verifyHmac($data, $hash, $key, $alg)
    {
        $hashed = hash_hmac($alg, $data, $key, true);

        if (empty($hashed)) {
            throw new RuntimeException('Unable to hash data for verifying using HMAC method');
        }

        return $this->hashEquals($hash, $hashed);
    }

    /**
     * Compares two hashed strings
     * @param string $str1
     * @param string $str2
     * @return boolean
     */
    protected function hashEquals($str1, $str2)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($str1, $str2);
        }

        if (strlen($str1) != strlen($str2)) {
            return false;
        }

        $res = $str1 ^ $str2;
        $ret = 0;

        for ($i = strlen($res) - 1; $i >= 0; $i--) {
            $ret |= ord($res[$i]);
        }

        return !$ret;
    }

    /**
     * Decode a JSON string into a PHP object
     * @param string $input
     * @return object
     * @throws RuntimeException
     */
    protected function jsonDecode($input)
    {
        $object = json_decode($input);

        if (json_last_error() === JSON_ERROR_NONE) {
            return $object;
        }

        throw new RuntimeException('Failed to decode JSON string');
    }

    /**
     * Encode a PHP object into a JSON string
     * @param object|array $input
     * @return string
     * @throws RuntimeException
     */
    protected function jsonEncode($input)
    {
        $json = json_encode($input);

        if (json_last_error() === JSON_ERROR_NONE) {
            return $json;
        }

        throw new RuntimeException('Failed to encode JSON string');
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