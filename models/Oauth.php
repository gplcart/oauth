<?php

/**
 * @package Oauth
 * @author Iurii Makukh <gplcart.software@gmail.com>
 * @copyright Copyright (c) 2017, Iurii Makukh
 * @license https://www.gnu.org/licenses/gpl.html GNU/GPLv3
 */

namespace gplcart\modules\oauth\models;

use Exception;
use gplcart\core\Handler;
use gplcart\core\helpers\Session as SessionHelper;
use gplcart\core\helpers\Url as UrlHelper;
use gplcart\core\Hook;
use gplcart\core\models\Http as HttpModel;
use gplcart\modules\oauth\helpers\Jwt as JwtHelper;
use OutOfRangeException;
use UnexpectedValueException;

/**
 * Manages basic behaviors and data related to Oauth 2.0 functionality
 */
class Oauth
{

    /**
     * JWT helper
     * @var \gplcart\modules\oauth\helpers\Jwt $jwt
     */
    protected $jwt;

    /**
     * Hook class instance
     * @var \gplcart\core\Hook $hook
     */
    protected $hook;

    /**
     * Http model class instance
     * @var \gplcart\core\models\Http $http
     */
    protected $http;

    /**
     * URL helper instance
     * @var \gplcart\core\helpers\Url $url
     */
    protected $url;

    /**
     * Session helper instance
     * @var \gplcart\core\helpers\Session $session
     */
    protected $session;

    /**
     * @param Hook $hook
     * @param HttpModel $http
     * @param JwtHelper $jwt
     * @param SessionHelper $session
     * @param UrlHelper $url
     */
    public function __construct(Hook $hook, HttpModel $http, JwtHelper $jwt, SessionHelper $session, UrlHelper $url)
    {
        $this->jwt = $jwt;
        $this->url = $url;
        $this->hook = $hook;
        $this->http = $http;
        $this->session = $session;
    }

    /**
     * Does main authorization process
     * @param array $provider
     * @param array $params
     * @return array
     */
    public function authorize(array $provider, array $params)
    {
        $result = null;
        $this->hook->attach('module.oauth.authorize.before', $provider, $params, $result, $this);

        if (isset($result)) {
            return $result;
        }

        try {
            $result = (array) $this->callHandler('authorize', $provider, $params);
        } catch (Exception $ex) {
            $result = array();
        }

        $this->hook->attach('module.oauth.authorize.after', $provider, $params, $result, $this);
        return $result;
    }

    /**
     * Returns an Oauth provider
     * @param string $id
     * @return array
     * @throws OutOfRangeException
     */
    public function getProvider($id)
    {
        $providers = $this->getProviders();

        if (empty($providers[$id])) {
            throw new OutOfRangeException('Unknown provider ID');
        }

        return $providers[$id];
    }

    /**
     * Returns an array of Oauth providers
     * @param array $options
     * @return array
     */
    public function getProviders(array $options = array())
    {
        $providers = &gplcart_static(gplcart_array_hash(array('module.oauth.providers' => $options)));

        if (isset($providers)) {
            return $providers;
        }

        $providers = array();
        $this->hook->attach('module.oauth.providers', $providers, $this);
        return $this->prepareProviders($providers, $options);
    }

    /**
     * Returns an array of URL query to redirect a user to an authorization server
     * @param array $provider
     * @param array $params
     * @return array
     * @throws OutOfRangeException
     */
    public function getQueryAuth(array $provider, array $params = array())
    {
        if (empty($provider['id'])) {
            throw new OutOfRangeException('Empty "id" key in the provider data');
        }

        $default = array(
            'response_type' => 'code',
            'redirect_uri' => $this->url->get('oauth', array(), true)
        );

        $query = array_merge($default, $params);

        if (!isset($query['state'])) {
            $query['state'] = $this->encodeState($provider['id']);
            $this->setState($query['state'], $provider['id']);
        }

        if (!isset($query['scope']) && isset($provider['scope'])) {
            $query['scope'] = $provider['scope'];
        }

        if (!isset($query['client_id']) && isset($provider['settings']['client_id'])) {
            $query['client_id'] = $provider['settings']['client_id'];
        }

        if (!empty($provider['handlers']['auth_query'])) {
            $query = $this->callHandler('auth_query', $provider, $query);
        }

        return $query;
    }

    /**
     * Returns an array of URL query to request an access token
     * @param array $provider
     * @param array $params
     * @return array
     */
    public function getQueryToken(array $provider, array $params = array())
    {
        $default = array(
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->url->get('oauth', array(), true)
        );

        $query = array_merge($default, $params);

        if (!isset($query['client_id']) && isset($provider['settings']['client_id'])) {
            $query['client_id'] = $provider['settings']['client_id'];
        }

        if (!isset($query['client_secret']) && isset($provider['settings']['client_secret'])) {
            $query['client_secret'] = $provider['settings']['client_secret'];
        }

        return $query;
    }

    /**
     * Returns the full URL to an authorization server
     * @param array $provider
     * @param array $params
     * @return string
     */
    public function getAuthUrl(array $provider, array $params = array())
    {
        if (empty($provider['url']['auth'])) {
            return '';
        }

        try {
            $query = $this->getQueryAuth($provider, $params);
            return $this->url->get($provider['url']['auth'], $query, true);
        } catch (Exception $ex) {
            return '';
        }
    }

    /**
     * Build a state code for the given provider
     * @param string $provider_id
     * @return string
     * @throws UnexpectedValueException
     */
    public function encodeState($provider_id)
    {
        $data = array(
            'id' => $provider_id,
            'url' => $this->url->get('', array(), true),
            'key' => gplcart_string_random(4), // Make resulting hash unique
        );

        $state = gplcart_string_encode(json_encode($data));

        if (empty($state)) {
            throw new UnexpectedValueException('Failed to encode the state data');
        }

        return $state;
    }

    /**
     * Decode the state code
     * @param string $state
     * @return array
     * @throws UnexpectedValueException
     * @throws OutOfRangeException
     */
    public function decodeState($state)
    {
        $decoded = gplcart_string_decode($state);

        if (empty($decoded)) {
            throw new UnexpectedValueException('Failed to decode base64 encoded string');
        }

        $data = $this->decodeJson($decoded);

        if (empty($data['id'])) {
            throw new OutOfRangeException('Empty "id" key in the decoded state data');
        }

        return $data;
    }

    /**
     * Save the state code in the session
     * @param string $state
     * @param string $provider_id
     * @return bool
     */
    public function setState($state, $provider_id)
    {
        return $this->session->set("module.oauth.state.$provider_id", $state);
    }

    /**
     * Returns a saved state data for the provider from the session
     * @param string $provider_id
     * @return string
     */
    public function getState($provider_id)
    {
        return $this->session->get("module.oauth.state.$provider_id");
    }

    /**
     * Remove a state form the session
     * @param null|null $provider_id
     * @return bool
     */
    public function unsetState($provider_id = null)
    {
        $key = 'module.oauth.state';

        if (isset($provider_id)) {
            $key .= ".$provider_id";
        }

        return $this->session->delete($key);
    }

    /**
     * Save the token data in the session
     * @param array $token
     * @param string $provider_id
     */
    public function setToken(array $token, $provider_id)
    {
        if (isset($token['expires_in'])) {
            $token['expires'] = GC_TIME + $token['expires_in'];
        }

        $this->session->set("module.oauth.token.$provider_id", $token);
    }

    /**
     * Whether a token for the given provider is valid
     * @param string $provider_id
     * @return bool
     */
    public function isValidToken($provider_id)
    {
        $token = $this->getToken($provider_id);

        return isset($token['access_token']) && isset($token['expires']) && GC_TIME < $token['expires'];
    }

    /**
     * Whether the state for the provider is valid
     * @param string $state
     * @param string $provider_id
     * @return bool
     */
    public function isValidState($state, $provider_id)
    {
        return gplcart_string_equals($state, $this->getState($provider_id));
    }

    /**
     * Returns a saved token data for the provider from the session
     * @param string $provider_id
     * @return array
     */
    public function getToken($provider_id)
    {
        return $this->session->get("oauth.token.$provider_id");
    }

    /**
     * Performs an HTTP request to get an access token
     * @param array $provider
     * @param array $query
     * @return array
     * @throws OutOfRangeException
     */
    public function requestToken(array $provider, array $query)
    {
        $result = null;
        $this->hook->attach('module.oauth.request.token.before', $provider, $query, $result, $this);

        if (isset($result)) {
            return (array) $result;
        }

        if (empty($provider['url']['token'])) {
            throw new OutOfRangeException('Token URL is empty in the provider data');
        }

        $post = array(
            'data' => $query,
            'method' => 'POST'
        );

        $response = $this->http->request($provider['url']['token'], $post);
        $result = $this->decodeJson($response['data']);

        $this->hook->attach('module.oauth.request.token.after', $provider, $query, $result, $this);
        return $result;
    }

    /**
     * Returns an array of requested token data
     * @param array $provider
     * @param array $params
     * @return array
     * @throws OutOfRangeException
     */
    public function exchangeToken(array $provider, array $params = array())
    {
        if (empty($provider['id'])) {
            throw new OutOfRangeException('Empty "id" key in the provider data');
        }

        if ($this->isValidToken($provider['id'])) {
            return $this->getToken($provider['id']);
        }

        if (!empty($provider['handlers']['token'])) {
            $token = $this->callHandler('token', $provider, $params);
        } else {
            $token = $this->requestToken($provider, $params);
        }

        $this->setToken($token, $provider['id']);
        return $token;
    }

    /**
     * Returns an array of requested token for "server-to-server" authorization
     * @param array $provider
     * @param array $jwt
     * @return mixed
     * @throws OutOfRangeException
     */
    public function exchangeTokenServer($provider, $jwt)
    {
        if (empty($provider['id'])) {
            throw new OutOfRangeException('Empty "id" key in the provider data');
        }

        if ($this->isValidToken($provider['id'])) {
            return $this->getToken($provider['id']);
        }

        if (!isset($jwt['token_url']) && isset($provider['url']['token'])) {
            $jwt['token_url'] = $provider['url']['token'];
        }

        if (!isset($jwt['scope']) && isset($provider['scope'])) {
            $jwt['scope'] = $provider['scope'];
        }

        $request = array(
            'assertion' => $this->encodeJwt($jwt, $provider),
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        );

        $token = $this->requestToken($provider, $request);
        $this->setToken($token, $provider['id']);
        return $token;
    }

    /**
     * Encode JWT token data
     * @param array $data
     * @param array $provider
     * @return string
     * @throws OutOfRangeException
     */
    public function encodeJwt(array $data, array $provider)
    {
        if (!isset($provider['settings']['client_secret'])) {
            throw new OutOfRangeException('Key "client_secret" is not set in the provider settings');
        }

        $data += array('lifetime' => 3600);
        return $this->jwt->encode($data, $provider['settings']['client_secret']);
    }

    /**
     * Call a provider handler
     * @param string $handler_name
     * @param array $provider
     * @param array $params
     * @return mixed
     */
    public function callHandler($handler_name, array $provider, array $params)
    {
        $providers = $this->getProviders();
        return Handler::call($providers, $provider['id'], $handler_name, array($params, $provider, $this));
    }

    /**
     * Prepare an array of Oauth providers
     * @param array $providers
     * @param array $options
     * @return array
     */
    protected function prepareProviders(array $providers, array $options)
    {
        foreach ($providers as $provider_id => &$provider) {

            $provider['id'] = $provider_id;

            if (isset($provider['scope']) && is_array($provider['scope'])) {
                $provider['scope'] = implode(' ', $provider['scope']);
            }

            if (isset($options['type'])
                && isset($provider['type'])
                && $options['type'] !== $provider['type']) {
                unset($providers[$provider_id]);
                continue;
            }

            if (isset($options['status'])
                && isset($provider['status'])
                && $options['status'] != $provider['status']) {
                unset($providers[$provider_id]);
            }
        }

        return $providers;
    }

    /**
     * Decode JSON string
     * @param string $json
     * @return array
     * @throws UnexpectedValueException
     */
    protected function decodeJson($json)
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            throw new UnexpectedValueException('Failed to decode JSON');
        }

        return $decoded;
    }

}
