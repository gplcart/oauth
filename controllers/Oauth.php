<?php

/**
 * @package Oauth
 * @author Iurii Makukh <gplcart.software@gmail.com>
 * @copyright Copyright (c) 2018, Iurii Makukh <gplcart.software@gmail.com>
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html GPL-3.0-or-later
 */

namespace gplcart\modules\oauth\controllers;

use Exception;
use gplcart\core\controllers\frontend\Controller as FrontendController;
use gplcart\modules\oauth\models\Oauth as ModuleOauthModel;
use InvalidArgumentException;
use OutOfRangeException;

/**
 * Handles incoming requests and outputs data related to Oauth functionality
 */
class Oauth extends FrontendController
{

    /**
     * Oauth model instance
     * @var \gplcart\modules\oauth\models\Oauth $oauth
     */
    protected $oauth;

    /**
     * The current Oauth provider
     * @var array
     */
    protected $data_provider;

    /**
     * A code received from a provider
     * @var string
     */
    protected $data_code;

    /**
     * A state hash received from a provider
     * @var string
     */
    protected $data_state;

    /**
     * An array of data parsed from a received state
     * @var array
     */
    protected $data_decoded_state;

    /**
     * An array of token data
     * @var array
     */
    protected $data_token;

    /**
     * A processed authorization result
     * @var mixed
     */
    protected $data_result;

    /**
     * @param ModuleOauthModel $oauth
     */
    public function __construct(ModuleOauthModel $oauth)
    {
        parent::__construct();

        $this->oauth = $oauth;
    }

    /**
     * Callback for Oauth returning URL
     */
    public function callbackOauth()
    {
        try {
            $this->setResponseOauth();
            $this->setTokenOauth();
            $this->setResultOauth();
            $this->redirectOauth();
        } catch (Exception $ex) {
            trigger_error($ex->getMessage());
            $this->outputHttpStatus(403);
        }

    }

    /**
     * Set and validates received data from Oauth provider
     * @throws InvalidArgumentException
     */
    protected function setResponseOauth()
    {
        $this->data_code = $this->getQuery('code', '');
        $this->data_state = $this->getQuery('state', '');
        $this->data_decoded_state = $this->oauth->decodeState($this->data_state);
        $this->data_provider = $this->oauth->getProvider($this->data_decoded_state['id']);

        if (!$this->oauth->isValidState($this->data_state, $this->data_decoded_state['id'])) {
            throw new InvalidArgumentException('Invalid state code');
        }

        $domain = parse_url($this->data_decoded_state['url'], PHP_URL_HOST);

        if (empty($domain)) {
            throw new InvalidArgumentException('Unknown redirect domain');
        }

        $store = $this->store->get($domain);

        if (empty($store['status'])) {
            throw new InvalidArgumentException('Invalid redirect domain');
        }
    }

    /**
     * Does final redirect after authorization
     */
    protected function redirectOauth()
    {
        if (isset($this->data_result['message'])) {
            $this->setMessage($this->data_result['message'], $this->data_result['severity'], true);
        }

        if (isset($this->data_result['redirect'])) {
            $this->redirect($this->data_result['redirect']);
        }

        $this->redirect($this->data_decoded_state['url']);
    }

    /**
     * Set received token data
     * @throws OutOfRangeException
     */
    protected function setTokenOauth()
    {
        $query = $this->oauth->getQueryToken($this->data_provider, array('code' => $this->data_code));
        $this->data_token = $this->oauth->exchangeToken($this->data_provider, $query);
    }

    /**
     * Set authorization result
     */
    protected function setResultOauth()
    {
        if (empty($this->data_token['access_token'])) {
            throw new OutOfRangeException('Empty Oauth access token');
        }

        $this->data_result = $this->oauth->authorize($this->data_provider, array('token' => $this->data_token));

        $this->data_result += array(
            'severity' => 'warning',
            'message' => $this->text('An error occurred')
        );
    }

}
