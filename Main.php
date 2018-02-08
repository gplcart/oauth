<?php

/**
 * @package Oauth
 * @author Iurii Makukh <gplcart.software@gmail.com>
 * @copyright Copyright (c) 2018, Iurii Makukh <gplcart.software@gmail.com>
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html GPL-3.0-or-later
 */

namespace gplcart\modules\oauth;

use gplcart\core\Container;

/**
 * Main class for Oauth module
 */
class Main
{

    /**
     * Implements hook "route.list"
     * @param array $routes
     */
    public function hookRouteList(array &$routes)
    {
        $routes['oauth'] = array(
            'internal' => true,
            'handlers' => array(
                'controller' => array('gplcart\\modules\\oauth\\controllers\\Oauth', 'callbackOauth')
            )
        );
    }

    /**
     * Returns a provider
     * @param string $id
     * @return array
     */
    public function getProvider($id)
    {
        return $this->getModel()->getProvider($id);
    }

    /**
     * Returns an array of providers
     * @param array $options
     * @return array
     */
    public function getProviders(array $options = array())
    {
        return $this->getModel()->getProviders($options);
    }

    /**
     * Does main authorization process
     * @param array $provider
     * @param array $options
     * @return mixed
     */
    public function authorize(array $provider, array $options)
    {
        return $this->getModel()->authorize($provider, $options);
    }

    /**
     * Returns the Oauth model instance
     * @return \gplcart\modules\oauth\models\Oauth
     */
    public function getModel()
    {
        /** @var \gplcart\modules\oauth\models\Oauth $instance */
        $instance = Container::get('gplcart\\modules\\oauth\\models\\Oauth');
        return $instance;
    }
}
