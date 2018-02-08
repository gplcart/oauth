[![Build Status](https://scrutinizer-ci.com/g/gplcart/oauth/badges/build.png?b=master)](https://scrutinizer-ci.com/g/gplcart/oauth/build-status/master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/gplcart/oauth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/gplcart/oauth/?branch=master)

Oauth is a [GPL Cart](https://github.com/gplcart/gplcart) module that implements OAuth 2.0 standard for use with GPLCart sites.
Note: it does nothing by itself. You should install it only if other modules depend on it.

**Installation**

1. Download and extract to `system/modules` manually or using composer `composer require gplcart/oauth`. IMPORTANT: If you downloaded the module manually, be sure that the name of extracted module folder doesn't contain a branch/version suffix, e.g `-master`. Rename if needed.
2. Go to `admin/module/list` end enable the module