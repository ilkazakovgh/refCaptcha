# refCaptcha
Hook class for CodeIgniter that implements HTTP_REFERER verification and displays a simple captcha for “direct” visits

You can configure the following class constants:
```php
COOKIE_NAME
COOKIE_DOMAIN
```
These values are used for a cookie so that visitors who have already passed the captcha won’t be shown it again.

Hook processing must be enabled in config/config.php

```php
$config['enable_hooks'] = TRUE;
```
