# refCaptcha for CI4
Hook class for CodeIgniter ver. 4 that implements HTTP_REFERER verification and displays a simple captcha for “direct” visits.

Using this hook can help cut off bot traffic on your site that Yandex.Metrica reports under the "Direct visits" source.

You can configure the following class constants:
```php
COOKIE_NAME
COOKIE_DOMAIN
```
These values are used for a cookie so that visitors who have already passed the captcha won’t be shown it again.

Configure the HTML template in the `showCaptchaForm()` method: Specify your site name in the &lt;title&gt; tag and in the &lt;div class="project-title"&gt; tag.

The hook class must be used in `config/Event.php` via an event with the `pre_system` type.

```php
Events::on('pre_system', static function () {
    if (ENVIRONMENT !== 'development') {
        // Your code...

        $hook = new DirectAccessHook();
        $hook->checkAccess();
    }
});
```
