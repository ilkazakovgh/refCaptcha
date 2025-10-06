<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * DirectAccessHook
 *
 * A CodeIgniter pre_system hook that mitigates suspicious direct access by requiring
 * users without an allowed referrer/domain to solve a simple math CAPTCHA.
 * Because pre_system runs before the CI core is fully bootstrapped, this hook
 * works directly with PHP superglobals and plain PHP sessions/cookies.
 */
class DirectAccessHook {
    /**
     * Name of the cookie that indicates a user has successfully passed the CAPTCHA.
     * If this cookie is present, the hook skips further checks for that user.
     */
    private const COOKIE_NAME = 'client_uid_form_cf_main';

    /**
     * The cookie domain attribute used for the allow cookie.
     * Set this to your base domain to share the cookie across subdomains
     * (for example, set to "example.com" to cover "www.example.com" and "api.example.com").
     */
    private const COOKIE_DOMAIN = 'domain.com';

    /**
     * Constructor.
     * Note: In the pre_system hook you cannot use get_instance(),
     * so the hook uses PHP superglobals directly.
     */
    public function __construct() {
        // In the pre_system hook get_instance() is not available.
        // Therefore we work directly with superglobal variables.
    }

    /**
     * Main entry point for the hook. Performs direct-access checks and CAPTCHA flow.
     *
     * Flow:
     * - If the allow cookie is present, do nothing.
     * - Start PHP session manually (CI session is not available in pre_system).
     * - If it is a direct access (no Referer), resolve client IP to a domain and compare against the whitelist.
     * - If the domain is not allowed, render the CAPTCHA form and terminate further execution.
     * - If a POST with captcha_answer is present, validate it and set the allow cookie; otherwise re-render the form with an error.
     *
     * @return void
     */
    public function checkAccess() {
        if (isset($_COOKIE[self::COOKIE_NAME])) {
            return;
        }

        // Initialize PHP session manually because CI sessions are not available yet
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        // Check for direct access
        if ($this->isDirectAccess()) {
            $ip = $this->getClientIp();
            $domain = $this->reverseLookup($ip);

            // If the domain is not allowed, show the CAPTCHA form
            if (!$this->isAllowedDomain($domain)) {
                $this->showCaptchaForm();
                exit;
            }
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['captcha_answer'])) {
            if ($this->checkCaptcha($_POST['captcha_answer'])) {
                setcookie(self::COOKIE_NAME, uniqid(), time()+43200, '/', self::COOKIE_DOMAIN, true);
            } else {
                $this->showCaptchaForm('Неверный ответ. Попробуйте ещё раз.');
                exit;
            }
        }
    }

    /**
     * Determine whether the current request is a direct access (no HTTP Referer).
     *
     * @return bool True if HTTP_REFERER is empty; false otherwise.
     */
    protected function isDirectAccess(): bool
    {
        return empty($_SERVER['HTTP_REFERER']);
    }

    /**
     * Get the client's IP address from common headers (HTTP_CLIENT_IP, HTTP_X_FORWARDED_FOR) or REMOTE_ADDR.
     * Note: HTTP_X_FORWARDED_FOR may contain a comma-separated list; this method returns it as is.
     *
     * @return string Client IP string as provided by the server variables.
     */
    protected function getClientIp(): string
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }

    /**
     * Reverse DNS lookup for an IP address.
     *
     * @param string $ip IPv4/IPv6 address.
     * @return string|false Resolved domain name or false if not resolved.
     */
    protected function reverseLookup(string $ip) {
        $domain = gethostbyaddr($ip);
        return ($domain == $ip) ? false : $domain;
    }

    /**
     * Check if the resolved domain is in the allowed list.
     *
     * @param string|false $domain Domain resolved from reverse DNS or false.
     * @return bool True if the domain is allowed; otherwise false.
     */
    protected function isAllowedDomain($domain): bool
    {
        if (empty($domain)) {
            return false;
        }

        $allowedDomains = ['yandex.com', 'google.com'];

        foreach ($allowedDomains as $allowed) {
            if (strpos($domain, $allowed) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a simple math expression and store the correct answer in the session.
     *
     * @return string Readable math expression (e.g., "3 + 5").
     */
    protected function generateCaptcha(): string
    {
        $num1 = rand(1, 10);
        $num2 = rand(1, 10);
        $operators = ['+', '-', '*'];
        $operator = $operators[array_rand($operators)];

        $_SESSION['captcha_answer'] = $this->calculateCaptcha($num1, $num2, $operator);

        return "$num1 $operator $num2";
    }

    /**
     * Calculate the answer for a generated math expression.
     *
     * @param int $num1 First operand.
     * @param int $num2 Second operand.
     * @param string $operator One of '+', '-', '*'.
     * @return int The calculated result.
     */
    protected function calculateCaptcha(int $num1, int $num2, string $operator) {
        switch ($operator) {
            case '+': return $num1 + $num2;
            case '-': return $num1 - $num2;
            case '*': return $num1 * $num2;
            default: return 0;
        }
    }

    /**
     * Validate the provided answer against the stored CAPTCHA solution.
     *
     * @param mixed $answer User-provided answer (string or number).
     * @return bool True if the answer matches; otherwise false.
     */
    protected function checkCaptcha($answer): bool
    {
        return isset($_SESSION['captcha_answer']) && is_numeric($answer)
            && intval($_SESSION['captcha_answer']) == intval($answer);
    }

    /**
     * Render the CAPTCHA HTML form and terminate the request.
     *
     * @param string|null $error Optional error message to display above the form.
     * @return void
     */
    protected function showCaptchaForm(string $error = null) {
        $captchaQuestion = $this->generateCaptcha();
        ?>
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <title>МинЖКХ.ру - хотим убедиться, что вы не робот</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }
                body {
                    font-family: Arial, sans-serif;
                    background-color: #eee;
                    color: #000;
                    line-height: 1.6;
                    padding: 20px;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 30px;
                    background-color: #fff;
                    border-radius: 10px;
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #1faabe;
                    font-size: 28px;
                    margin-bottom: 20px;
                    text-align: center;
                }
                .project-title {
                    color: #1faabe;
                    font-size: 32px;
                    font-weight: bold;
                    text-align: center;
                    margin-bottom: 30px;
                }
                p {
                    font-size: 18px;
                    margin-bottom: 20px;
                    text-align: center;
                }
                .captcha-container {
                    background-color: #f9f9f9;
                    padding: 25px;
                    border-radius: 8px;
                    margin-top: 20px;
                }
                .error {
                    color: #ff3333;
                    font-size: 16px;
                    text-align: center;
                    margin-bottom: 15px;
                    font-weight: bold;
                }
                form {
                    display: flex;
                    flex-direction: column;
                    gap: 20px;
                }
                .form-group {
                    display: flex;
                    flex-direction: column;
                }
                label {
                    font-size: 18px;
                    margin-bottom: 8px;
                    font-weight: bold;
                }
                input[type="text"] {
                    padding: 15px;
                    font-size: 18px;
                    border: 2px solid #ddd;
                    border-radius: 6px;
                    width: 100%;
                    transition: border-color 0.3s;
                }
                input[type="text"]:focus {
                    border-color: #32c8de;
                    outline: none;
                }
                button {
                    background-color: #32c8de;
                    color: white;
                    border: none;
                    padding: 15px;
                    font-size: 18px;
                    border-radius: 6px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                    font-weight: bold;
                }
                button:hover {
                    background-color: #1faabe;
                }
                @media (max-width: 480px) {
                    .container {
                        padding: 20px;
                    }
                    h1 {
                        font-size: 24px;
                    }
                    .project-title {
                        font-size: 28px;
                    }
                    p, label {
                        font-size: 16px;
                    }
                    input[type="text"], button {
                        padding: 12px;
                        font-size: 16px;
                    }
                }
            </style>
        </head>
        <body>
        <div class="container">
            <div class="project-title">Название вашего приложения</div>
            <h1>Хотим убедиться, что вы не робот</h1>
            <p>Пожалуйста, решите пример, чтобы продолжить:</p>

            <?php if ($error): ?>
                <p class="error"><?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>

            <div class="captcha-container">
                <form method="POST">
                    <div class="form-group">
                        <label for="captcha_answer">Сколько будет <?php echo htmlspecialchars($captchaQuestion); ?>?</label>
                        <input type="text" id="captcha_answer" name="captcha_answer" required autocomplete="off">
                    </div>
                    <button type="submit">Продолжить</button>
                </form>
            </div>
        </div>
        </body>
        </html>
        <?php
        exit;
    }
}