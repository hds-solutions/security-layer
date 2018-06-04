<?php
    namespace net\hdssolutions\php\security;

    require_once __DIR__.'/lib/Device.class.php';

    use Exception;
    use net\hdssolutions\php\security\lib\Device;

    final class SecurityLayer {
        /**
         * List of keys allowed to XSS
         *
         * Useful for html form fields
         *
         * @var Array List of keys
         */
        private static $ALLOWED_KEYS = Array();

        /**
         * Registred device
         * @var Devices Registred device
         */
        private $device;

        public function __construct() {
            // validate requested method
            $this->validateMethod();
            // set basic php configurations
            $this->configurePHP();
            // set http security headers
            $this->setSecurityHeaders();
            // clean vars
            $this->cleanVars();
            // init session
            if (!isset($_SESSION)) session_start();
            // open device db
            $this->device = new Device($this);
        }

        /**
         * Clean a custom variable
         *
         * @param mixed Variable to clean
         */
        public function clean($var) {
            if (gettype($var) == 'object')
                $var = (Array)$var;
            $var = $this->cleanXSS($var);
            $var = $this->cleanCRLF($var);
            $var = $this->addSlashes($var);
            return (Object)$var;
        }

        public static function allow($key) {
            // add allowed key
            self::$ALLOWED_KEYS = array_merge(self::$ALLOWED_KEYS, gettype($key) == 'array' ? $key : [ $key ]);
        }

        /**
         * Returns true if there is a session open
         */
        public function isLogged() {
            // return if is logged
            return $this->device->isLogged();
        }

        /**
         * Logout current session
         */
        public function logout() {
            // logout device
            return $this->device->logout();
        }

        /**
         * Validate token with current
         * @param string Client Token
         */
        public function validateToken($token = null) {
            // validate device token
            return $this->device->validateToken($token);
        }

        /**
         * Get current token
         * @return token Token
         */
        public function getToken() {
            // get device token
            return $this->device->getToken();
        }

        /**
         * Make a new token
         * @return token Token
         */
        public function newToken() {
            // create device token
            return $this->device->newToken();
        }

        /**
         * Send token on response
         */
        public function sendToken() {
            // send device token
            return $this->device->sendToken();
        }

        private function validateMethod() {
        	// get method
            $method = $_SERVER['REQUEST_METHOD'];
            // check for special method (PUT, DELETE, PATCH, etc)
            if ($method == 'POST' && array_key_exists('HTTP_X_HTTP_METHOD', $_SERVER))
            	// get special method
                $method = strtoupper($_SERVER['HTTP_X_HTTP_METHOD']);
            // allow normal methods
            switch ($method) {
                case 'GET':
                case 'POST':
                case 'PUT':
                case 'DELETE':
                    break;
                default:
                    exit(header($_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request', true, 400));
                    break;
            }
        }

        private function configurePHP() {
            // **PREVENTING SESSION HIJACKING**
            // Prevents javascript XSS attacks aimed to steal the session ID
            ini_set('session.cookie_httponly', true);

            // **PREVENTING SESSION FIXATION**
            // Session ID cannot be passed through URL
            ini_set('session.use_only_cookies', true);

            // Uses a secure connection (HTTPS) if possible
            ini_set('session.cookie_secure', true);
        }

        private function setSecurityHeaders() {
            header('X-Frame-Options: DENY');
            header('X-XSS-Protection: 1; mode=block');
            header('X-Content-Type-Options: nosniff');
        }

        private function cleanVars() {
            // XSS
            $_GET     = $this->cleanXSS($_GET);
            $_POST    = $this->cleanXSS($_POST);
            $_REQUEST = $this->cleanXSS($_REQUEST);
            if (isset($_SESSION))
                $_SESSION = $this->cleanXSS($_SESSION);

            // clean CRLF
            $_GET     = $this->cleanCRLF($_GET);
            $_POST    = $this->cleanCRLF($_POST);
            $_REQUEST = $this->cleanCRLF($_REQUEST);
            if (isset($_SESSION))
                $_SESSION = $this->cleanCRLF($_SESSION);

            // add slashes
            $_GET     = $this->addSlashes($_GET);
            $_POST    = $this->addSlashes($_POST);
            $_REQUEST = $this->addSlashes($_REQUEST);
            if (isset($_SESSION))
                $_SESSION = $this->addSlashes($_SESSION);
        }

        private function cleanXSS($var) {
            if ($var !== null)
                foreach ($var as $key => $value) {
                    if (is_array($value) || is_object($value))
                        $value = $this->cleanXSS($value);
                    else
                        $value = in_array($key, self::$ALLOWED_KEYS) ? $value : htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                    //
                    if (is_object($var))
                        $var->$key = $value;
                    else
                        $var[$key] = $value;
                }
            return $var;
        }

        private function addSlashes($var) {
            if ($var !== null)
                foreach ($var as $key => $value) {
                    if (is_array($value) || is_object($value))
                        $value = $this->addSlashes($value);
                    else
                        $value = addslashes($value);
                    //
                    if (is_object($var))
                        $var->$key = $value;
                    else
                        $var[$key] = $value;
                }
            return $var;
        }

        private function cleanCRLF($var) {
            if ($var !== null)
                foreach ($var as $key => $value) {
                    if (is_array($value) || is_object($value))
                        $value = $this->cleanCRLF($value);
                    else
                        $value = str_replace(Array('\r\n', '\r', '\n', '\t'), Array( '\\r\\n', '\\r', '\\n', '\\t'), $value);
                    //
                    if (is_object($var))
                        $var->$key = $value;
                    else
                        $var[$key] = $value;
                }
            return $var;
        }
    }