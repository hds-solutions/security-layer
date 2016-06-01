<?php
	namespace net\hdssolutions\php\security;

	final class SecurityLayer {
		/**
		 * Session inactive timeout
		 * @var int Timeout in seconds
		 */
		const SESSION_EXPIRE = 1800;

		/**
		 * List of keys allowed to XSS
		 *
		 * Useful for html form fields
		 *
		 * @var Array List of keys
		 */
		private static $ALLOWED_KEYS = Array();

		function __construct() {
			// init session
			if (!isset($_SESSION)) session_start();
			// validate requested method
			$this->validateMethod();
			// set basic php configurations
			$this->configurePHP();
			// set http security headers
			$this->setSecurityHeaders();
			// clean vars
			$this->cleanVars();
			// check last move
			$this->lastMove();
		}

		/**
		 * Clean a custom variable
		 *
		 * @param mixed Variable to clean
		 */
		public function clean($var){
			if (gettype($var) == 'object')
				$var = (Array)$var;
			$var = $this->cleanXSS($var);
			$var = $this->cleanCRLF($var);
			$var = $this->addSlashes($var);
			return (Object)$var;
		}

		public static function allow($key) {
			// add allowed key
			self::$ALLOWED_KEYS[] = $key;
		}

		/**
		 * Returns true if there is a session open
		 */
		public function isLogged() {
			// return if is logged
			return isset($_SESSION[md5(__CLASS__).'_TOKEN']);
		}

		/**
		 * Logout current session
		 */
		public function logout() {
			// destroy current session
			session_destroy();
		}

		/**
		 * Make a new token
		 */
		public function newToken() {
			// make a new token
			$_SESSION[md5(__CLASS__).'_TOKEN'] = base64_encode(md5(uniqid()));
			// return token
			return $_SESSION[md5(__CLASS__).'_TOKEN'];
		}

		/**
		 * Get current token
		 */
		public function getToken() {
			// check if toke exists
			if (!isset($_SESSION[md5(__CLASS__).'_TOKEN']) || strlen(base64_decode($_SESSION[md5(__CLASS__).'_TOKEN'])) != 32)
				// create a new token
				$this->newToken();
			// return current token
			return $_SESSION[md5(__CLASS__).'_TOKEN'];
		}

		/**
		 * Validate token with current
		 * @param string Client Token
		 */
		public function validateToken($token = null) {
			// get token, if param is not specified, get request token
			$token = $token !== null ? $token : (isset($_REQUEST['token']) ? $_REQUEST['token'] : null);
			// compare with current token
			if ($token != $this->getToken()) return false;
			// token is equal
			return true;
		}

		private function validateMethod() {
			$method = $_SERVER['REQUEST_METHOD'];
			if ($method == 'POST' && array_key_exists('HTTP_X_HTTP_METHOD', $_SERVER))
				$method = strtoupper($_SERVER['HTTP_X_HTTP_METHOD']);
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
				foreach ($var AS $key => $value)
					$var[$key] = in_array($key, self::$ALLOWED_KEYS) ? $value : htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
			return $var;
		}

		private function addSlashes($var) {
			if ($var !== null)
				foreach ($var AS $key => $value)
					$var[$key] = addslashes($value);
			return $var;
		}

		private function cleanCRLF($var) {
			if ($var !== null)
				foreach ($var AS $key => $value)
					$var[$key] = str_replace(Array('\r\n', '\r', '\n', '\t'), Array( '\\r\\n', '\\r', '\\n', '\\t'), $value);
			return $var;
		}

		private function lastMove() {
			// check if a session exists and if the token is expired
			if ($this->isLogged() && isset($_SESSION[md5(__CLASS__).'_LAST_MOVE']) && (strtotime('now') - $_SESSION[md5(__CLASS__).'_LAST_MOVE']) >= self::SESSION_EXPIRE)
				// create a new token
				$this->newToken();
			// update timestamp
			$_SESSION[md5(__CLASS__).'_LAST_MOVE'] = strtotime('now');
		}
	}