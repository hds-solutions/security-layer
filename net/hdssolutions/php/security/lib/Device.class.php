<?php
    namespace net\hdssolutions\php\security\lib;

    use \SQLite3;

    final class Device extends SQLite3 {
        /**
         * Version
         */
        const VERSION = '1.0';

        /**
         * Session inactive timeout
         * @var int Timeout in seconds
         */
        const SESSION_EXPIRE = 1800;

        /**
         * Parent
         * @var SecurityLayer parent
         */
        private $sLayer;

        public function __construct($sLayer) {
            // save parent
            $this->sLayer = $sLayer;
            // check config
            if (SECURITY_DB === null) define(SECURITY_DB, 'security_devices.db');
            // open database file
            $this->open(SECURITY_DB);
            // init database
            if (!$this->initDatabase())
                // return exception
                throw new Exception('SQLite3 Database can\'t be inited.');
            // load hashing extension
            if (!$this->loadExtension(__DIR__.'/../../sqlite/lib/digest.so'))
                // return exception
                throw new Exception('Digest Extension can\'t be loaded.');
            // check last move
            $this->lastMove();
        }

        /**
         * Returns true if there is a session open
         */
        public function isLogged() {
            // return if is logged
            return isset($_SESSION[md5(__CLASS__).'_TOKEN']);
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

        public function sendToken() {
            // send new token on headers
            if ($this->isLogged())
                // version + token
                header('Authorization: ' . self::VERSION . ';' . $this->newToken());
        }

        /**
         * Logout current session
         */
        public function logout() {
            // destroy current session
            session_destroy();
            // remove local vars
            unset($_SESSION[md5(__CLASS__).'_TOKEN']);
            unset($_SESSION[md5(__CLASS__).'_LAST_MOVE']);
            // remove token header
            header_remove('Authorization');
            header_remove('Auth-Version');
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

        public function getTokenCreator() {
            $pstmt = $this->pprepare('SELECT rowid AS device, device_creator FROM security_devices WHERE HEX(SHA1(rowid)) = :device');
            $pstmt->bindValue(':device', $token);
            $pstmt->execute();
            if (($device_data = $pstmt->fetchArray(SQLITE3_ASSOC)) === false) return $this->newTokenCreator();
        }

        private function newTokenCreator() {
            $pstmt = $this->prepare('INSERT INTO security_devices VALUES (:creator)');
            $pstmt->bindValue(':creator', rand(pow(10, 8), (pow(10,9) - 1)));
            $pstmt->execute();
            return sha1($this->lastInsertRowid());
        }

        private function initDatabase() {
            // check if database is inited
            $stmt = $this->query('SELECT name FROM sqlite_master WHERE type = "table" AND name = "security_devices"');
            if ($stmt->fetchArray(SQLITE3_ASSOC) !== false) return true;
            // create table
            return $this->exec('CREATE TABLE security_devices (device_creator INT NOT NULL)');
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