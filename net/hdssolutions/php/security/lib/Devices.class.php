<?php
    namespace net\hdssolutions\php\security\lib;

    use \SQLite3;

    final class Devices extends SQLite3 {
        public function __construct() {
            // check config
            if (SECURITY_DB === null) define(SECURITY_DB, 'security_devices.db');
            // open database file
            $this->open(SECURITY_DB);
            // init database
            if (!$this->init())
                // return exception
                throw new Exception('SQLite3 Database can\'t be inited.');
        }

        private function init() {
            // check if database is inited
            $stmt = $this->query('SELECT name FROM sqlite_master WHERE type="table" AND name="security_devices"');
            if (($table = $stmt->fetchArray(SQLITE3_ASSOC)) !== false) return true;
            // create table
            return $this->exec('CREATE TABLE security_devices (device_id INT PRIMARY KEY NOT NULL, device_creator INT NOT NULL)');
        }
    }