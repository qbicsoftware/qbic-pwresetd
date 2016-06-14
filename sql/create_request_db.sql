DROP DATABASE IF EXISTS @DB_NAME@;
CREATE DATABASE @DB_NAME@;

GRANT ALL ON @DB_NAME@.* TO '@DB_USER@'@'localhost';
USE `@DB_NAME@`;
CREATE TABLE `reset_requests` (
  `request_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `account_name` varchar(11) COLLATE utf8_bin NOT NULL DEFAULT '',
  `secret_code` varchar(128) COLLATE utf8_bin NOT NULL DEFAULT '',
  `creation_timestamp` DATETIME NOT NULL,
  `reset_duration` int(11) NOT NULL DEFAULT '48',
  `is_active` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`request_id`),
  UNIQUE KEY `secret_code` (`secret_code`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

