DROP DATABASE IF EXISTS `hackathon`;
CREATE DATABASE IF NOT EXISTS `hackathon`;
use hackathon;

CREATE TABLE IF NOT EXISTS `firewall_policy` (
    `policy_id` INT(1) UNSIGNED NOT NULL,
    `policy_name` VARCHAR(50) NOT NULL,
    PRIMARY KEY(`policy_id`)
) ENGINE=InnoDB CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `firewall_rule` (
    `rule_id` INT(11) UNSIGNED AUTO_INCREMENT NOT NULL,
    `saddr` INT(1) UNSIGNED DEFAULT NULL,
    `daddr` INT(1) UNSIGNED DEFAULT NULL,
    `stime` TINYINT(1) UNSIGNED,
    `etime` TINYINT(1) UNSIGNED,
    `action` TINYINT(1) UNSIGNED NOT NULL,
    `policy_id` INT(1) UNSIGNED NOT NULL,

    PRIMARY KEY(`rule_id`),
    FOREIGN KEY (`policy_id`) REFERENCES `firewall_policy` (`policy_id`) ON DELETE CASCADE ON UPDATE CASCADE

) ENGINE=InnoDB CHARSET=utf8;


CREATE TABLE IF NOT EXISTS `dpi_policy` (
    `policy_id` INT(1) UNSIGNED NOT NULL,
    `policy_name` VARCHAR(50) NOT NULL,
    PRIMARY KEY(`policy_id`)
) ENGINE=InnoDB CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `dpi_rule` (
    `rule_id` INT(11) UNSIGNED AUTO_INCREMENT NOT NULL,
    `fromPhoneNumber` VARCHAR(32) DEFAULT NULL,
    `toPhoneNumber` VARCHAR(32) DEFAULT NULL,
    `userAgent` VARCHAR(64) DEFAULT NULL,
    `action` TINYINT(1) UNSIGNED NOT NULL,
    `policy_id` INT(1) UNSIGNED NOT NULL,

    PRIMARY KEY(`rule_id`),
    FOREIGN KEY (`policy_id`) REFERENCES `dpi_policy` (`policy_id`) ON DELETE CASCADE ON UPDATE CASCADE

) ENGINE=InnoDB CHARSET=utf8;
