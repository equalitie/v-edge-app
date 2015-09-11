-- MySQL dump 10.13  Distrib 5.6.23, for Linux (x86_64)
--
-- Host: localhost    Database: eq_dashboard
-- ------------------------------------------------------
-- Server version	5.6.22-1+deb.sury.org~precise+1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `permissions`
--

DROP TABLE IF EXISTS `permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `permissions` (
  `user_id` int(11) NOT NULL,
  `website_id` int(11) NOT NULL,
  `role` tinyint(4) NOT NULL DEFAULT '1',
  PRIMARY KEY (`user_id`,`website_id`),
  UNIQUE KEY `website_user_combo` (`user_id`,`website_id`),
  KEY `role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `records`
--

DROP TABLE IF EXISTS `records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `records` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(6) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `value` varchar(255) NOT NULL,
  `priority` int(11) DEFAULT NULL,
  `weight` int(11) DEFAULT NULL,
  `website_id` int(11) NOT NULL,
  `deflect` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_combo` (`type`,`hostname`,`value`,`website_id`),
  KEY `type` (`type`),
  KEY `hostname` (`hostname`),
  KEY `tll` (`priority`),
  KEY `value` (`value`),
  KEY `website_id` (`website_id`)
) ENGINE=InnoDB AUTO_INCREMENT=722 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `password_salt` varchar(255) NOT NULL,
  `date_joined` int(11) NOT NULL,
  `status` tinyint(4) NOT NULL DEFAULT '0',
  `password_reset` tinyint(4) NOT NULL DEFAULT '0',
  `reset_link` varchar(100) DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email_UNIQUE` (`email`),
  KEY `date_joined` (`date_joined`),
  KEY `status` (`status`),
  KEY `email` (`email`(10)),
  KEY `reset_link` (`reset_link`(20))
) ENGINE=InnoDB AUTO_INCREMENT=140 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `websites`
--

DROP TABLE IF EXISTS `websites`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `websites` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) NOT NULL,
  `status` float NOT NULL,
  `hash_id` binary(16) NOT NULL,
  `hidden_domain` varchar(32) NOT NULL,
  `banjax_auth_hash` varchar(255) NOT NULL DEFAULT '',
  `awstats_password` varchar(40) NOT NULL DEFAULT '',
  `creator_id` int(11) NOT NULL,
  `ip_address` varchar(16) DEFAULT NULL,
  `scan_in_progress` tinyint(4) NOT NULL DEFAULT '0',
  `nsinfo` text NOT NULL,
  `admin_key` varchar(255) DEFAULT '',
  `save_visitor_logs` tinyint(4) NOT NULL DEFAULT '0',
  `use_ssl` tinyint(4) NOT NULL DEFAULT '0',
  `ssl_certificate_file_upload_date` bigint(20) DEFAULT NULL,
  `ssl_key_file_upload_date` bigint(20) DEFAULT NULL,
  `ssl_chain_file_upload_date` bigint(20) DEFAULT NULL,
  `cache_time` int(11) NOT NULL DEFAULT '10',
  `under_attack` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `url_UNIQUE` (`url`),
  UNIQUE KEY `hash_id_UNIQUE` (`hash_id`),
  KEY `website_status` (`status`),
  KEY `website_hash_id` (`hash_id`),
  KEY `save_visitor_logs` (`save_visitor_logs`)
) ENGINE=InnoDB AUTO_INCREMENT=141 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-02-28 13:10:19
