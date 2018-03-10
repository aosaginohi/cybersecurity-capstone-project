CREATE DATABASE CAPSTONE;
USE CAPSTONE;

CREATE TABLE users (
    ID int NOT NULL AUTO_INCREMENT,
	Email varchar(65) NOT NULL UNIQUE,
	UserName varchar(16) NOT NULL UNIQUE,
	Password varchar(255) NOT NULL,
	EmailVerification varchar(255) NOT NULL,
	MFAEnabled varchar(3) NOT NULL,
	MFAVerification varchar(255),
	PasswordVerification varchar(255),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `messages` (
  `to_user` text(65535) NOT NULL,
  `from_user` text(65535) NOT NULL,
  `message` text(65535) NOT NULL,
  `datetime` text(65535) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;