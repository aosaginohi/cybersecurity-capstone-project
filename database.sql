CREATE DATABASE CAPSTONE;
USE CAPSTONE;

CREATE TABLE users (
    ID int NOT NULL AUTO_INCREMENT,
    LastName varchar(255) NOT NULL,
    FirstName varchar(255) NOT NULL,
	Email varchar(255) NOT NULL UNIQUE,
	UserName varchar(255) NOT NULL UNIQUE,
	Password varchar(255) NOT NULL,
	EmailVerification varchar(10) NOT NULL,
	MFAEnabled varchar(3) NOT NULL,
	MFAVerification varchar(10),
	PasswordVerification varchar(10),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `messages` (
  `to_user` text(65535) NOT NULL,
  `from_user` text(65535) NOT NULL,
  `message` text(65535) NOT NULL,
  `datetime` text(65535) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



