CREATE TABLE `users` (
                         `ID`int NOT NULL AUTO_INCREMENT,
                         `UUID` varchar(200) unique not null,
                         `NAME` varchar(20) NULL,
                         `EMAIL` varchar(60) unique not NULL,
                         `PHONE` varchar(60) NULL,
                         `PASSWORD` varchar(90) null,
                         `IS_GOOGLE_AUTHENTICATED` varchar(3) not null,
                         PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
