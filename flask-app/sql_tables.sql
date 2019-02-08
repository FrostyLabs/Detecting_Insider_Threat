DROP TABLE stats;
CREATE TABLE stats(
  ip_addr varchar(15) PRIMARY KEY NOT NULL,
  two_weeks int(3),
  one_week int(3),
  three_days int(3),
  total int(5)
);

DROP TABLE users;
CREATE TABLE users(
	id int(11) AUTO_INCREMENT PRIMARY KEY NOT NULL,
	name varchar(100),
	email varchar(100),
	username varchar(30),
	password varchar(100),
	register_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

DROP TABLE articles;
CREATE TABLE articles(
	id int(11) AUTO_INCREMENT PRIMARY KEY NOT NULL,
	title varchar(255),
	author varchar(100),
	body TEXT,
	create_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
