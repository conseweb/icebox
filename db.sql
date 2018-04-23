
CREATE TABLE
IF NOT EXISTS "addrs"
(
  "Id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  "Type" integer NOT NULL,
  "Index" integer NOT NULL,
  "Name" char(32)
);

CREATE TABLE
IF NOT EXISTS "products"
(
  "Id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  "Code" char(8) NOT NULL,
  "Name" char(16) NOT NULL,
  "Path" char(256) NOT NULL
);