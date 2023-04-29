use test-order-mgmt;
create table products(
    product_id BINARY(16) PRIMARY KEY,
    product_name VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    price bigint NOT NULL,
    description VARCHAR(500) DEFAULT NULL,
    created_at datetime(6) NOT NULL,
    updated_at datetime(6) DEFAULT NULL
);


DELIMITER //

CREATE FUNCTION BIN_TO_UUID(bin BINARY(16))
    RETURNS VARCHAR(36) DETERMINISTIC
BEGIN
  DECLARE hex VARCHAR(32);
  SET hex = HEX(bin);
RETURN LOWER(CONCAT(LEFT(hex, 8), '-', MID(hex, 9, 4), '-', MID(hex, 13, 4), '-', MID(hex, 17, 4), '-', RIGHT(hex, 12)));
END; //

DELIMITER ;



DELIMITER //

CREATE FUNCTION UUID_TO_BIN(uuid VARCHAR(36))
    RETURNS BINARY(16) DETERMINISTIC
BEGIN
RETURN UNHEX(CONCAT(REPLACE(uuid, '-', '')));
END; //

DELIMITER ;
