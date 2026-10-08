-- =====================================================================
-- Online Event Management System: MySQL 8.0+ backend
-- Run:  mysql -u root -p < event_management.sql
-- =====================================================================
CREATE DATABASE IF NOT EXISTS event_mgmt CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE event_mgmt;

DROP VIEW IF EXISTS v_event_stats, v_pending_events, v_attendee_tickets;
DROP TABLE IF EXISTS activity_log, event_updates, ticket_purchases, registrations, tickets, events, user_profiles, system_settings, users, role_titles;

-- ---------- Tables ----------
-- Staff title hierarchy. level is NULL for Organizer/Attendee (they aren't ranked staff tiers).
-- dashboard_role says which of the three dashboards that title opens.
CREATE TABLE role_titles (
  title          VARCHAR(60) PRIMARY KEY,
  level          TINYINT NULL,                      -- 1 (Administrator) .. 6 (Senior Administrator); NULL for non-staff
  dashboard_role ENUM('Admin','Organizer','Attendee') NOT NULL,
  description    VARCHAR(200)
);

CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(100) NOT NULL,
  email         VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,              -- store bcrypt/argon2 hashes, never plain text
  title         VARCHAR(60) NOT NULL DEFAULT 'Attendee',
  role          ENUM('Admin','Organizer','Attendee') NOT NULL,   -- kept in sync with role_titles.dashboard_role for fast lookups
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (title) REFERENCES role_titles(title)
);

CREATE TABLE user_profiles (                        -- attendee profile + update subscription
  user_id          INT PRIMARY KEY,
  phone            VARCHAR(20),
  city             VARCHAR(80),
  age_group        ENUM('Under 20','20-29','30-39','40+'),
  receive_updates  BOOLEAN NOT NULL DEFAULT TRUE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE events (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  organizer_id  INT NOT NULL,
  title         VARCHAR(150) NOT NULL,
  description   TEXT,
  event_date    DATE NOT NULL,
  event_time    TIME NOT NULL,
  venue         VARCHAR(200) NOT NULL,
  status        ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  reviewed_by   INT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organizer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (reviewed_by)  REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_status_date (status, event_date)
);

CREATE TABLE tickets (                              -- one ticket type per event
  id        INT AUTO_INCREMENT PRIMARY KEY,
  event_id  INT NOT NULL UNIQUE,
  price     DECIMAL(10,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
  quantity  INT NOT NULL DEFAULT 100 CHECK (quantity >= 0),
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE registrations (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  event_id       INT NOT NULL,
  user_id        INT NOT NULL,
  status         ENUM('Registered','Cancelled') NOT NULL DEFAULT 'Registered',
  registered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_event_user (event_id, user_id),
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
);

CREATE TABLE ticket_purchases (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  event_id      INT NOT NULL,
  user_id       INT NOT NULL,
  quantity      INT NOT NULL CHECK (quantity > 0),
  total_amount  DECIMAL(10,2) NOT NULL,
  payment_ref   VARCHAR(60),                        -- gateway transaction id (card data is never stored)
  purchased_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE,
  INDEX idx_purchase_event (event_id)
);

CREATE TABLE event_updates (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  event_id   INT NOT NULL,
  sender_id  INT NOT NULL,
  message    TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id)  REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id)  ON DELETE CASCADE
);

CREATE TABLE system_settings (
  setting_key    VARCHAR(50) PRIMARY KEY,
  setting_value  VARCHAR(200) NOT NULL,
  updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE activity_log (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NULL,
  action      VARCHAR(255) NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_log_time (created_at)
);

-- ---------- Views (dashboard data) ----------
CREATE VIEW v_event_stats AS                        -- Admin + Organizer statistics
SELECT e.id AS event_id, e.title, e.organizer_id, e.status, t.quantity AS capacity,
       COALESCE(SUM(p.quantity),0)                  AS tickets_sold,
       COALESCE(SUM(p.total_amount),0)              AS revenue,
       t.quantity - COALESCE(SUM(p.quantity),0)     AS tickets_left,
       (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id AND r.status='Registered') AS registrations
FROM events e
LEFT JOIN tickets t          ON t.event_id = e.id
LEFT JOIN ticket_purchases p ON p.event_id = e.id
GROUP BY e.id, e.title, e.organizer_id, e.status, t.quantity;

CREATE VIEW v_pending_events AS                     -- Admin approvals table
SELECT e.id, e.title, e.event_date, e.venue, u.name AS organizer, e.created_at
FROM events e JOIN users u ON u.id = e.organizer_id
WHERE e.status = 'pending' ORDER BY e.created_at;

CREATE VIEW v_attendee_tickets AS                   -- Attendee "My tickets"
SELECT p.user_id, e.title, e.event_date, p.quantity, p.total_amount, p.purchased_at
FROM ticket_purchases p JOIN events e ON e.id = p.event_id;

-- ---------- Stored procedures ----------
DELIMITER //

CREATE PROCEDURE sp_register(IN p_user INT, IN p_event INT, OUT p_msg VARCHAR(120))
BEGIN
  IF NOT EXISTS (SELECT 1 FROM events WHERE id = p_event AND status = 'approved') THEN
    SET p_msg = 'Event is not open for registration';
  ELSE
    INSERT INTO registrations (event_id, user_id) VALUES (p_event, p_user)
      ON DUPLICATE KEY UPDATE status = 'Registered';
    INSERT INTO activity_log (user_id, action) VALUES (p_user, CONCAT('Registered for event #', p_event));
    SET p_msg = 'Registration confirmed';
  END IF;
END //

-- Buys tickets in one transaction; locks the ticket row so two buyers can't oversell.
CREATE PROCEDURE sp_buy_tickets(IN p_user INT, IN p_event INT, IN p_qty INT, IN p_payment_ref VARCHAR(60), OUT p_msg VARCHAR(120))
BEGIN
  DECLARE v_price DECIMAL(10,2); DECLARE v_cap INT; DECLARE v_sold INT; DECLARE v_status VARCHAR(10);
  DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; SET p_msg = 'Purchase failed. Please try again'; END;

  START TRANSACTION;
  SELECT t.price, t.quantity, e.status INTO v_price, v_cap, v_status
    FROM tickets t JOIN events e ON e.id = t.event_id WHERE t.event_id = p_event FOR UPDATE;
  SELECT COALESCE(SUM(quantity),0) INTO v_sold FROM ticket_purchases WHERE event_id = p_event;

  IF v_status IS NULL OR v_status <> 'approved' THEN
    ROLLBACK; SET p_msg = 'Tickets are not on sale for this event';
  ELSEIF p_qty < 1 OR p_qty > v_cap - v_sold THEN
    ROLLBACK; SET p_msg = CONCAT('Only ', v_cap - v_sold, ' tickets left');
  ELSE
    INSERT INTO registrations (event_id, user_id) VALUES (p_event, p_user)
      ON DUPLICATE KEY UPDATE status = 'Registered';
    INSERT INTO ticket_purchases (event_id, user_id, quantity, total_amount, payment_ref)
      VALUES (p_event, p_user, p_qty, p_qty * v_price, p_payment_ref);
    INSERT INTO activity_log (user_id, action) VALUES (p_user, CONCAT('Bought ', p_qty, ' ticket(s) for event #', p_event));
    COMMIT;
    SET p_msg = CONCAT('Purchase confirmed: ', p_qty, ' ticket(s)');
  END IF;
END //

CREATE PROCEDURE sp_review_event(IN p_admin INT, IN p_event INT, IN p_decision ENUM('approved','rejected'))
BEGIN
  UPDATE events SET status = p_decision, reviewed_by = p_admin WHERE id = p_event AND status = 'pending';
  INSERT INTO activity_log (user_id, action) VALUES (p_admin, CONCAT('Event #', p_event, ' ', p_decision));
END //

CREATE PROCEDURE sp_create_event(IN p_org INT, IN p_title VARCHAR(150), IN p_desc TEXT, IN p_date DATE,
                                 IN p_time TIME, IN p_venue VARCHAR(200), IN p_price DECIMAL(10,2), IN p_qty INT)
BEGIN
  DECLARE v_status VARCHAR(10);
  SELECT IF(setting_value = 'Automatic', 'approved', 'pending') INTO v_status FROM system_settings WHERE setting_key = 'event_approval';
  INSERT INTO events (organizer_id, title, description, event_date, event_time, venue, status)
    VALUES (p_org, p_title, p_desc, p_date, p_time, p_venue, COALESCE(v_status, 'pending'));
  INSERT INTO tickets (event_id, price, quantity) VALUES (LAST_INSERT_ID(), p_price, p_qty);
  INSERT INTO activity_log (user_id, action) VALUES (p_org, CONCAT('Created event "', p_title, '"'));
END //

-- Sends an update; only attendees who are registered AND subscribed will see it (see query below).
CREATE PROCEDURE sp_send_update(IN p_org INT, IN p_event INT, IN p_msg TEXT, OUT p_recipients INT)
BEGIN
  INSERT INTO event_updates (event_id, sender_id, message)
    SELECT p_event, p_org, p_msg FROM events WHERE id = p_event AND organizer_id = p_org;
  SELECT COUNT(*) INTO p_recipients FROM registrations r
    LEFT JOIN user_profiles up ON up.user_id = r.user_id
    WHERE r.event_id = p_event AND r.status = 'Registered' AND COALESCE(up.receive_updates, TRUE);
END //

-- Admin-only: assign a title (and therefore dashboard access). Keeps users.role in sync with role_titles.
CREATE PROCEDURE sp_set_title(IN p_user INT, IN p_title VARCHAR(60), OUT p_msg VARCHAR(120))
BEGIN
  DECLARE v_role VARCHAR(10);
  SELECT dashboard_role INTO v_role FROM role_titles WHERE title = p_title;
  IF v_role IS NULL THEN
    SET p_msg = 'Unknown title';
  ELSE
    UPDATE users SET title = p_title, role = v_role WHERE id = p_user;
    INSERT INTO activity_log (user_id, action) VALUES (p_user, CONCAT('Title changed to ', p_title));
    SET p_msg = 'Title updated';
  END IF;
END //

-- Public sign-up: only Attendee or Organizer are self-service. Admin-tier titles must be granted via sp_set_title.
CREATE PROCEDURE sp_signup(IN p_name VARCHAR(100), IN p_email VARCHAR(150), IN p_password_hash VARCHAR(255),
                           IN p_title VARCHAR(60), OUT p_user_id INT, OUT p_msg VARCHAR(120))
BEGIN
  DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; SET p_msg = 'Could not create the account'; SET p_user_id = NULL; END;
  IF p_title NOT IN ('Attendee','Organizer') THEN
    SET p_msg = 'That title needs to be granted by an administrator'; SET p_user_id = NULL;
  ELSEIF EXISTS (SELECT 1 FROM users WHERE email = p_email) THEN
    SET p_msg = 'An account with that email already exists'; SET p_user_id = NULL;
  ELSE
    START TRANSACTION;
    INSERT INTO users (name, email, password_hash, title, role) VALUES (p_name, p_email, p_password_hash, p_title, p_title);
    SET p_user_id = LAST_INSERT_ID();
    IF p_title = 'Attendee' THEN INSERT INTO user_profiles (user_id, receive_updates) VALUES (p_user_id, TRUE); END IF;
    INSERT INTO activity_log (user_id, action) VALUES (p_user_id, CONCAT(p_name, ' signed up as ', p_title));
    COMMIT;
    SET p_msg = 'Account created';
  END IF;
END //

DELIMITER ;

-- ---------- Seed data ----------
INSERT INTO role_titles (title, level, dashboard_role, description) VALUES
 ('Administrator',1,'Admin','Handles day-to-day user management, approvals and support.'),
 ('Community Manager',2,'Admin','Runs communication with organizers and attendees, and gathers feedback.'),
 ('Curator of the Project',3,'Admin','Shapes the roadmap and keeps event content and quality on track.'),
 ('Database Developer',4,'Admin','Designs and looks after the MySQL schema, queries and data integrity.'),
 ('Main Developer',5,'Admin','Builds and maintains the core application and features.'),
 ('Senior Administrator',6,'Admin','Oversees platform policy, escalations and final event decisions.'),
 ('Organizer',NULL,'Organizer','Creates and manages events, tickets and attendee communication.'),
 ('Attendee',NULL,'Attendee','Registers for events and buys tickets.');

-- Password hashes below are real PBKDF2-HMAC-SHA256 hashes (120,000 iterations, random salt), stored as
-- "iterations:saltBase64:hashBase64" -- the exact format EventAppMySQL.java's hashPassword()/verifyPassword() use.
-- Demo passwords: Ravi = admin123, Priya = organizer123, Aisha / Tom = attendee123.
INSERT INTO users (name, email, password_hash, title, role) VALUES
 ('Ravi Menon','ravi@gatherly.io','120000:XeS55KWpEKsdywHMSQO3xA==:l8gQxEuoPbbPk7ybBxH3jN1atvAO4GOb0SPfIZQpls0=','Senior Administrator','Admin'),
 ('Priya Shah','priya@summitco.com','120000:kk8UnEK4jq6BVQdYLX67mA==:limTM2DQqkFbyIt8/MhkTjepneVuJ2iHa3UCBpw7OzE=','Organizer','Organizer'),
 ('Aisha Khan','aisha@mail.com','120000:MmEY+hrDFLIERunV3/uywQ==:Cte/KQRcHGCK097qaYVR78D2lsrKtKJIkHpRBbln37M=','Attendee','Attendee'),
 ('Tom Berg','tom@mail.com','120000:MmEY+hrDFLIERunV3/uywQ==:Cte/KQRcHGCK097qaYVR78D2lsrKtKJIkHpRBbln37M=','Attendee','Attendee');

INSERT INTO user_profiles (user_id, phone, city, age_group, receive_updates) VALUES
 (3,'+91 98765 43210','Agra','20-29',TRUE),(4,'+91 91234 56789','Delhi','30-39',TRUE);

INSERT INTO system_settings VALUES
 ('site_name','Gatherly',DEFAULT),('currency','INR',DEFAULT),('platform_fee_percent','5',DEFAULT),
 ('event_approval','Required',DEFAULT),('email_notifications','Enabled',DEFAULT);

INSERT INTO events (organizer_id,title,description,event_date,event_time,venue,status,reviewed_by) VALUES
 (2,'Product Design Summit','A day of talks on product craft.','2026-10-18','10:00','Jaipur Convention Hall','approved',1),
 (2,'Indie Music Night','Five local bands, one stage.','2026-11-02','19:00','Riverside Arena, Agra','approved',1),
 (2,'Startup Founders Meetup','Networking and pitch practice.','2026-12-05','17:30','Hub 42, Delhi','pending',NULL),
 (2,'Photography Walk','Golden hour around the old city.','2026-10-10','06:30','Mehtab Bagh','pending',NULL);

INSERT INTO tickets (event_id, price, quantity) VALUES (1,1500,200),(2,800,300),(3,0,80),(4,300,40);

INSERT INTO registrations (event_id, user_id) VALUES (1,3),(2,3),(1,4);
INSERT INTO ticket_purchases (event_id,user_id,quantity,total_amount,payment_ref) VALUES
 (1,3,1,1500,'demo-001'),(1,4,2,3000,'demo-002'),(2,3,4,3200,'demo-003');
INSERT INTO event_updates (event_id,sender_id,message) VALUES (1,2,'Doors open at 9:30 AM. Bring your ticket confirmation.');
INSERT INTO activity_log (user_id,action) VALUES (2,'Created event "Startup Founders Meetup"'),(3,'Bought 1 ticket(s) for event #1');

-- ---------- Queries the dashboards use ----------
-- Admin:      SELECT u.id,u.name,u.email,u.title,rt.level,u.role,u.is_active FROM users u JOIN role_titles rt ON rt.title=u.title ORDER BY u.id;
--             SELECT title,level,dashboard_role,description FROM role_titles ORDER BY level DESC;  -- for the title dropdown, level 6 first
--             CALL sp_set_title(3, 'Community Manager', @msg); SELECT @msg;   -- promote/reassign a staff member
--             SELECT * FROM v_pending_events;              CALL sp_review_event(1, 3, 'approved');
--             UPDATE system_settings SET setting_value='7' WHERE setting_key='platform_fee_percent';
--             SELECT a.created_at, u.name, a.action FROM activity_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 50;
-- Sign-up:    CALL sp_signup('New User','new@mail.com','<bcrypt hash>','Attendee', @uid, @msg); SELECT @uid, @msg;
-- Organizer:  SELECT * FROM v_event_stats WHERE organizer_id = 2;
--             UPDATE tickets SET price=1800, quantity=250 WHERE event_id=1;   -- app must reject quantity < tickets_sold
--             SELECT up.age_group, COUNT(*) FROM registrations r JOIN user_profiles up ON up.user_id=r.user_id WHERE r.event_id=1 GROUP BY up.age_group;
--             SELECT title, event_date FROM events WHERE organizer_id=2 AND status='approved' AND event_date>=CURDATE() ORDER BY event_date;
-- Attendee:   CALL sp_register(3, 2, @msg);  CALL sp_buy_tickets(3, 2, 2, 'gw-123', @msg);  SELECT @msg;
--             SELECT * FROM v_attendee_tickets WHERE user_id = 3;
--             SELECT e.title, u.message, u.created_at FROM event_updates u JOIN events e ON e.id=u.event_id
--               JOIN registrations r ON r.event_id=u.event_id AND r.user_id=3 AND r.status='Registered' ORDER BY u.created_at DESC;
--             SELECT e.title, r.registered_at, r.status FROM registrations r JOIN events e ON e.id=r.event_id WHERE r.user_id=3;
