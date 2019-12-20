INSERT INTO city (id, name)
VALUES (nextval('city_id_seq'), 'Иннополис'),
       (nextval('city_id_seq'), 'Казань'),
       (nextval('city_id_seq'), 'Москва'),
       (nextval('city_id_seq'), 'Пенза'),
       (nextval('city_id_seq'), 'Махачкала');

INSERT INTO roles (id, name)
VALUES (nextval('role_id_seq'), 'admin'),
       (nextval('role_id_seq'), 'user');

INSERT INTO condition (id, name)
VALUES (nextval('condition_id_seq'), 'Идеальное'),
       (nextval('condition_id_seq'), 'Хорошее'),
       (nextval('condition_id_seq'), 'Среднее'),
       (nextval('condition_id_seq'), 'Плохое');


INSERT INTO category (id, name)
VALUES (nextval('category_id_seq'), 'Одежда'),
       (nextval('category_id_seq'), 'Электроника'),
       (nextval('category_id_seq'), 'Спорттовары'),
       (nextval('category_id_seq'), 'Игрушки'),
       (nextval('category_id_seq'), 'Запчасти'),
       (nextval('category_id_seq'), 'Услуги');

INSERT INTO users (id, username, first_name, last_name, password,
                   phone_number, email, city_id, role_id)
VALUES (nextval('users_id_seq'), 'username1', 'first name 1', 'last name 1',
        '$2a$10$UqSbP/Wsulh3c/t058fW8ei04H1U1yThkiJ311mJANkt5Oi0ZqMK6', '+78005553535', 'email1@mail.k',
        (SELECT id FROM city WHERE id = 1), 1),
       (nextval('users_id_seq'), 'username2', 'first name 2', 'last name 2',
        '$2a$10$XcLXPHgdnDr2m5kC7yFfYOij3bYw3MB6Sd0WVI9Qk9o0htVJr3kOm', '+78005553539', 'email2@mail.su',
        (SELECT id FROM city WHERE id = 2), 2),
       (nextval('users_id_seq'), 'username3', 'first name 3', 'last name 3',
        '$2a$10$XcLXPHgdnDr2m5kC7yFfYOij3bYw3MB6Sd0WVI9Qk9o0htVJr3kOm', '+78005553538', 'email3@mail.sy',
        (SELECT id FROM city WHERE id = 3), 2),
       (nextval('users_id_seq'), 'username4', 'first name 4', 'last name 4',
        '$2a$10$XcLXPHgdnDr2m5kC7yFfYOij3bYw3MB6Sd0WVI9Qk9o0htVJr3kOm', '+78005553537', 'email4@kmail.su',
        (SELECT id FROM city WHERE id = 4), 2),
       (nextval('users_id_seq'), 'username5', 'first name 5', 'last name 5',
        '$2a$10$XcLXPHgdnDr2m5kC7yFfYOij3bYw3MB6Sd0WVI9Qk9o0htVJr3kOm', '+78005553536', 'email5@omail.su',
        (SELECT id FROM city WHERE id = 1), 2);


INSERT INTO message (id, body, sender_id, receiver_id)
VALUES (nextval('message_id_seq'), 'Hello. I want to get my purchase.',
        (SELECT id FROM users WHERE username = 'username3'), (SELECT id FROM users WHERE username = 'username2')),
       (nextval('message_id_seq'), 'Ok, call me',
        (SELECT id FROM users WHERE username = 'username3'), (SELECT id FROM users WHERE username = 'username2')),
       (nextval('message_id_seq'), 'I can''t, call me back pls',
        (SELECT id FROM users WHERE username = 'username2'), (SELECT id FROM users WHERE username = 'username3')),
       (nextval('message_id_seq'), 'Ok, I will call you tomorrow',
        (SELECT id FROM users WHERE username = 'username2'), (SELECT id FROM users WHERE username = 'username3'));

INSERT INTO lot (id, category_id, condition_id, creation_time, last_mod_time, description,
                  user_id, current_price, min_price, max_price, step_price, city_id, name)
VALUES (nextval('lots_id_seq'), 1, 1, now(), now(), 'Simple car', (SELECT id FROM users WHERE username = 'username3'),
        1001, 500, 1500, 75, 1, 'Car 1'),
       (nextval('lots_id_seq'), 1, 3, now(), now(), 'Simple car', (SELECT id FROM users WHERE username = 'username3'),
        1002, 500, 1500, 75, 2, 'Car 2'),
       (nextval('lots_id_seq'), 1, 3, now(), now(), 'Simple phone', (SELECT id FROM users WHERE username = 'username2'),
        1003, 500, 1500, 75, 3, 'Phone 1'),
       (nextval('lots_id_seq'), 1, 3, now(), now(), 'Simple phone', (SELECT id FROM users WHERE username = 'username2'),
        1004, 500, 1500, 75, 4, 'Phone 2'),
       (nextval('lots_id_seq'), 1, 3, now(), now(), 'Simple car', (SELECT id FROM users WHERE username = 'username4'),
        1005, 500, 1500, 75, 3, 'Car 3'),
       (nextval('lots_id_seq'), 2, 2, now(), now(), 'Simple car', (SELECT id FROM users WHERE username = 'username4'),
        1006, 500, 1500, 75, 2, 'Car 4'),
       (nextval('lots_id_seq'), 2, 2, now(), now(), 'Simple car', (SELECT id FROM users WHERE username = 'username4'),
        1007, 500, 1500, 75, 1, 'Car 5');