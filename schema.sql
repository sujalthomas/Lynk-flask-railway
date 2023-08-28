CREATE TABLE "user" (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    fs_uniquifier VARCHAR(255) UNIQUE,
    password_reset_code VARCHAR(6),
    password_reset_code_expiration TIMESTAMP,
    is_active BOOLEAN DEFAULT FALSE,
    verification_code VARCHAR(6),
    verification_code_expiration TIMESTAMP
);

CREATE TABLE role (
    id SERIAL PRIMARY KEY,
    name VARCHAR(80) UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE roles_users (
    user_id INTEGER REFERENCES "user"(user_id),
    role_id INTEGER REFERENCES role(id),
    PRIMARY KEY(user_id, role_id)
);

CREATE TABLE cover_letter (
    cover_letter_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(user_id) NOT NULL,
    company_name VARCHAR(100),
    job_listing TEXT,
    recruiter VARCHAR(100),
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path VARCHAR(255)
);

CREATE TABLE resume (
    resume_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(user_id) NOT NULL,
    content TEXT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE usage_statistic (
    stat_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(user_id),
    action VARCHAR(50),
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
