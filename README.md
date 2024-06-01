```

# Flask Application with User Management and File Handling

This repository contains a Flask web application with functionalities including user registration, email verification, login, password reset, session management, file upload, and generating cover letters and resumes using the OpenAI API.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [Routes](#routes)
- [Contributing](#contributing)
- [License](#license)

## Features

- User Registration and Email Verification
- Login and Logout
- Password Reset
- Session Management with Redis
- File Upload and Conversion
- Cover Letter and Resume Generation using OpenAI API
- Rate Limiting

## Technologies Used

- [Flask](https://flask.palletsprojects.com/)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/)
- [Flask-Mail](https://pythonhosted.org/Flask-Mail/)
- [Flask-Session](https://pythonhosted.org/Flask-Session/)
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/en/latest/)
- [Flask-CORS](https://flask-cors.readthedocs.io/en/latest/)
- [Flask-Limiter](https://flask-limiter.readthedocs.io/en/stable/)
- [Redis](https://redis.io/)
- [PyPDF2](https://pypdf2.readthedocs.io/en/latest/)
- [python-docx](https://python-docx.readthedocs.io/en/latest/)
- [OpenAI API](https://beta.openai.com/)
- [WTForms](https://wtforms.readthedocs.io/en/stable/)
- [PostgreSQL](https://www.postgresql.org/)

## Setup Instructions

Follow these steps to set up the project on your local machine:

1. **Clone the repository:**

    ```sh
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name
    ```

2. **Create and activate a virtual environment:**

    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the required dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**

    Create a `.env` file in the root directory and add the following variables:

    ```env
    SECRET_KEY=your_secret_key
    SECURITY_PASSWORD_SALT=your_password_salt
    SQLALCHEMY_DATABASE_URI=your_database_uri
    MAIL_SERVER=smtp.sendgrid.net
    MAIL_PORT=587
    MAIL_USERNAME=apikey
    MAIL_PASSWORD=your_sendgrid_api_key
    REDIS_URL=redis://your_redis_url
    ```

5. **Initialize the database:**

    ```sh
    flask db init
    flask db migrate -m "Initial migration."
    flask db upgrade
    ```

6. **Run the application:**

    ```sh
    flask run
    ```

## Usage

### Register a New User

Send a POST request to `/register` with the following JSON payload:

```json
{
  "email": "user@example.com",
  "password": "password123",
  "name": "John Doe"
}
```

### Verify Email

Send a POST request to `/verify` with the following JSON payload:

```json
{
  "email": "user@example.com",
  "code": "verification_code"
}
```

### Login

Send a POST request to `/login` with the following JSON payload:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

### Reset Password

#### Request Password Reset Code

Send a POST request to `/request-reset-password` with the following JSON payload:

```json
{
  "email": "user@example.com"
}
```

#### Reset Password with Code

Send a POST request to `/reset-password` with the following JSON payload:

```json
{
  "email": "user@example.com",
  "code": "reset_code",
  "newPassword": "newpassword123"
}
```

### Upload Resume

Send a POST request to `/upload-resume` with a form-data payload including the user ID token and the resume file.

### Generate Cover Letter

Send a POST request to `/cover-letter` with the following JSON payload:

```json
{
  "apiKey": "your_openai_api_key",
  "Company-name": "Company Name",
  "Job-Listing": "Job Listing Details",
  "Recruiter": "Recruiter's Name",
  "Date": "Today's Date",
  "user_id": "user_id_token"
}
```

## Routes

- `/register` - User registration
- `/verify` - Email verification
- `/login` - User login
- `/request-reset-password` - Request password reset code
- `/reset-password` - Reset password with code
- `/upload-resume` - Upload a resume file
- `/cover-letter` - Generate a cover letter
- `/generate-resume` - Generate a reworded resume

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure your code follows best practices and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

```