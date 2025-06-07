# 📘 TARPAULIN

Tarpaulin is a lightweight course management tool. The Tarpaulin REST API has 13 endpoints, most of which are protected. The protected endpoints require a valid JWT in the request as Bearer token in the Authorization header. Each user in Tarpaulin has one of three roles: admin, instructor, and student.

---

## 📋 Features
- Google Cloud Integration (Google App Engine, Google Cloud Datastore, Google Cloud Storage)
- JWT-based Authentication using Auth0
- Role-based access control (admin, instructor, student)
- JWT verification via RS256
- Custom AuthError handling
- User Management
- Course Management
- Enrollment Management

## 📡 API Endpoints

- `POST /users/login`
    - Generates and returns JWT token
    
    - Parameters: 
        - Required:
            - username      (Username)
            - password      (Password)
    
    - Returns:
        - 200 OK          (POST): Success
        - 400 Bad Request (POST): Failure
        - 401 Unauthorized (POST): Failure

- `GET /users`
    - Fetches all users and returns id, role, and sub properties for each
    
    - Parameters:
        - Required:
            - JWT as Bearer token in Authorization header
        
    - Returns:
        - 200 OK           (GET): Success
        - 401 Unauthorized (GET): Failure
        - 403 Forbidden    (GET): Failure

- `GET /users/<int:user_id>`
    - Fetches and returns user details by user id
    
    - Parameters:
        - Required:
            - user_id       (ID of the user)
            - JWT as Bearer token in Authorization header
        
    - Returns:
        - 200 OK           (GET): Success
        - 401 Unauthorized (GET): Failure
        - 403 Forbidden    (GET): Failure

- `GET /users/<int:user_id>/avatar`
    - Fetches user avatar file from Google Cloud Storage

    - Parameters:
        - Required:
            - user_id       (ID of the user)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 200 OK           (GET): Success
        - 401 Unauthorized (GET): Failure
        - 403 Forbidden    (GET): Failure
        - 404 Not Found    (GET): Failure

- `POST /users/<int:user_id>/avatar`
    - Uploads user avatar file to Google Cloud Storage

    - Parameters:
        - Required:
            - user_id       (ID of the user)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 200 OK           (POST): Success
        - 401 Unauthorized (POST): Failure
        - 403 Forbidden    (POST): Failure

- `DELETE /users/<int:user_id>/avatar`
    - Deletes user avatar file from Google Cloud Storage

    - Parameters:
        - Required:
            - user_id       (ID of the user)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 204 No Content   (DELETE): Success
        - 401 Unauthorized (DELETE): Failure
        - 403 Forbidden    (DELETE): Failure
        - 404 Not Found    (DELETE): Failure

- `GET /courses`
    - Returns a paginated list of all courses

    - Parameters:
        - Optional:
            - offset        (Offset)
            - limit         (Limit)
    
    - Returns:
        - 200 OK           (GET): Success
        - 400 Bad Request  (GET): Failure

- `POST /courses`
    - Creates a course

    - Parameters:
        - Required:
            - subject           (String. Subject code up to 4 chars)
            - number           (Integer)
            - title             (String. Course title up to 50 chars)
            - term              (String. Up to 10 chars)
            - instructor_id     (Integer. The instructor assigned to teach the course)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 201 Created      (POST): Success
        - 400 Bad Request  (POST): Failure
        - 401 Unauthorized (POST): Failure
        - 403 Forbidden    (POST): Failure

- `GET /courses/<int:course_id>`
    - Returns details of existing course

    - Parameters:
        - Required:
            - course_id         (ID of the course)

    - Returns:
        - 200 OK           (GET): Success
        - 404 Not Found    (GET): Failure

- `PATCH /courses/<int:course_id>`
    - Performs a partial update on the course

    - Parameters:
        - Required:
            - course_id         (ID of the course)
            - JWT as Bearer token in Authorization header

        - Optional:
            - subject           (String. Subject code up to 4 chars)
            - number            (Integer)
            - title             (String. Course title up to 50 chars)
            - term              (String. Up to 10 chars)
            - instructor_id     (Integer)
        
        - Returns:
            - 200 OK           (PATCH): Success
            - 400 Bad Request  (PATCH): Failure
            - 401 Unauthorized (PATCH): Failure
            - 403 Forbidden    (PATCH): Failure     

- `DELETE /courses/<int:course_id>`
    - Deletes a course

    - Parameters:
        - Required:
            - course_id         (ID of the course)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 204 No Content   (DELETE): Success
        - 401 Unauthorized (DELETE): Failure
        - 403 Forbidden    (DELETE): Failure

- `GET /courses/<int:course_id>/students`
    - Returns list of students enrolled in a course

    - Parameters:
        - Required:
            - course_id         (ID of the course)
            - JWT as Bearer token in Authorization header

    - Returns:
        - 200 OK           (GET): Success
        - 401 Unauthorized (GET): Failure
        - 403 Forbidden    (GET): Failure

- `PATCH /courses/<int:course_id>/students`
    - Enroll and or disenroll students from a course

    - Parameters:
        - Required:
            - add               (Array of student IDs to enroll in course (can be empty array))
            - remove            (Array of student IDs to remove from course (can be empty array))
            - course_id         (ID of the course)
            - JWT as Bearer token in Authorization header

        - Returns:
            - 200 OK           (PATCH): Success
            - 401 Unauthorized (PATCH): Failure
            - 403 Forbidden    (PATCH): Failure
            - 409 Conflict     (PATCH): Failure

## 🏛️ Architecture

The application consists of four main components:

1. **Flask Backend**: REST API endpoints to interact with courses, users, and student enrollments
2. **Auth0 Authentication/Authorization**: OAuth authentication -> JWT 
3. **Google Cloud Datastore**: NoSQL Database for storing users, courses, enrollments
4. **Google Cloud Storage**: Object storage for storing user avatar image files

## ⚠️ Troubleshooting

- If you would like to try out this API, you can request a link to create an account by emailing [support@derekrgreene.com](mailto:support@derekrgreene.com)

## 📝 License

[MIT License](LICENSE)

## 📧 Contact

For support or questions, please open an issue on GitHub.
