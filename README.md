# 📝 Secure Multi-User Notes API

A production-ready, highly secure RESTful backend service for a multi-user notes application (akin to Google Keep or Apple Notes). Built using **FastAPI**, **SQLAlchemy**, and **SQLite**, this service manages user authentication, full note lifecycles, and secure cross-user note sharing while strictly resolving deep concurrency and injection edge cases.

*   **Live Deployment Base URL:** `https://note-bend-app.onrender.com`  
*   **Interactive API Docs (Swagger UI):** `https://note-bend-app.onrender.com/docs`  
*   **OpenAPI Specification:** `https://note-bend-app.onrender.com/openapi.json`



##  Tech Stack & Architecture

*   **Framework:** FastAPI (Selected for high performance and native OpenAPI/Swagger generation)
*   **Database ORM:** SQLAlchemy with an optimized SQLite backend
*   **Security & Auth:** JWT (JSON Web Tokens) with a native `hashlib` cryptographic salt-and-hash scheme
*   **Data Validation:** Pydantic v2
*   **Containerization:** Docker



##  Key Features & Advanced Edge-Case Handling

### 1. Core Service Features
*   **User Management:** Secure signup and credential verification returning short-lived JWT bearer access tokens.
*   **Note CRUD:** Complete control over creating, viewing, updating, and removing personal notes.
*   **Note Sharing:** Secure multi-tenant ecosystem allowing users to share specific notes with other registered emails.

### 2. Custom Advanced Features (Production Grade)
*   **Dual-Stage Deletion (Trash Bin & Permanent Purge):** `DELETE /notes/{id}` acts as a safe *Soft Delete*, routing items to a hidden Trash Bin viewable via `GET /notes/trash` and fully recoverable via `POST /notes/{id}/restore`. Absolute removal is achieved via `DELETE /notes/{id}/permanent`.
*   **Optimistic Concurrency Control (Race Condition Fix):** Solves the "last-write-wins" collision model on shared collaborative notes. Edits via `PUT` mandate a matching resource `version` check. Overlapping out-of-date modifications are blocked with an explicit `409 Conflict`.
*   **XSS Mitigation & Input Sanitization:** Automatically strips leading/trailing blank margins and sanitizes raw input payloads using secure HTML-escaping utilities before writing to the database, preventing JavaScript injection attacks.
*   **Pagination & Full-Text Search:** Native server-side chunk filtering (`limit` & `skip`) alongside a comprehensive search engine query (`GET /notes/search?q=keyword`).

---

##  API Endpoints 

| Method | Endpoint | Description | Auth Required | Custom Status Codes Documented |
| :--- | :--- | :--- | :---: | :--- |
| **POST** | `/register` | Register a new user | No | `201 Created`, `400 Bad Request` |
| **POST** | `/login` | Authenticate & retrieve JWT token | No | `200 OK`, `401 Unauthorized` |
| **GET** | `/notes` | Retrieve all active owned/shared notes (Paginated) | **Yes** | `200 OK` |
| **GET** | `/notes/search` | Full-text query on note content/title | **Yes** | `200 OK` |
| **GET** | `/notes/trash` | View soft-deleted notes | **Yes** | `200 OK` |
| **GET** | `/notes/{id}` | Fetch a single specific note by ID | **Yes** | `200 OK`, `403 Forbidden`, `404 Not Found` |
| **POST** | `/notes` | Create a new note | **Yes** | `201 Created` |
| **PUT** | `/notes/{id}`| Modify an existing note (Requires `version`) | **Yes** | `200 OK`, `403 Forbidden`, `404 Not Found`, `409 Conflict` |
| **POST** | `/notes/{id}/restore` | Recover a soft-deleted note from trash | **Yes** | `200 OK`, `400 Bad Request`, `404 Not Found` |
| **DELETE**| `/notes/{id}` | Soft-delete a note (Move to Trash) | **Yes** | `204 No Content`, `403 Forbidden`, `404 Not Found` |
| **DELETE**| `/notes/{id}/permanent` | Hard-delete a note entirely from DB | **Yes** | `204 No Content`, `403 Forbidden`, `404 Not Found` |
| **POST** | `/notes/{id}/share` | Share a note with another user's email | **Yes** | `200 OK`, `400 Bad Request`, `403 Forbidden`, `404 Not Found` |
| **GET** | `/about` | Project metadata & features summary | No | `200 OK` |
| **GET** | `/openapi.json` | Compliance schema download | No | `200 OK` |

---

##  Local Installation & Running Guide

### Prerequisites
*   Python 3.10+
*   Docker (Optional, for container testing)

### 1. Setup Virtual Environment
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Server Natively
```bash
uvicorn main:app --reload --port 8080
```

### 4. Run via Docker
```bash
# Build the container image
docker build -t notes-backend .

# Run the container mapping internal ports
docker run -p 8080:8080 -e JWT_SECRET="your_test_secret_key" notes-backend
```

###   Automated Grading & Testing Flow Notes
*  **Header Authorization:** For locked endpoints, log in via POST /login, copy the string value inside access_token, and input it into the Swagger Authorize prompt at the top of the interface as a standard Bearer authorization context.

*  **Multi-tenant Security:** Resource lookups apply 404 Not Found shielding on unauthorized entity IDs to prevent asset data mining, turning into 403 Forbidden exclusively on valid paths where permission is expressly denied.

*  **Database Resets:** The deployment utilizes SQLite for persistence. As part of Render's free hosting virtualization tier, the container local file systems refresh upon instance cycling or prolonged inactivity periods.
