# GoLang TODO List Application with MongoDB and JWT Authentication

This is a simple TODO list application implemented in GoLang, using MongoDB for data storage and JWT for user authentication.

## Prerequisites

Before running the application, ensure you have the following installed:
- GoLang (version 1.15+ recommended)
- MongoDB (Atlas or local installation)
- Node.js and npm (for frontend development, if applicable)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
Install dependencies:

bash
Copy code
go mod tidy
Set up environment variables:
Create a .env file or set environment variables:

plaintext
Copy code
MONGODB_URI=mongodb+srv://your-connection-string
JWT_SECRET=your_secret_key
Configuration
Ensure MongoDB is running and accessible. Update the connectionString and jwtKey variables in main.go with your MongoDB URI and JWT secret key.

Running the Application
To start the server, run:

bash
Copy code
go run main.go
By default, the server will start on port 9020. You can access the application at http://localhost:9020.

Endpoints
GET /: Homepage of the application.
GET /signup: Register a new user.
POST /signup: Create a new user account.
GET /login: Display the login page.
POST /login: Authenticate user and generate JWT token.
GET /todo: Fetch user-specific TODO list.
POST /todo: Create a new TODO item.
PUT /todo/{id}: Update an existing TODO item.
DELETE /todo/{id}: Delete a TODO item
