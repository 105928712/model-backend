# Joey Manani & Anchorfish Team 2026
# main.py


"""
Provide an API to the frontend to interact with the model and the database.

FastAPI will be used along with Pydantic and a SQLite database.

I will probably also make a docker container for this too and make this publicly available.

We will be doing every security method outlined by Assignment 3.

API Contacts are still to be decided.

This API will follow REST and OOP practices, taking data in as JSON and returning JSON.

We will be using real HTTP methods, status codes and headers.

Authentication will be done using JWT tokens.

User accounts will be stored in the database. 

We will need to also design the database schema too to handle these things.

Security comes first, speed second.
"""

import fastapi
import pydantic
import sqlite3
import jwt
import dotenv
import uvicorn
dotenv.load_dotenv()


if __name__ == "__main__":
    app = fastapi.FastAPI(
        title="Anchorfish Model Backend",
        description="API for the Anchorfish model",
        version="0.1.0",
        contact={
            "name": "Joey Manani",
            "email": "joeymanani@theflyingrat.com",
        },
    )

    uvicorn.run(app, host="0.0.0.0", port=8000)
    print("Server is running on http://0.0.0.0:8000")