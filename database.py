import os
import sqlite3
import psycopg2


def db():
    url = os.getenv("DATABASE_URL")

    if url:
        return psycopg2.connect(url)
    else:
        return sqlite3.connect("auth.db")
