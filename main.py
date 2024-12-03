import streamlit as st
import pandas as pd
import sqlite3
from io import BytesIO

@st.cache_resource
def init_db():
    conn = sqlite3.connect("groom_admin.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            role TEXT,
            status TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS glossary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            term TEXT,
            definition TEXT,
            category TEXT
        )
    """)
    conn.commit()
    return conn

conn = init_db()
@st.cache_data(ttl=60)
def get_users():
    return pd.read_sql_query("SELECT * FROM users", conn)
@st.cache_data(ttl=60)
def get_glossary():
    return pd.read_sql_query("SELECT * FROM glossary", conn)

def authenticate(username, password):
    if username in USER_DB and USER_DB[username] == password:
        st.session_state["auth"] = True
        st.session_state["role"] = USER_ROLES.get(username, "User")
        st.success(f"Logged in as {st.session_state['role']}")
    else:
        st.error("Invalid username or password")
if "auth" not in st.session_state:
    st.session_state["auth"] = False
if "role" not in st.session_state:
    st.session_state["role"] = ""
USER_DB = {"admin": "password123", "user": "userpass"}
USER_ROLES = {"admin": "Admin", "user": "User"}

if not st.session_state["auth"]:
    st.title("Groom Admin Panel - Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        authenticate(username, password)
else:
    menu_options = ["Dashboard", "Users", "Glossary", "Listings"]
    if st.session_state["role"] == "User":
        menu_options.remove("Users")

    menu = st.sidebar.radio("Navigation", menu_options)

    if menu == "Dashboard":
        st.title("Admin Panel Dashboard")
        st.metric("Total Users", len(get_users()))
        st.metric("Glossary Terms", len(get_glossary()))
        st.dataframe(get_users()[["username", "role", "status"]])
    elif menu == "Users":
        st.title("User Management")
        username = st.text_input("New Username")
        role = st.selectbox("Role", ["Admin", "User"])
        status = st.radio("Status", ["Active", "Inactive"])

        if st.button("Add User"):
            try:
                conn.execute("INSERT INTO users (username, role, status) VALUES (?, ?, ?)", (username, role, status))
                conn.commit()
                st.experimental_rerun()
            except sqlite3.IntegrityError:
                st.error("Username already exists!")

        st.dataframe(get_users())
    elif menu == "Glossary":
        st.title("Glossary Management")
        term = st.text_input("Term")
        definition = st.text_area("Definition")
        category = st.selectbox("Category", ["Hair Type 1", "Hair Type 2", "Hair Type 3", "Hair Type 4"])

        if st.button("Add Term"):
            conn.execute("INSERT INTO glossary (term, definition, category) VALUES (?, ?, ?)", (term, definition, category))
            conn.commit()
            st.experimental_rerun()

        uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
        if uploaded_file:
            new_data = pd.read_csv(uploaded_file)
            new_data.to_sql("glossary", conn, if_exists="append", index=False)
            st.success("Glossary CSV uploaded successfully!")

        glossary_csv = BytesIO()
        get_glossary().to_csv(glossary_csv, index=False)
        st.download_button("Download Glossary CSV", glossary_csv, "glossary.csv", "text/csv")

        st.dataframe(get_glossary())
    elif menu == "Listings":
        st.title("Listings Management")
        st.write("Listing management is under development...")

    if st.sidebar.button("Logout"):
        st.session_state["auth"] = False
        st.experimental_rerun()
