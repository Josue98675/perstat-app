from dotenv import load_dotenv
load_dotenv()

from app import app, generate_ai_summary

with app.app_context():
    generate_ai_summary()
