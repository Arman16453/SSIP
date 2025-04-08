from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import openai
import os
from dotenv import load_dotenv
import json
from ssip_responses import SSIP_FAQ

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatbot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

# Initialize database
db = SQLAlchemy(app)

# Chat Message Model
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_message = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.String(100), nullable=False)

# SSIP System prompt
SYSTEM_PROMPT = """You are an AI assistant for the Student Startup and Innovation Policy (SSIP) program. 
Your role is to help students with:
1. Information about SSIP schemes and funding
2. Project submission guidelines
3. Deadlines and important dates
4. Application processes
5. Documentation requirements

Provide accurate, helpful responses based on SSIP guidelines. If you're unsure about something, 
acknowledge it and suggest contacting the SSIP coordinator for verification.

Keep responses concise and focused on SSIP-related queries."""

def get_fallback_response(query):
    # Convert query to lowercase for matching
    query = query.lower().strip()
    
    # Try to find an exact match
    if query in SSIP_FAQ:
        return SSIP_FAQ[query]
    
    # Try to find a partial match
    for key in SSIP_FAQ:
        if key in query or query in key:
            return SSIP_FAQ[key]
    
    # If no match found, return default response
    return SSIP_FAQ["default"]

@app.route('/chat-widget')
def chat_widget():
    return render_template('chat-widget.html')

@app.route('/')
def demo():
    return render_template('widget-demo.html')

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        user_message = data.get('message', '')
        session_id = session.get('session_id', os.urandom(16).hex())
        session['session_id'] = session_id

        # First try the fallback system
        fallback_response = get_fallback_response(user_message)

        # If OpenAI API is not configured, use fallback response
        if not openai.api_key or openai.api_key == 'sk-xxxxxxxxxxxxxxxxxxxxx':
            return jsonify({
                'response': fallback_response,
                'success': True
            })

        # Try OpenAI API
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.7,
                max_tokens=500
            )

            bot_response = response.choices[0].message.content

            # Save to database
            chat_message = ChatMessage(
                user_message=user_message,
                bot_response=bot_response,
                session_id=session_id
            )
            db.session.add(chat_message)
            db.session.commit()

            return jsonify({
                'response': bot_response,
                'success': True
            })

        except (openai.error.AuthenticationError, 
                openai.error.RateLimitError, 
                openai.error.APIError):
            # Use fallback response if OpenAI API fails
            return jsonify({
                'response': fallback_response,
                'success': True
            })

    except Exception as e:
        print(f"Error in chat endpoint: {str(e)}")
        # Use default fallback response for any other errors
        return jsonify({
            'response': SSIP_FAQ["default"],
            'success': True
        })

@app.route('/chat-history')
def chat_history():
    session_id = session.get('session_id')
    if not session_id:
        return jsonify([])
    
    messages = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.timestamp).all()
    history = [{
        'user_message': msg.user_message,
        'bot_response': msg.bot_response,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for msg in messages]
    
    return jsonify(history)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
