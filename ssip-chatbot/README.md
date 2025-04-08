# SSIP AI Chatbot

## Project Overview
The SSIP (Student Startup and Innovation Policy) AI Chatbot is an intelligent assistant designed to help students, faculty, and administrators navigate the SSIP ecosystem efficiently. This chatbot provides instant, accurate responses to queries about SSIP schemes, funding opportunities, project submissions, deadlines, and related processes.

### Why SSIP Chatbot?
- **24/7 Accessibility**: Provides round-the-clock assistance for SSIP-related queries
- **Consistent Information**: Ensures accurate and standardized responses
- **Reduced Administrative Load**: Minimizes repetitive queries to coordinators
- **Multilingual Support**: Assists students in multiple languages
- **Quick Resolution**: Instant answers to common SSIP questions

### Problems Solved
1. Information Gap: Bridges the knowledge gap between students and SSIP opportunities
2. Time Management: Reduces response time for common queries
3. Resource Optimization: Frees up coordinator time for more complex tasks
4. Accessibility: Makes SSIP information available anytime, anywhere
5. Documentation: Maintains chat logs for improving service quality

### Features
1. **Core Features**
   - Real-time query responses
   - Multilingual support (English, Gujarati)
   - 24/7 availability
   - Context-aware conversations
   - SSIP scheme information

2. **User Features**
   - Chat history
   - File attachment support
   - Voice-to-text input
   - Mobile-responsive interface
   - Save favorite responses

3. **Administrative Features**
   - Admin dashboard
   - Query analytics
   - Knowledge base management
   - User feedback collection
   - Custom response configuration

## Tech Stack
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Backend**: Python Flask
- **AI Engine**: OpenAI GPT-3.5/4
- **Database**: SQLite (for chat logs and user sessions)
- **Deployment**: Render/Vercel
- **Additional Tools**: 
  - Vector Database: ChromaDB
  - Authentication: Flask-Login
  - Session Management: Flask-Session

## Installation
```bash
# Clone the repository
git clone [repository-url]

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Add your OpenAI API key to .env

# Run the application
python app.py
```

## Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
MIT License

## Contact
For any queries regarding this project, please contact [Your Contact Information]
