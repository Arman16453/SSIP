// Chat functionality
const chatForm = document.getElementById('chatForm');
const userInput = document.getElementById('userInput');
const chatMessages = document.getElementById('chatMessages');
const loadingSpinner = document.getElementById('loadingSpinner');

let isVoiceInputActive = false;
let recognition = null;

// Initialize speech recognition
if ('webkitSpeechRecognition' in window) {
    recognition = new webkitSpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';

    recognition.onresult = function(event) {
        const transcript = event.results[0][0].transcript;
        userInput.value = transcript;
        toggleVoiceInput(); // Turn off voice input
        chatForm.dispatchEvent(new Event('submit')); // Submit the form
    };

    recognition.onerror = function(event) {
        console.error('Speech recognition error:', event.error);
        toggleVoiceInput(); // Turn off voice input
    };
}

// Handle chat form submission
chatForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const message = userInput.value.trim();
    if (!message) return;

    // Add user message to chat
    appendMessage('user', message);
    userInput.value = '';

    // Show loading spinner
    loadingSpinner.classList.remove('d-none');

    try {
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });

        const data = await response.json();
        
        if (data.success) {
            appendMessage('bot', data.response);
        } else {
            appendMessage('bot', 'Sorry, I encountered an error. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        appendMessage('bot', 'Sorry, I encountered an error. Please try again.');
    } finally {
        loadingSpinner.classList.add('d-none');
    }
});

// Append a message to the chat
function appendMessage(sender, content) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${sender}-message`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.innerHTML = formatMessage(content);
    
    messageDiv.appendChild(contentDiv);
    chatMessages.appendChild(messageDiv);
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Format message content (convert URLs to links, etc.)
function formatMessage(content) {
    // Convert URLs to clickable links
    content = content.replace(
        /(https?:\/\/[^\s]+)/g, 
        '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>'
    );
    
    // Convert line breaks to <br>
    content = content.replace(/\n/g, '<br>');
    
    return content;
}

// Toggle voice input
function toggleVoiceInput() {
    if (!recognition) {
        alert('Speech recognition is not supported in your browser.');
        return;
    }

    const voiceButton = document.querySelector('button[onclick="toggleVoiceInput()"]');
    
    if (!isVoiceInputActive) {
        recognition.start();
        isVoiceInputActive = true;
        voiceButton.classList.add('voice-active');
        userInput.placeholder = 'Listening...';
    } else {
        recognition.stop();
        isVoiceInputActive = false;
        voiceButton.classList.remove('voice-active');
        userInput.placeholder = 'Type your message...';
    }
}

// Start a new chat
function newChat() {
    chatMessages.innerHTML = '';
    // Add welcome message
    appendMessage('bot', `Hello! I'm your SSIP AI Assistant. I can help you with:
    <ul>
        <li>Information about SSIP schemes</li>
        <li>Funding opportunities</li>
        <li>Project submission guidelines</li>
        <li>Important deadlines</li>
        <li>Application process</li>
    </ul>
    How can I assist you today?`);
}

// Download chat history
async function downloadHistory() {
    try {
        const response = await fetch('/chat-history');
        const history = await response.json();
        
        let csvContent = 'data:text/csv;charset=utf-8,';
        csvContent += 'Timestamp,User Message,Bot Response\n';
        
        history.forEach(msg => {
            csvContent += `${msg.timestamp},"${msg.user_message.replace(/"/g, '""')}","${msg.bot_response.replace(/"/g, '""')}"\n`;
        });
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement('a');
        link.setAttribute('href', encodedUri);
        link.setAttribute('download', 'chat_history.csv');
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        console.error('Error downloading history:', error);
        alert('Error downloading chat history. Please try again.');
    }
}
