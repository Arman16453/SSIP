// Chat Widget Functionality
document.addEventListener('DOMContentLoaded', function() {
    const chatWidget = document.querySelector('.chat-widget');
    const chatButton = document.querySelector('.chat-widget-button');
    const chatClose = document.querySelector('.chat-close');
    const chatForm = document.querySelector('.chat-input-form');
    const chatInput = document.querySelector('.chat-input');
    const chatMessages = document.querySelector('.chat-messages');
    const typingIndicator = document.querySelector('.typing-indicator');

    // Toggle chat widget
    chatButton.addEventListener('click', () => {
        chatWidget.classList.add('active');
        chatButton.style.display = 'none';
        chatInput.focus();
    });

    chatClose.addEventListener('click', () => {
        chatWidget.classList.remove('active');
        chatButton.style.display = 'flex';
    });

    // Handle chat submission
    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const message = chatInput.value.trim();
        if (!message) return;

        // Add user message
        appendMessage('user', message);
        chatInput.value = '';

        // Show typing indicator
        typingIndicator.classList.add('active');

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: message })
            });

            const data = await response.json();
            
            // Hide typing indicator
            typingIndicator.classList.remove('active');

            if (data.success) {
                appendMessage('bot', data.response);
            } else {
                appendMessage('bot', 'Sorry, I encountered an error. Please try again.');
            }
        } catch (error) {
            console.error('Error:', error);
            typingIndicator.classList.remove('active');
            appendMessage('bot', 'Sorry, I encountered an error. Please try again.');
        }

        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
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

    // Format message content
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

    // Add welcome message
    appendMessage('bot', `Hello! I'm your SSIP Assistant. I can help you with:
    • Information about SSIP schemes
    • Funding opportunities
    • Project submission guidelines
    • Important deadlines
    • Application process
    
    How can I assist you today?`);
});
