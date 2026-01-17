FROM node:18-alpine

# Set working directory to project root
WORKDIR /app

# Copy the entire project context
COPY . .

# Install server dependencies
RUN cd server && npm install --production

# Switch to server directory to run the app
WORKDIR /app/server

# Expose port (Coolify uses 3000 by default)
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
