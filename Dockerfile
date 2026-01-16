FROM node:18-alpine

# Set working directory to project root
WORKDIR /app

# Copy server package configuration first for caching
COPY server/package.json ./server/

# Install server dependencies
RUN cd server && npm install --production

# Copy the server source code
COPY server ./server

# Copy the client source code (files static references depend on this folder existing at ../client)
COPY client ./client

# Switch to server directory to run the app
WORKDIR /app/server

# Expose port (Coolify uses 3000 by default)
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
