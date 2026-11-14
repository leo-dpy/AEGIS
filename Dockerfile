# Stage 1: Build & Serve (Simple setup)
FROM node:18-alpine

# Use production mode
ENV NODE_ENV=production

# Set working directory
WORKDIR /app

# Copy server package files first to leverage build cache
COPY server/package*.json ./server/

# Install only production dependencies
WORKDIR /app/server
RUN npm ci --omit=dev

# Move back to root and copy the rest of the application
WORKDIR /app
COPY server/ ./server/
COPY client/ ./client/

# Change context back to server to run
WORKDIR /app/server

# Port d'écoute (surchargeable avec -e PORT=...)
ENV PORT=3000
EXPOSE 3000

# Ne pas tourner en root dans le conteneur
USER node

# Start application
CMD ["node", "server.js"]
