# Build stage
FROM node:20-alpine AS build
WORKDIR /app

# Accept build arguments for environment variables
ARG VITE_OIDC_AUTHORITY
ARG VITE_OIDC_CLIENT_ID
ARG VITE_OIDC_SCOPE
ARG VITE_REDIRECT_URI
ARG VITE_POST_LOGOUT_REDIRECT_URI

# Set environment variables for build
ENV VITE_OIDC_AUTHORITY=${VITE_OIDC_AUTHORITY}
ENV VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID}
ENV VITE_OIDC_SCOPE=${VITE_OIDC_SCOPE}
ENV VITE_REDIRECT_URI=${VITE_REDIRECT_URI}
ENV VITE_POST_LOGOUT_REDIRECT_URI=${VITE_POST_LOGOUT_REDIRECT_URI}

# Copy package files
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . ./

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# Remove default nginx files
RUN rm -rf ./*

# Copy built application
COPY --from=build /app/dist .

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Run nginx
CMD ["nginx", "-g", "daemon off;"]
