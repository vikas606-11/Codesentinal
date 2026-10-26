# CodeSentinal. dashboard — React (Vite) built, served by Nginx.
# Stage 1: build the static SPA.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
# No lockfile committed; install deps (pinned versions in package.json).
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Nginx runtime (unprivileged/rootless — runs as uid 101, port 8080).
FROM nginxinc/nginx-unprivileged:1.27-alpine
# Backend Service name/port, overridable via env at deploy time.
ENV BACKEND_HOST=CodeSentinal.-backend \
    BACKEND_PORT=8080
COPY --from=build /app/dist /usr/share/nginx/html
# Template is rendered with envsubst at container start.
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 8080
# nginx:alpine auto-runs envsubst on /etc/nginx/templates/*.template -> conf.d
CMD ["nginx", "-g", "daemon off;"]
