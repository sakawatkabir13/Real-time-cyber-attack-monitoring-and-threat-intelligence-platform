FROM node:20-alpine AS builder
WORKDIR /app
# Bound the build heap on small shared VPS hosts; the runtime is still Nginx.
ARG NODE_OPTIONS="--max-old-space-size=512"
ENV NODE_OPTIONS=${NODE_OPTIONS}
COPY package*.json .
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx-spa.conf /etc/nginx/conf.d/default.conf
