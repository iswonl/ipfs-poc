# Build Stage
FROM node:14.19.1-slim

WORKDIR /application
COPY ./ /application/

RUN yarn

EXPOSE 3000
CMD ["yarn", "dev", "--host", "0.0.0.0"]