FROM node:8-alpine

RUN npm config set registry http://registry.npm.taobao.org/
RUN mkdir /app
WORKDIR /app
COPY ./package.json /app/package.json
RUN npm install
COPY . /app
RUN npm run build

CMD [ "npm", "run", "server" ]
