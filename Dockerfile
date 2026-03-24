FROM docker.1ms.run/ubuntu:24.04

WORKDIR /app

COPY build/tftp_server .

RUN mkdir -p /tftp

EXPOSE 69/udp

#VOLUME ["tftp"]

CMD ["/app/tftp_server", "/tftp"]
