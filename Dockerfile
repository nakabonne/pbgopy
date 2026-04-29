FROM alpine

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/pbgopy /usr/bin/
CMD ["pbgopy"]
