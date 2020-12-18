ARG IMAGE_NAME_DEFAULT=podmu

FROM golang:1.15-alpine AS build-env

ARG IMAGE_NAME_DEFAULT
ENV CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  IMAGE_NAME=${IMAGE_NAME_DEFAULT}

WORKDIR $GOPATH/src/github.com/podmu/podmu
COPY . .

RUN mkdir -p ./build/_output/bin && CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} \
  go build -o ./build/_output/bin/${IMAGE_NAME} ./cmd/ && \
  cp ./build/_output/bin/${IMAGE_NAME} /${IMAGE_NAME} && \
  cp ./LICENSE /licenses

# =============================================================================
FROM alpine:latest

ARG IMAGE_NAME_DEFAULT

# set labels for metadata
LABEL maintainer="Khanh Ngo<khanhngobackend@gmail.com>" \
  name="podmu" \
  description="" \
  summary=""

# set environment variables
ENV USER_UID=1001 \
  USER_NAME=podmu \
  IMAGE_NAME=${IMAGE_NAME_DEFAULT}
  
ENV BINARY_LOCATION=/usr/local/bin/${IMAGE_NAME}

# install podmu binary
COPY --from=build-env /${IMAGE_NAME} ${BINARY_LOCATION}
RUN chmod +x ${BINARY_LOCATION} && ${BINARY_LOCATION} --help

# copy licenses
RUN mkdir /licenses
COPY --from=build-env /licenses /licenses

# set entrypoint
ENTRYPOINT ["/usr/local/bin/podmu"]

# switch to non-root user
USER ${USER_UID}
