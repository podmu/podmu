FROM alpine:latest

# set labels for metadata
LABEL maintainer="Khanh Ngo<khanhngobackend@gmail.com>" \
  name="podmu" \
  description="" \
  summary=""

# set environment variables
ENV BINARY_LOCATION=/usr/local/bin/podmu \
  USER_UID=1001 \
  USER_NAME=podmu

# install podmu binary
COPY build/_output/bin/podmu ${BINARY_LOCATION}
RUN chmod +x ${BINARY_LOCATION} && ${BINARY_LOCATION} --help

# copy licenses
RUN mkdir /licenses
COPY LICENSE /licenses

# set entrypoint
ENTRYPOINT ["/usr/local/bin/podmu"]

# switch to non-root user
USER ${USER_UID}
