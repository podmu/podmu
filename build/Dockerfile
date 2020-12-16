FROM alpine:latest

# set labels for metadata
LABEL maintainer="Khanh Ngo<khanhngobackend@gmail.com>" \
  name="containers-mutator" \
  description="" \
  summary=""

# set environment variables
ENV BINARY_LOCATION=/usr/local/bin/containers-mutator \
  USER_UID=1001 \
  USER_NAME=containers-mutator

# install containers-mutator binary
COPY build/_output/bin/containers-mutator ${BINARY_LOCATION}

# copy licenses
RUN mkdir /licenses
COPY LICENSE /licenses

# set entrypoint
ENTRYPOINT ["/usr/local/bin/containers-mutator"]

# switch to non-root user
USER ${USER_UID}
