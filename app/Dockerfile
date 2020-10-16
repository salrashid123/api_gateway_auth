FROM golang:1.14 as build
ENV GO111MODULE=on
WORKDIR /app
ADD . /app
RUN go mod download
RUN export GOBIN=/app/bin && go install server.go

FROM gcr.io/distroless/base
COPY --from=build /app/bin/server /
EXPOSE 8080
ENTRYPOINT ["/server"]