#!/bin/bash

#GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC=mipsel-linux-gnu-gcc CGO_LDFLAGS="-Xlinker -rpath=/home/niklas/GolandProjects/gopacket_analysis/mips-libs -static" go build -o mips -ldflags="-L /home/niklas/GolandProjects/gopacket_analysis/mips-libs/"
GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC=mipsel-linux-gnu-gcc CGO_LDFLAGS="-Xlinker -rpath=gopacket_analysis/mips-libs -static" go build -o mips