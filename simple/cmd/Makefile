ARCH=$(shell uname -m)

TARGET := main
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a

.PHONY: all
all: $(TARGET) $(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET) 

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-g -O2 -c -target bpf \
		-o $@ $<

#	clang -g -O2 -Wall -emit-llvm -c main.bpf.c -o - | \
    	llc -march=bpf -mcpu=probe -filetype=obj -o main.bpf.o

#	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-g -O1 -c -target bpf \
		-o $@ $<



#	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		 -g -O2 -c -target bpf \
		-o $@ $<		

#	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean:
	go clean
