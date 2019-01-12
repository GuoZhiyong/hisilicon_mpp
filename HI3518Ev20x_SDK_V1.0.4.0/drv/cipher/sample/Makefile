ifeq ($(PARAM_FILE), )
        PARAM_FILE:=../../../mpp/Makefile.param
        include $(PARAM_FILE)
endif

SRC_ROOT :=$(PWD)

INC_FLAGS := -I$(SRC_ROOT)/../include -I./ -I$(SRC_ROOT)/../src -I$(SRC_ROOT)/../src/api

CFLAGS := -Wall -g $(INC_FLAGS) -lpthread

CFLAGS += -DCHIP_TYPE_$(HIARCH)

LIBA := $(SRC_ROOT)/../src/libhi_cipher.a

SRC  := $(wildcard *.c)
HEAD := $(wildcard *.h)
OBJ  := $(SRC:%.c=%)

COMPILE=$(CC) $(CFLAGS) -o "$(*F)" "$<" $(LIBA)

% : %.c
	@$(COMPILE)


.PHONY : clean all

all: $(OBJ) $(HEAD)
	@echo 

clean:
	@rm -f $(OBJ)
