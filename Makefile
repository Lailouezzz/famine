#!/usr/bin/make -f
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
#
# Author : Alan "ale-boud" Le Bouder <ale-boud@student.42lehavre.fr>
#
# Description of source tree :
# └── include
#     └── <header>.h
# └── src
#     └── <compilunit>.c
#
# After compilation :
# - $(OBJDIR) contain all object files and gcc generated dependencies
# - $(OUTDIR) contain the executable
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

# Default target
all: all-famine
bonus: all

# Include vars and msg module
include Makefile.vars Makefile.msg

# ---
# General targets
# ---

# Mostly clean (clean everything but the end result)

clean: 
	$(call rmsg,Removing the object folder ($(OBJDIR)))
	$(call qcmd,$(RM) -rf $(OBJDIR))

mclean: clean

# Clean everything

fclean: clean cleandoc
ifneq ($(OUTDIR),.)
	$(call rmsg,Removing the output binary folder ($(OUTDIR)))
	$(call qcmd,$(RM) -rf $(OUTDIR))
else
	$(call rmsg,Removing the output binary ($(BIN_PATH)))
	$(call qcmd,$(RM) -f $(BIN_PATH))
endif

# Clean libs

cleanlibs: $(LIBS_CLEAN_RULE)
	$(call rmsg,Clean libs ($(LIBS)))

# Fclean libs

fcleanlibs: cleanlibs $(LIBS_FCLEAN_RULE)
	$(call rmsg,Fclean libs ($(LIBS)))

# To original state

mrproper: fclean fcleanlibs cleandoc
	$(call rmsg,Removing the configuration file (Makefile.cfg))
	$(call qcmd,$(RM) -rf Makefile.cfg)

# Remake everything

re: fclean all

# Make the doxygen documentation

all-doc: doc/Doxyfile
	$(call bcmd,doxygen,$<,doxygen $<)

# Clean the doxygen documentation

cleandoc:
	$(call rmsg,Removing the documentation (doc/html doc/man))
	$(call qcmd,$(RM) -rf doc/html doc/man)

docker-build:
	$(call omsg,Building Docker image...)
	$(call bcmd,docker,build,docker build -t $(IMAGE_NAME) -f $(DOCKERFILE) $(DOCKER_BUILD_CONTEXT))

docker-build-no-cache:
	$(call omsg,Building Docker image...)
	$(call bcmd,docker,build,docker build --no-cache -t $(IMAGE_NAME) -f $(DOCKERFILE) $(DOCKER_BUILD_CONTEXT))

docker-run:
	$(call omsg,Running Docker container...)
	$(call qcmd,docker run --rm -it --name $(CONTAINER_NAME) $(IMAGE_NAME))

docker-rm-image:
	$(call rmsg,Removing Docker image...)
	$(call qcmd,docker rmi $(IMAGE_NAME))

.PHONY: all clean mclean fclean cleanlibs fcleanlibs mrproper re all-doc \
	cleandoc bonus docker-build docker-build-no-cache docker-run docker-rm-image

# ---
# Check configuration
# ---

Makefile.cfg:
	$(call emsg,Makefile.cfg missing did you "./configure")
	@exit 1

# ---
# Build targets
# ---

all-famine: $(LIBS_MAKE_RULE) $(BIN_PATH)

# Make the binary

$(BIN_PATH): $(OBJS)
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,ld,$(OBJS),$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LD_LIBS))

# Make objects

$(OBJDIR)/%.c.o: $(SRCDIR)/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) -c $(CFLAGS) -o $@ $<)

# Make xtea 64

$(OBJDIR)/xtea_crypt_64.S.o: stub/packer64/xtea_crypt_64.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) $(ASFLAGS) $< -o $@)

# Make xtea 32

$(OBJDIR)/xtea_crypt_32.S.o: stub/packer32/xtea_crypt_32.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) $(ASFLAGS) $< -o $@)

# Make famine 64

$(OBJDIR)/famine_64.c.o: stub/common/famine.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) -c $(CFLAGS) -o $@ $<)

# Make famine 32

$(OBJDIR)/famine_32.c.o: stub/common/famine.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) -c $(CFLAGS) -o $@ $<)

# Make object resources

$(OBJDIR)/%.res.o: $(RESDIR)/%
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,ld,$<,ld -m $(LD_EMUL) --format=binary -r $< -o $@ -z noexecstack)

# Make the stub64 asm

$(OBJDIR)/stub/64/%.S.o: stub/64/%.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) $< -o $@)

# Make the stub64 C

$(OBJDIR)/stub/64/%.c.o: $(SRCDIR)/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/64/%.c.o: stub/64/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/64/%.c.o: stub/common/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

# Make the stub64.bin

$(OBJDIR)/stub64.o: $(OBJDIR)/stub/64/stub.S.o $(OBJDIR)/stub/64/stub.c.o $(OBJDIR)/stub/64/strings.c.o $(OBJDIR)/stub/64/syscall.c.o $(OBJDIR)/stub/64/elf.c.o $(OBJDIR)/stub/64/elf/elf_reader32.c.o $(OBJDIR)/stub/64/elf/elf_reader64.c.o $(OBJDIR)/stub/64/elf/raw_data_rw.c.o $(OBJDIR)/stub/64/elf_loader.c.o $(OBJDIR)/stub/64/famine.c.o  $(OBJDIR)/stub/64/protect_range.c.o $(OBJDIR)/stub/packer64/xtea_crypt_64.S.o $(OBJDIR)/stub/64/utils/sort.c.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -r -o $@ $^ -z noexecstack)

comma := ,
$(RESDIR)/stub64.bin: $(OBJDIR)/stub64.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -Wl$(comma)--oformat=binary -T stub/64/linker.ld $^ -o $@ -z noexecstack)

# Make the packer64 asm

$(OBJDIR)/stub/packer64/%.S.o: stub/packer64/%.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) $< -o $@)

# Make the packer64 C

$(OBJDIR)/stub/packer64/%.c.o: $(SRCDIR)/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/packer64/%.c.o: stub/packer64/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/packer64/%.c.o: stub/common/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB64) -I$(INCDIR) -c $< -o $@)

# Make the packer64.bin

$(OBJDIR)/packer64.o: $(OBJDIR)/stub/packer64/packer.S.o $(OBJDIR)/stub/packer64/packer.c.o $(OBJDIR)/stub/packer64/strings.c.o $(OBJDIR)/stub/packer64/syscall.c.o $(OBJDIR)/stub/packer64/elf.c.o $(OBJDIR)/stub/packer64/elf/elf_reader32.c.o $(OBJDIR)/stub/packer64/elf/elf_reader64.c.o $(OBJDIR)/stub/packer64/elf/raw_data_rw.c.o $(OBJDIR)/stub/packer64/elf_loader.c.o $(OBJDIR)/stub/packer64/utils.c.o $(OBJDIR)/stub/packer64/xtea_crypt_64.S.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -r -o $@ $^ -z noexecstack)

comma := ,
$(RESDIR)/packer64.bin: $(OBJDIR)/packer64.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -Wl$(comma)--oformat=binary -T stub/packer64/linker.ld $^ -o $@ -z noexecstack)

# Make the stub32 asm

$(OBJDIR)/stub/32/%.S.o: stub/32/%.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) --32 $< -o $@)

# Make the stub32 C

$(OBJDIR)/stub/32/%.c.o: $(SRCDIR)/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/32/%.c.o: stub/32/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/32/%.c.o: stub/common/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

# Make the stub32.bin

$(OBJDIR)/stub32.o: $(OBJDIR)/stub/32/stub.S.o $(OBJDIR)/stub/32/stub.c.o $(OBJDIR)/stub/32/strings.c.o  $(OBJDIR)/stub/32/syscall.c.o $(OBJDIR)/stub/32/elf.c.o $(OBJDIR)/stub/32/elf/elf_reader64.c.o $(OBJDIR)/stub/32/elf/elf_reader32.c.o $(OBJDIR)/stub/32/elf/raw_data_rw.c.o $(OBJDIR)/stub/32/elf_loader.c.o $(OBJDIR)/stub/32/famine.c.o $(OBJDIR)/stub/32/protect_range.c.o $(OBJDIR)/stub/packer32/xtea_crypt_32.S.o  $(OBJDIR)/stub/32/utils/sort.c.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -m32 -r -o $@ $^ -z noexecstack)

$(OBJDIR)/stub32.elf: $(OBJDIR)/stub32.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -m32 -T stub/32/linker.ld $^ -o $@ -z noexecstack)

$(RESDIR)/stub32.bin: $(OBJDIR)/stub32.elf
	$(call bcmd,objcopy,$^,objcopy -O binary $^ $@)

# Make the packer32 asm

$(OBJDIR)/stub/packer32/%.S.o: stub/packer32/%.S
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,as,$<,$(AS) --32 $< -o $@)

# Make the packer32 C

$(OBJDIR)/stub/packer32/%.c.o: $(SRCDIR)/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/packer32/%.c.o: stub/packer32/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

$(OBJDIR)/stub/packer32/%.c.o: stub/common/%.c
	$(call qcmd,$(MKDIR) -p $(@D))
	$(call bcmd,cc,$<,$(CC) $(CFLAGS_STUB32) -I$(INCDIR) -c $< -o $@)

# Make the packer32.bin

$(OBJDIR)/packer32.o: $(OBJDIR)/stub/packer32/packer.S.o $(OBJDIR)/stub/packer32/packer.c.o $(OBJDIR)/stub/packer32/strings.c.o  $(OBJDIR)/stub/packer32/syscall.c.o $(OBJDIR)/stub/packer32/elf.c.o $(OBJDIR)/stub/packer32/elf/elf_reader64.c.o $(OBJDIR)/stub/packer32/elf/elf_reader32.c.o $(OBJDIR)/stub/packer32/elf/raw_data_rw.c.o $(OBJDIR)/stub/packer32/elf_loader.c.o $(OBJDIR)/stub/packer32/xtea_crypt_32.S.o $(OBJDIR)/stub/packer32/utils.c.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -m32 -r -o $@ $^ -z noexecstack)

$(OBJDIR)/packer32.elf: $(OBJDIR)/packer32.o
	$(call bcmd,ld,$^,$(LD) -nostdlib -m32 -T stub/packer32/linker.ld $^ -o $@ -z noexecstack)

$(RESDIR)/packer32.bin: $(OBJDIR)/packer32.elf
	$(call bcmd,objcopy,$^,objcopy -O binary $^ $@)

# Include generated dep by cc

-include $(DEPS)

.PHONY: all-famine norminette

norminette:
	@norminette $(SRCDIR) $(INCDIR) | grep -Ev '^Notice|OK!$$'	\
	&& $(ECHO) -e '\033[1;31mNorminette KO!'					\
	|| $(ECHO) -e '\033[1;32mNorminette OK!'
