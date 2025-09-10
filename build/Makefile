#!/usr/bin/make -f
# libhimitsu Primary Makefile
# Delegates to the unified build system

# Default to unified Makefile
UNIFIED_MAKEFILE := Makefile.unified

# Check if unified makefile exists
ifeq (,$(wildcard $(UNIFIED_MAKEFILE)))
    $(error Unified Makefile not found: $(UNIFIED_MAKEFILE))
endif

# Pass all targets to unified makefile
%:
	@$(MAKE) -f $(UNIFIED_MAKEFILE) $@

# Special targets that need to be handled here
.PHONY: help
help:
	@echo "libhimitsu Build System"
	@echo "======================"
	@echo ""
	@echo "This Makefile delegates to the unified build system."
	@echo "For detailed help, use: make -f $(UNIFIED_MAKEFILE) help"
	@echo ""
	@echo "Quick commands:"
	@echo "  make           - Build everything"
	@echo "  make test      - Run tests"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make install   - Install library"
	@echo ""
	@echo "Advanced usage:"
	@echo "  ./build-master.sh    - Auto-detect best build system"
	@echo "  ./build.sh          - Advanced build configurations"
	@echo ""

# Default target
.DEFAULT_GOAL := all
