#!/bin/bash
# libhimitsu Build Configuration Script
# Provides intelligent build management and environment setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# System detection
detect_system() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    case "$os" in
        Linux*)   PLATFORM="linux" ;;
        Darwin*)  PLATFORM="macos" ;;
        FreeBSD*) PLATFORM="freebsd" ;;
        MINGW*)   PLATFORM="windows" ;;
        *)        PLATFORM="unknown" ;;
    esac
    
    case "$arch" in
        x86_64)  ARCH="x64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="arm32" ;;
        *)       ARCH="unknown" ;;
    esac
    
    log_info "Detected platform: $PLATFORM-$ARCH"
}

# Dependency checking
check_dependencies() {
    log_info "Checking build dependencies..."
    
    local missing_deps=()
    
    # Essential tools
    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v ar >/dev/null 2>&1 || missing_deps+=("binutils")
    
    # Optional but recommended
    if ! command -v clang-format >/dev/null 2>&1; then
        log_warn "clang-format not found - code formatting will be unavailable"
    fi
    
    if ! command -v cppcheck >/dev/null 2>&1; then
        log_warn "cppcheck not found - static analysis will be unavailable"
    fi
    
    if ! command -v valgrind >/dev/null 2>&1; then
        log_warn "valgrind not found - memory testing will be unavailable"
    fi
    
    if ! command -v lcov >/dev/null 2>&1; then
        log_warn "lcov not found - coverage reporting will be unavailable"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install the missing dependencies and try again."
        exit 1
    fi
    
    log_success "All required dependencies found"
}

# Environment setup
setup_environment() {
    log_info "Setting up build environment..."
    
    # Export environment variables
    export PROJECT_ROOT
    export BUILD_DIR
    export PLATFORM
    export ARCH
    
    # Create necessary directories
    cd "$BUILD_DIR"
    mkdir -p obj lib bin test examples dist coverage-report
    
    log_success "Build environment ready"
}

# Build configuration
configure_build() {
    local build_type="${1:-release}"
    local makefile="${2:-Makefile.unified}"
    
    log_info "Configuring build (type: $build_type, makefile: $makefile)"
    
    # Validate build type
    case "$build_type" in
        release|debug|coverage)
            ;;
        *)
            log_error "Invalid build type: $build_type"
            echo "Valid types: release, debug, coverage"
            exit 1
            ;;
    esac
    
    # Check if makefile exists
    if [ ! -f "$BUILD_DIR/$makefile" ]; then
        log_error "Makefile not found: $makefile"
        exit 1
    fi
    
    # Set build configuration
    export BUILD_TYPE="$build_type"
    export MAKEFILE="$makefile"
    
    log_success "Build configured: $build_type using $makefile"
}

# Quick build function
quick_build() {
    local target="${1:-all}"
    
    log_info "Starting quick build: $target"
    
    cd "$BUILD_DIR"
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" "$target"
    
    if [ $? -eq 0 ]; then
        log_success "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Full build with tests
full_build() {
    log_info "Starting full build and test cycle"
    
    cd "$BUILD_DIR"
    
    # Clean build
    make -f "$MAKEFILE" clean
    
    # Build libraries
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" all
    
    # Run tests
    if make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" test; then
        log_success "All tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
    
    # Build examples
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" examples
    
    log_success "Full build cycle completed successfully"
}

# Development build
dev_build() {
    log_info "Starting development build"
    
    # Use debug build type for development
    BUILD_TYPE="debug"
    
    cd "$BUILD_DIR"
    
    # Clean and build
    make -f "$MAKEFILE" clean
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" all
    
    # Run unit tests only for faster iteration
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" test-unit
    
    log_success "Development build ready"
}

# Production build
production_build() {
    log_info "Starting production build"
    
    # Use release build type
    BUILD_TYPE="release"
    
    cd "$BUILD_DIR"
    
    # Clean build
    make -f "$MAKEFILE" distclean
    
    # Full build with all optimizations
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" all
    
    # Run full test suite
    make -f "$MAKEFILE" BUILD_TYPE="$BUILD_TYPE" test
    
    # Run static analysis
    if command -v cppcheck >/dev/null 2>&1; then
        make -f "$MAKEFILE" analyze
    fi
    
    # Format code
    if command -v clang-format >/dev/null 2>&1; then
        make -f "$MAKEFILE" format
    fi
    
    # Create distribution
    make -f "$MAKEFILE" dist-source
    make -f "$MAKEFILE" dist-binary
    
    log_success "Production build completed"
}

# CI/CD build
ci_build() {
    log_info "Starting CI/CD build pipeline"
    
    # Run in strict mode
    set -e
    
    cd "$BUILD_DIR"
    
    # Clean environment
    make -f "$MAKEFILE" distclean
    
    # Build all configurations
    for build_type in release debug coverage; do
        log_info "Building $build_type configuration..."
        
        make -f "$MAKEFILE" clean
        make -f "$MAKEFILE" BUILD_TYPE="$build_type" all
        make -f "$MAKEFILE" BUILD_TYPE="$build_type" test
        
        log_success "$build_type build completed"
    done
    
    # Generate coverage report
    make -f "$MAKEFILE" BUILD_TYPE="coverage" test-coverage
    
    # Run static analysis
    if command -v cppcheck >/dev/null 2>&1; then
        make -f "$MAKEFILE" analyze
    fi
    
    # Check code formatting
    if command -v clang-format >/dev/null 2>&1; then
        make -f "$MAKEFILE" format
        if ! git diff --quiet; then
            log_error "Code formatting issues found"
            exit 1
        fi
    fi
    
    log_success "CI/CD pipeline completed successfully"
}

# Show usage
usage() {
    echo "libhimitsu Build Configuration Script"
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup              - Set up build environment"
    echo "  quick [target]     - Quick build (default: all)"
    echo "  dev                - Development build (debug + unit tests)"
    echo "  full               - Full build with all tests"
    echo "  production         - Production build with optimizations"
    echo "  ci                 - CI/CD pipeline build"
    echo "  clean              - Clean build artifacts"
    echo "  info               - Show build information"
    echo "  help               - Show this help"
    echo ""
    echo "Build Types:"
    echo "  release            - Optimized release build (default)"
    echo "  debug              - Debug build with sanitizers"
    echo "  coverage           - Coverage instrumentation build"
    echo ""
    echo "Environment Variables:"
    echo "  BUILD_TYPE         - Build configuration (release|debug|coverage)"
    echo "  MAKEFILE           - Makefile to use (default: Makefile.unified)"
    echo ""
    echo "Examples:"
    echo "  $0 setup           # Set up environment"
    echo "  $0 dev             # Quick development build"
    echo "  $0 quick test      # Build and run tests"
    echo "  $0 production      # Full production build"
    echo "  BUILD_TYPE=debug $0 quick static  # Debug static library"
}

# Show build info
show_info() {
    echo "Build Configuration Information"
    echo "==============================="
    echo "Platform: $PLATFORM-$ARCH"
    echo "Build Type: ${BUILD_TYPE:-release}"
    echo "Makefile: ${MAKEFILE:-Makefile.unified}"
    echo "Project Root: $PROJECT_ROOT"
    echo "Build Dir: $BUILD_DIR"
    echo ""
    echo "Available Makefiles:"
    ls -1 "$BUILD_DIR"/Makefile* 2>/dev/null || echo "  None found"
    echo ""
    echo "Available Targets:"
    cd "$BUILD_DIR"
    make -f "${MAKEFILE:-Makefile.unified}" help 2>/dev/null | grep "^  " || echo "  Help not available"
}

# Main script
main() {
    # Initialize
    detect_system
    
    # Set defaults
    BUILD_TYPE="${BUILD_TYPE:-release}"
    MAKEFILE="${MAKEFILE:-Makefile.unified}"
    
    # Parse command
    case "${1:-help}" in
        setup)
            check_dependencies
            setup_environment
            ;;
        quick)
            setup_environment
            configure_build "$BUILD_TYPE" "$MAKEFILE"
            quick_build "${2:-all}"
            ;;
        dev)
            setup_environment
            configure_build "debug" "$MAKEFILE"
            dev_build
            ;;
        full)
            check_dependencies
            setup_environment
            configure_build "$BUILD_TYPE" "$MAKEFILE"
            full_build
            ;;
        production)
            check_dependencies
            setup_environment
            configure_build "release" "$MAKEFILE"
            production_build
            ;;
        ci)
            check_dependencies
            setup_environment
            configure_build "release" "$MAKEFILE"
            ci_build
            ;;
        clean)
            cd "$BUILD_DIR"
            make -f "${MAKEFILE:-Makefile.unified}" distclean 2>/dev/null || true
            log_success "Build artifacts cleaned"
            ;;
        info)
            show_info
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
