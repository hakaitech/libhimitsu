#!/bin/bash
# libhimitsu Master Build Script
# Automatically detects and uses the best available build system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect available build systems
detect_build_systems() {
    local systems=()
    
    # Check for CMake
    if command -v cmake >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/CMakeLists.txt" ]; then
        systems+=("cmake")
    fi
    
    # Check for unified Makefile
    if command -v make >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Makefile.unified" ]; then
        systems+=("make-unified")
    fi
    
    # Check for simple Makefile
    if command -v make >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Makefile.simple" ]; then
        systems+=("make-simple")
    fi
    
    # Check for standard Makefile
    if command -v make >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Makefile" ]; then
        systems+=("make")
    fi
    
    echo "${systems[@]}"
}

# Choose the best build system
choose_build_system() {
    local systems=($1)
    local preference=("cmake" "make-unified" "make" "make-simple")
    
    for preferred in "${preference[@]}"; do
        for available in "${systems[@]}"; do
            if [ "$preferred" = "$available" ]; then
                echo "$preferred"
                return
            fi
        done
    done
    
    # If no preferred system found, return first available
    echo "${systems[0]}"
}

# Build with CMake
build_cmake() {
    local target="${1:-all}"
    local build_type="${2:-Release}"
    
    log_info "Building with CMake (type: $build_type, target: $target)"
    
    # Create build directory
    local cmake_build_dir="$SCRIPT_DIR/cmake-build-$(echo "$build_type" | tr '[:upper:]' '[:lower:]')"
    mkdir -p "$cmake_build_dir"
    cd "$cmake_build_dir"
    
    # Configure
    cmake .. \
        -DCMAKE_BUILD_TYPE="$build_type" \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=ON \
        -DBUILD_TESTS=ON \
        -DBUILD_EXAMPLES=ON
    
    # Build
    case "$target" in
        all|build)
            cmake --build . --parallel $(nproc 2>/dev/null || echo 4)
            ;;
        test)
            cmake --build . --target all --parallel $(nproc 2>/dev/null || echo 4)
            ctest --output-on-failure
            ;;
        install)
            cmake --build . --target all --parallel $(nproc 2>/dev/null || echo 4)
            cmake --install .
            ;;
        clean)
            cmake --build . --target clean
            ;;
        *)
            cmake --build . --target "$target" --parallel $(nproc 2>/dev/null || echo 4)
            ;;
    esac
    
    log_success "CMake build completed"
}

# Build with unified Makefile
build_make_unified() {
    local target="${1:-all}"
    local build_type="${2:-release}"
    
    log_info "Building with unified Makefile (type: $build_type, target: $target)"
    
    cd "$SCRIPT_DIR"
    make -f Makefile.unified BUILD_TYPE="$build_type" "$target" -j$(nproc 2>/dev/null || echo 4)
    
    log_success "Unified Makefile build completed"
}

# Build with simple Makefile
build_make_simple() {
    local target="${1:-all}"
    
    log_info "Building with simple Makefile (target: $target)"
    
    cd "$SCRIPT_DIR"
    make -f Makefile.simple "$target" -j$(nproc 2>/dev/null || echo 4)
    
    log_success "Simple Makefile build completed"
}

# Build with standard Makefile
build_make() {
    local target="${1:-all}"
    
    log_info "Building with standard Makefile (target: $target)"
    
    cd "$SCRIPT_DIR"
    make "$target" -j$(nproc 2>/dev/null || echo 4)
    
    log_success "Standard Makefile build completed"
}

# Clean all build artifacts
clean_all() {
    log_info "Cleaning all build artifacts..."
    
    cd "$SCRIPT_DIR"
    
    # Clean CMake builds
    rm -rf cmake-build-* CMakeCache.txt CMakeFiles/
    
    # Clean Make builds
    for makefile in Makefile Makefile.simple Makefile.unified; do
        if [ -f "$makefile" ]; then
            make -f "$makefile" clean 2>/dev/null || true
            make -f "$makefile" distclean 2>/dev/null || true
        fi
    done
    
    # Clean common artifacts
    rm -rf obj lib bin test examples dist coverage-report
    rm -f *.o *.a *.so *.so.* *.dylib *.dll
    rm -f test_* basic_usage node_implementation
    rm -f *.gcov *.gcda *.gcno coverage.info
    
    log_success "All build artifacts cleaned"
}

# Show build status
show_status() {
    local systems=($(detect_build_systems))
    local chosen=$(choose_build_system "${systems[*]}")
    
    echo "libhimitsu Build Status"
    echo "======================"
    echo "Available build systems: ${systems[*]}"
    echo "Recommended system: $chosen"
    echo "Project root: $PROJECT_ROOT"
    echo "Build directory: $SCRIPT_DIR"
    echo ""
    
    # Show available targets for each system
    for system in "${systems[@]}"; do
        echo "Targets for $system:"
        case "$system" in
            cmake)
                echo "  all, test, install, clean, format, analyze"
                ;;
            make-unified)
                echo "  all, static, shared, debug, test, examples, install, clean, format, analyze"
                ;;
            make-simple)
                echo "  all, static, shared, test, examples, clean"
                ;;
            make)
                echo "  all, static, shared, debug, test, examples, install, clean"
                ;;
        esac
        echo ""
    done
}

# Main function
main() {
    local systems=($(detect_build_systems))
    
    if [ ${#systems[@]} -eq 0 ]; then
        log_error "No build systems available!"
        echo "Please ensure you have either cmake or make installed."
        exit 1
    fi
    
    local build_system=$(choose_build_system "${systems[*]}")
    local command="${1:-build}"
    local target="${2:-all}"
    local build_type="${BUILD_TYPE:-Release}"
    
    # Convert make build types to CMake format
    case "$build_type" in
        release) build_type="Release" ;;
        debug) build_type="Debug" ;;
        coverage) build_type="Debug" ;;
    esac
    
    case "$command" in
        build|make)
            case "$build_system" in
                cmake) build_cmake "$target" "$build_type" ;;
                make-unified) build_make_unified "$target" "${BUILD_TYPE:-release}" ;;
                make-simple) build_make_simple "$target" ;;
                make) build_make "$target" ;;
            esac
            ;;
        test)
            case "$build_system" in
                cmake) build_cmake "test" "$build_type" ;;
                make-unified) build_make_unified "test" "${BUILD_TYPE:-release}" ;;
                make-simple) build_make_simple "test" ;;
                make) build_make "test" ;;
            esac
            ;;
        clean)
            if [ "$target" = "all" ]; then
                clean_all
            else
                case "$build_system" in
                    cmake) build_cmake "clean" "$build_type" ;;
                    make-unified) build_make_unified "clean" "${BUILD_TYPE:-release}" ;;
                    make-simple) build_make_simple "clean" ;;
                    make) build_make "clean" ;;
                esac
            fi
            ;;
        install)
            case "$build_system" in
                cmake) build_cmake "install" "$build_type" ;;
                make-unified) build_make_unified "install" "${BUILD_TYPE:-release}" ;;
                make) build_make "install" ;;
                make-simple) 
                    log_error "Simple Makefile doesn't support install target"
                    exit 1
                    ;;
            esac
            ;;
        status|info)
            show_status
            ;;
        help|--help|-h)
            echo "libhimitsu Master Build Script"
            echo "Usage: $0 [COMMAND] [TARGET] [OPTIONS]"
            echo ""
            echo "Commands:"
            echo "  build [target]   - Build the project (default)"
            echo "  test             - Build and run tests"
            echo "  clean [all]      - Clean build artifacts"
            echo "  install          - Install the library"
            echo "  status           - Show build system status"
            echo "  help             - Show this help"
            echo ""
            echo "Common targets:"
            echo "  all              - Build everything"
            echo "  static           - Build static library"
            echo "  shared           - Build shared library"
            echo "  examples         - Build examples"
            echo ""
            echo "Environment variables:"
            echo "  BUILD_TYPE       - Build type (release/debug/coverage)"
            echo ""
            echo "Examples:"
            echo "  $0 build all                    # Build everything"
            echo "  $0 test                         # Run tests"
            echo "  BUILD_TYPE=debug $0 build       # Debug build"
            echo "  $0 clean all                    # Clean everything"
            ;;
        *)
            # Treat unknown commands as targets
            case "$build_system" in
                cmake) build_cmake "$command" "$build_type" ;;
                make-unified) build_make_unified "$command" "${BUILD_TYPE:-release}" ;;
                make-simple) build_make_simple "$command" ;;
                make) build_make "$command" ;;
            esac
            ;;
    esac
}

# Run main function
main "$@"
