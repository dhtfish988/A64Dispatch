cmake_minimum_required(VERSION 3.24)
project(A64Dispatch VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(A64DISPATCH_SANITIZE "Enable ASan and UBSan" OFF)
option(A64DISPATCH_FUZZ "Build the libFuzzer entry" OFF)
find_package(nlohmann_json 3.12 REQUIRED)
find_package(yaml-cpp 0.8 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone>=5.0)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn>=2.1)
pkg_check_modules(GCRYPT REQUIRED IMPORTED_TARGET libgcrypt>=1.10)
add_library(a64dispatch src/image/code_image.cpp src/aarch64/instruction_decoder.cpp src/aarch64/constant_tracker.cpp src/analysis/dispatch_survey.cpp src/analysis/transition_classifier.cpp src/analysis/target_resolver.cpp src/report/artifacts.cpp src/execution/execution_oracle.cpp src/rewrite/rewrite_planner.cpp src/rewrite/rewrite_transaction.cpp src/system/process_runner.cpp src/report/artifact_reader.cpp src/execution/command_oracle.cpp)
target_include_directories(a64dispatch PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(a64dispatch PUBLIC cxx_std_20)
target_link_libraries(a64dispatch PUBLIC nlohmann_json::nlohmann_json PRIVATE PkgConfig::GCRYPT PkgConfig::CAPSTONE PkgConfig::UNICORN yaml-cpp::yaml-cpp)
target_compile_options(a64dispatch PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
if(A64DISPATCH_SANITIZE)
 target_compile_options(a64dispatch PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
 target_link_options(a64dispatch PUBLIC -fsanitize=address,undefined)
endif()
add_executable(a64-dispatch app/main.cpp)
target_sources(a64dispatch PRIVATE src/app/analysis_workflow.cpp src/app/regression_expectations.cpp src/app/batch_workflow.cpp)
target_sources(a64dispatch PRIVATE src/execution/call_models.cpp src/execution/trace_source.cpp)
target_sources(a64dispatch PRIVATE src/rewrite/cleanup_proposals.cpp)
target_sources(a64dispatch PRIVATE src/analysis/state_expansion.cpp src/analysis/table_graph.cpp)
target_link_libraries(a64-dispatch PRIVATE a64dispatch)
include(CTest)
if(BUILD_TESTING)
 add_executable(dispatch-core-tests tests/unit/foundation_tests.cpp)
 target_link_libraries(dispatch-core-tests PRIVATE a64dispatch)
 add_test(NAME foundation-contract COMMAND dispatch-core-tests)
 add_executable(dispatch-cleanup-tests tests/unit/cleanup_tests.cpp)
 target_link_libraries(dispatch-cleanup-tests PRIVATE a64dispatch)
 add_test(NAME cleanup-contract COMMAND dispatch-cleanup-tests)
 add_executable(dispatch-graph-tests tests/unit/table_graph.cpp)
 target_link_libraries(dispatch-graph-tests PRIVATE a64dispatch)
 add_test(NAME table-graph-contract COMMAND dispatch-graph-tests)
 add_executable(dispatch-flat-tests tests/unit/flat_mapping.cpp)
 target_link_libraries(dispatch-flat-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-flat-tests a64-dispatch)
 add_test(NAME flat-image-contract COMMAND dispatch-flat-tests $<TARGET_FILE:a64-dispatch>)
endif()
if(BUILD_TESTING)
 find_program(A64DISPATCH_CROSS_CLANG clang HINTS /opt/homebrew/opt/llvm/bin)
 find_program(A64DISPATCH_ELF_LINKER ld.lld HINTS /opt/homebrew/opt/lld/bin)
 if(A64DISPATCH_CROSS_CLANG AND A64DISPATCH_ELF_LINKER)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf
   COMMAND ${A64DISPATCH_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${A64DISPATCH_ELF_LINKER}
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld ${CMAKE_CURRENT_SOURCE_DIR}/samples/dispatch_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf
   DEPENDS samples/dispatch_cases.S samples/layout.ld VERBATIM)
  add_custom_target(dispatch-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf)
  add_executable(dispatch-pipeline-tests tests/integration/sample_pipeline.cpp)
  target_link_libraries(dispatch-pipeline-tests PRIVATE a64dispatch)
  add_dependencies(dispatch-pipeline-tests dispatch-fixtures)
  add_test(NAME sample-pipeline COMMAND dispatch-pipeline-tests ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf)
 endif()
endif()
if(A64DISPATCH_FUZZ)
 target_compile_options(a64dispatch PRIVATE -fsanitize=fuzzer-no-link)
 add_executable(dispatch-fuzz tests/fuzz/analysis_driver.cpp)
 target_compile_options(dispatch-fuzz PRIVATE -fsanitize=fuzzer)
 target_link_options(dispatch-fuzz PRIVATE -fsanitize=fuzzer)
 target_link_libraries(dispatch-fuzz PRIVATE a64dispatch)
endif()

add_executable(a64-oracle-worker tools/oracle_worker.cpp)
target_link_libraries(a64-oracle-worker PRIVATE a64dispatch)
if(BUILD_TESTING AND TARGET dispatch-fixtures)
 add_executable(dispatch-contract-tests tests/integration/contracts.cpp)
 target_link_libraries(dispatch-contract-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-contract-tests dispatch-fixtures a64-oracle-worker)
 add_test(NAME artifact-process-contract COMMAND dispatch-contract-tests ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf $<TARGET_FILE:a64-oracle-worker>)
 add_executable(dispatch-workflow-tests tests/integration/workflow.cpp)
 target_link_libraries(dispatch-workflow-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-workflow-tests dispatch-fixtures a64-dispatch)
 add_test(NAME workflow-contract COMMAND dispatch-workflow-tests ${CMAKE_CURRENT_BINARY_DIR}/dispatch_cases.elf $<TARGET_FILE:a64-dispatch>)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf
  COMMAND ${A64DISPATCH_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${A64DISPATCH_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,copy_roundtrip ${CMAKE_CURRENT_SOURCE_DIR}/samples/call_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf
  DEPENDS samples/call_cases.S samples/layout.ld VERBATIM)
 add_custom_target(call-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf)
 add_executable(dispatch-call-tests tests/integration/call_models.cpp)
 target_link_libraries(dispatch-call-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-call-tests call-fixtures a64-oracle-worker)
 add_test(NAME call-model-contract COMMAND dispatch-call-tests ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf $<TARGET_FILE:a64-oracle-worker>)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf
  COMMAND ${A64DISPATCH_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${A64DISPATCH_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,tree_compact ${CMAKE_CURRENT_SOURCE_DIR}/samples/tree_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf
  DEPENDS samples/tree_cases.S samples/layout.ld VERBATIM)
 add_custom_target(tree-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf)
 add_executable(dispatch-tree-tests tests/integration/tree_pipeline.cpp)
 target_link_libraries(dispatch-tree-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-tree-tests tree-fixtures)
 add_test(NAME tree-pipeline COMMAND dispatch-tree-tests ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf
  COMMAND ${A64DISPATCH_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${A64DISPATCH_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,state_chain ${CMAKE_CURRENT_SOURCE_DIR}/samples/state_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf
  DEPENDS samples/state_cases.S samples/layout.ld VERBATIM)
 add_custom_target(state-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf)
 add_executable(dispatch-state-tests tests/integration/state_pipeline.cpp)
 target_link_libraries(dispatch-state-tests PRIVATE a64dispatch)
 add_dependencies(dispatch-state-tests state-fixtures)
 add_test(NAME state-pipeline COMMAND dispatch-state-tests ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS a64dispatch a64-dispatch a64-oracle-worker
 EXPORT A64DispatchTargets
 ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
 RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY docs integrations licenses examples samples validation
 DESTINATION ${CMAKE_INSTALL_DATADIR}/A64Dispatch
 PATTERN "__pycache__" EXCLUDE)
install(FILES README.md LICENSE THIRD_PARTY_NOTICES.md dependencies.lock.json
 DESTINATION ${CMAKE_INSTALL_DATADIR}/A64Dispatch)
configure_package_config_file(cmake/A64DispatchConfig.cmake.in
 ${CMAKE_CURRENT_BINARY_DIR}/A64DispatchConfig.cmake
 INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/A64Dispatch)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/A64DispatchConfigVersion.cmake
 VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/A64DispatchConfig.cmake
 ${CMAKE_CURRENT_BINARY_DIR}/A64DispatchConfigVersion.cmake
 DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/A64Dispatch)
install(EXPORT A64DispatchTargets NAMESPACE A64Dispatch::
 DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/A64Dispatch)
