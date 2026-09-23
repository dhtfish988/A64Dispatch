#pragma once
#include <a64dispatch/image.hpp>
namespace a64dispatch {
struct ProcessResult {
  int exit_code = 0;
  ByteArray output, errors;
};
ProcessResult run_process(const std::vector<std::string> &arguments,
                          std::span<const std::uint8_t> input,
                          unsigned timeout_milliseconds = 30000,
                          std::size_t maximum_output = 8 * 1024 * 1024);
class TemporaryDirectory {
public:
  TemporaryDirectory();
  ~TemporaryDirectory();
  TemporaryDirectory(const TemporaryDirectory &) = delete;
  TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;
  const std::filesystem::path &path() const { return path_; }

private:
  std::filesystem::path path_;
};
} // namespace a64dispatch
