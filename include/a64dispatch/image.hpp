#pragma once
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace a64dispatch {
using Address = std::uint64_t;
using ByteArray = std::vector<std::uint8_t>;
using Json = nlohmann::ordered_json;
struct AnalysisError : std::runtime_error {
  using std::runtime_error::runtime_error;
};
std::string hex_address(Address value);
Address parse_address(const Json &value);
ByteArray parse_hex(const std::string &value);
std::string hex_bytes(std::span<const std::uint8_t> value);
std::string sha256(std::span<const std::uint8_t> bytes);
ByteArray read_file(const std::filesystem::path &path,
                    std::size_t cap = 256 * 1024 * 1024);
Json parse_document(std::span<const std::uint8_t> bytes);
Json read_document(const std::filesystem::path &path);
void write_document(const std::filesystem::path &path, const Json &value);

struct MemoryRegion {
  Address begin = 0;
  ByteArray bytes;
  std::string label;
  bool readable = true, writable = false, executable = false;
  std::optional<std::uint64_t> source_offset;
  Address end() const;
  bool contains(Address address, std::size_t length = 1) const;
};
struct FunctionSpan {
  Address begin = 0, end = 0;
  std::string label;
};
struct ControlEdge {
  Address source = 0, target = 0;
  bool owned = false;
};
class CodeImage {
public:
  std::vector<MemoryRegion> regions;
  std::vector<FunctionSpan> functions;
  std::vector<ControlEdge> references;
  Address entry = 0;
  bool relocated = false;
  std::string origin;
  void validate() const;
  const MemoryRegion *region_at(Address address, std::size_t length = 1) const;
  const FunctionSpan *function_at(Address address) const;
  std::optional<std::uint64_t> integer(Address address, unsigned width) const;
  std::optional<std::uint32_t> instruction(Address address) const;
  ByteArray read(Address address, std::size_t length) const;
  void replace(Address address, std::span<const std::uint8_t> bytes);
  bool valid_target(Address address) const;
  std::string fingerprint() const;
  Json snapshot() const;
  static CodeImage from_snapshot(const Json &document);
  static CodeImage from_elf(std::span<const std::uint8_t> file);
  static CodeImage from_flat(std::span<const std::uint8_t> file,
                             const Json &mapping);
  static CodeImage load(const std::filesystem::path &path);
};
} // namespace a64dispatch
