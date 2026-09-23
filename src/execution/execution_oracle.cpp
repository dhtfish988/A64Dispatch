#include <a64dispatch/execution.hpp>
#include <algorithm>
#include <limits>
#include <memory>
#include <unicorn/unicorn.h>
namespace a64dispatch {
ExecutionResult command_execution(const Json &, const CodeImage &, Address,
                                  std::span<const std::uint8_t>,
                                  const std::vector<DispatchSite> &);
namespace {
void checked(uc_err status, const std::string &operation) {
  if (status != UC_ERR_OK)
    throw AnalysisError(operation + ": " + uc_strerror(status));
}
int machine_register(unsigned reg) {
  if (reg < 29)
    return UC_ARM64_REG_X0 + static_cast<int>(reg);
  if (reg == 29)
    return UC_ARM64_REG_X29;
  if (reg == 30)
    return UC_ARM64_REG_X30;
  if (reg == 31)
    return UC_ARM64_REG_SP;
  throw AnalysisError("invalid machine register");
}
std::uint64_t read_register(uc_engine *engine, unsigned reg) {
  std::uint64_t value = 0;
  checked(uc_reg_read(engine, machine_register(reg), &value), "read register");
  return value;
}
void write_register(uc_engine *engine, unsigned reg, std::uint64_t value) {
  checked(uc_reg_write(engine, machine_register(reg), &value),
          "write register");
}
unsigned register_number(const std::string &name) {
  if (name == "SP")
    return 31;
  if (name.size() < 2 || (name[0] != 'X' && name[0] != 'W'))
    throw AnalysisError("expected a general register name");
  auto number = parse_address(Json(name.substr(1)));
  if (number > 30)
    throw AnalysisError("invalid register number");
  return static_cast<unsigned>(number);
}
Address numeric(const Json &object, const std::string &key, Address fallback) {
  return object.contains(key) ? parse_address(object[key]) : fallback;
}
class NativeCallContext final : public CallContext {
public:
  NativeCallContext(uc_engine *engine, Address heap, Address size,
                    const std::map<Address, unsigned> &permissions)
      : engine_(engine), next_(heap), end_(heap + size),
        permissions_(permissions) {}
  std::uint64_t argument(unsigned index) const override {
    if (index > 7)
      throw AnalysisError("modeled call argument index exceeds X0..X7");
    return read_register(engine_, index);
  }
  ByteArray read(Address pointer, std::size_t length) const override {
    bounds(pointer, length, UC_PROT_READ);
    ByteArray result(length);
    if (length)
      checked(uc_mem_read(engine_, pointer, result.data(), length),
              "modeled memory read");
    return result;
  }
  void write(Address pointer, std::span<const std::uint8_t> bytes) override {
    bounds(pointer, bytes.size(), UC_PROT_WRITE);
    if (!bytes.empty())
      checked(uc_mem_write(engine_, pointer, bytes.data(), bytes.size()),
              "modeled memory write");
  }
  Address allocate(std::size_t length) override {
    if (length > 1024 * 1024)
      throw AnalysisError("modeled allocation limit exceeded");
    const auto extent =
        (std::max<std::size_t>(length, 1) + 15) & ~std::size_t{15};
    if (next_ > end_ || extent > end_ - next_)
      throw AnalysisError("modeled heap is exhausted");
    const auto address = next_;
    next_ += extent;
    allocations_[address] = length;
    return address;
  }
  std::size_t allocation_size(Address pointer) const override {
    auto found = allocations_.find(pointer);
    if (found == allocations_.end())
      throw AnalysisError("modeled allocator does not own this live pointer");
    return found->second;
  }
  void release(Address pointer) override {
    if (allocations_.erase(pointer) != 1)
      throw AnalysisError("invalid or repeated modeled free");
  }
  void return_value(std::uint64_t value) override {
    write_register(engine_, 0, value);
    const auto resume = read_register(engine_, 30);
    checked(uc_reg_write(engine_, UC_ARM64_REG_PC, &resume),
            "return from modeled call");
  }

private:
  void bounds(Address pointer, std::size_t length, unsigned permission) const {
    if (length > 1024 * 1024 ||
        length > std::numeric_limits<Address>::max() - pointer)
      throw AnalysisError("modeled memory access exceeds its bounds");
    if (length == 0)
      return;
    auto page = pointer & ~Address{4095};
    const auto last = (pointer + length - 1) & ~Address{4095};
    for (;;) {
      const auto found = permissions_.find(page);
      if (found == permissions_.end() || !(found->second & permission))
        throw AnalysisError("modeled memory access violates image permissions");
      if (page == last)
        break;
      page += 4096;
    }
  }
  uc_engine *engine_;
  Address next_, end_;
  std::map<Address, std::size_t> allocations_;
  const std::map<Address, unsigned> &permissions_;
};
struct RunContext {
  const CodeImage *image = nullptr;
  const std::vector<DispatchSite> *sites = nullptr;
  ExecutionResult result;
  std::string error;
  std::map<Address, std::uint64_t> live_states;
  NativeCallContext *calls = nullptr;
  const std::map<Address, const CallModel *> *imports = nullptr;
  std::optional<Address> preceding_transfer;
};
void observe(uc_engine *engine, std::uint64_t address, std::uint32_t,
             void *opaque) noexcept {
  auto &context = *static_cast<RunContext *>(opaque);
  try {
    ++context.result.instructions;
    if (context.preceding_transfer) {
      context.result.control_edges[*context.preceding_transfer].insert(address);
      context.preceding_transfer.reset();
    }
    if (context.imports) {
      auto found = context.imports->find(address);
      if (found != context.imports->end()) {
        // A modeled routine did not execute these machine-code bytes. Omitting
        // them from coverage prevents a hook from certifying an edited stub.
        (*found->second)(*context.calls);
        return;
      }
    }
    context.result.executed.insert(address);
    for (const auto &site : *context.sites) {
      auto state_value = [&] {
        auto value =
            read_register(engine, static_cast<unsigned>(site.state_reg));
        if ((site.state_slot && site.state_slot->width == 4) ||
            (site.target_access && (site.target_access->extension == 2 ||
                                    site.target_access->extension == 6)))
          value &= 0xffffffff;
        return value;
      };
      if (site.load_index && address == *site.load_index && site.state_reg >= 0)
        context.live_states[site.branch] = state_value();
      if (site.model == "single_level" && address == site.load_target &&
          site.state_reg >= 0)
        context.live_states[site.branch] = state_value();
    }
    auto word = context.image->instruction(address);
    if (word && (((*word & 0x7c000000) == 0x14000000) ||
                 ((*word & 0xff000010) == 0x54000000) ||
                 ((*word & 0x7e000000) == 0x34000000) ||
                 ((*word & 0x7e000000) == 0x36000000) ||
                 ((*word & 0xfe000000) == 0xd6000000)))
      context.preceding_transfer = address;
    if (word && (*word & 0xfffffc1f) == 0xd61f0000) {
      auto destination = read_register(engine, (*word >> 5) & 31);
      context.result.observations.targets[address].insert(destination);
      if (context.live_states.contains(address))
        context.result.state_targets[address][context.live_states[address]]
            .insert(destination);
    }
  } catch (const std::exception &error) {
    context.error = error.what();
    uc_emu_stop(engine);
  } catch (...) {
    context.error = "unexpected execution observer failure";
    uc_emu_stop(engine);
  }
}
} // namespace
ExecutionOracle::ExecutionOracle(Json specification,
                                 std::shared_ptr<const CallRegistry> registry)
    : specification_(std::move(specification)), registry_(std::move(registry)) {
  if (!registry_)
    throw AnalysisError("execution requires a call-model registry");
  auto backend = specification_.value("backend", std::string("unicorn"));
  if (backend != "unicorn" && backend != "command")
    throw AnalysisError("unknown execution backend");
}
ExecutionResult
ExecutionOracle::run(const CodeImage &image, Address entry,
                     std::span<const std::uint8_t> input,
                     const std::vector<DispatchSite> &sites) const {
  image.validate();
  if (!image.valid_target(entry))
    throw AnalysisError("entry is not an aligned executable address");
  if (input.size() > 1024 * 1024)
    throw AnalysisError("input size exceeds execution limit");
  if (specification_.value("backend", std::string("unicorn")) == "command")
    return command_execution(specification_, image, entry, input, sites);
  auto limit = numeric(specification_, "maximum_instructions", 1000000),
       timeout = numeric(specification_, "timeout_microseconds", 1000000);
  if (!limit || limit > 100000000 || !timeout || timeout > 60000000)
    throw AnalysisError("invalid execution budget");
  uc_engine *raw = nullptr;
  checked(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &raw), "open Unicorn");
  std::unique_ptr<uc_engine, decltype(&uc_close)> engine(raw, uc_close);
  auto layout = specification_.value("memory", Json::object());
  auto stack = numeric(layout, "stack", 0x400000000),
       io = numeric(layout, "io", 0x500000000),
       heap = numeric(layout, "heap", 0x600000000),
       tls = numeric(layout, "tls", 0x700000000),
       sentinel = numeric(layout, "return_address", 0x7fff0000);
  const auto stack_size = numeric(layout, "stack_size", 1024 * 1024),
             io_size = numeric(layout, "io_size", 2 * 1024 * 1024),
             heap_size = numeric(layout, "heap_size", 1024 * 1024),
             tls_size = numeric(layout, "tls_size", 4096),
             stack_offset = numeric(layout, "stack_offset", 256),
             canary_offset = numeric(layout, "canary_offset", 40);
  for (auto size : {stack_size, io_size, heap_size, tls_size})
    if (size < 4096 || size > 64 * 1024 * 1024 || size % 4096)
      throw AnalysisError(
          "helper memory sizes must be page-aligned within 4 KiB..64 MiB");
  for (auto address : {stack, io, heap, tls, sentinel})
    if (address % 4096)
      throw AnalysisError("helper memory bases must be page-aligned");
  if (stack_offset < 16 || stack_offset > stack_size ||
      canary_offset > tls_size - 8)
    throw AnalysisError("stack or TLS setup lies outside its helper mapping");
  std::map<Address, unsigned> pages;
  auto claim = [&](Address begin, Address length, unsigned protection,
                   bool unique) {
    if (length == 0 ||
        begin > std::numeric_limits<Address>::max() - length - 4095)
      throw AnalysisError("execution memory range overflow");
    auto start = begin & ~Address{4095},
         end = (begin + length + 4095) & ~Address{4095};
    for (auto page = start; page < end; page += 4096) {
      if (unique && pages.contains(page))
        throw AnalysisError(
            "execution helper memory overlaps image or another helper");
      pages[page] |= protection;
      if (pages.size() > 131072)
        throw AnalysisError("execution memory limit exceeded");
    }
  };
  for (const auto &region : image.regions)
    claim(region.begin, region.bytes.size(),
          (region.readable ? UC_PROT_READ : 0u) |
              (region.writable ? UC_PROT_WRITE : 0u) |
              (region.executable ? UC_PROT_EXEC : 0u),
          false);
  claim(stack, stack_size, UC_PROT_READ | UC_PROT_WRITE, true);
  claim(io, io_size, UC_PROT_READ | UC_PROT_WRITE, true);
  claim(heap, heap_size, UC_PROT_READ | UC_PROT_WRITE, true);
  claim(tls, tls_size, UC_PROT_READ | UC_PROT_WRITE, true);
  claim(sentinel, 4096, UC_PROT_READ | UC_PROT_EXEC, true);
  std::map<Address, const CallModel *> imports;
  std::set<Address> stub_pages;
  const auto imported = specification_.value("imports", Json::object());
  if (!imported.is_object() || imported.size() > 4096)
    throw AnalysisError("imports requires a bounded name-to-address map");
  std::set<std::string> enabled;
  if (specification_.contains("shims")) {
    const auto &selected = specification_.at("shims");
    if (!selected.is_array() || selected.size() > 4096)
      throw AnalysisError("shims requires a bounded name array");
    for (const auto &name : selected) {
      enabled.insert(name.get<std::string>());
      (void)registry_->lookup(name.get<std::string>());
    }
  }
  for (const auto &[name, value] : imported.items()) {
    if (specification_.contains("shims") && !enabled.contains(name))
      continue;
    const auto address = parse_address(value);
    const auto &model = registry_->lookup(name);
    if (address % 4 || !imports.emplace(address, &model).second)
      throw AnalysisError("modeled imports require unique aligned addresses");
    if (image.region_at(address, 4)) {
      if (!image.valid_target(address))
        throw AnalysisError("modeled import is not executable");
    } else {
      const auto page = address & ~Address{4095};
      if (stub_pages.insert(page).second)
        claim(page, 4096, UC_PROT_READ | UC_PROT_EXEC, true);
    }
  }
  for (auto iterator = pages.begin(); iterator != pages.end();) {
    auto start = iterator->first, end = start + 4096;
    auto protection = iterator->second;
    ++iterator;
    while (iterator != pages.end() && iterator->first == end &&
           iterator->second == protection) {
      end += 4096;
      ++iterator;
    }
    checked(uc_mem_map(raw, start, static_cast<std::size_t>(end - start),
                       protection),
            "map execution memory");
  }
  for (const auto &region : image.regions)
    checked(uc_mem_write(raw, region.begin, region.bytes.data(),
                         region.bytes.size()),
            "load candidate image bytes");
  for (const auto &[address, model] : imports) {
    (void)model;
    const auto stub = instruction_bytes(0xd65f03c0);
    checked(uc_mem_write(raw, address, stub.data(), stub.size()),
            "place modeled call stub");
  }
  auto input_spec = specification_.value("input", Json::object()),
       output_spec = specification_.value("output", Json::object());
  auto input_mode = input_spec.value("mode", std::string("scalar"));
  Address input_pointer = numeric(input_spec, "address", io + 256);
  auto helper_contains = [&](Address address, std::size_t size) {
    return address >= io && address - io <= io_size &&
           size <= io_size - (address - io);
  };
  if (input_mode == "scalar") {
    if (input.size() > 8)
      throw AnalysisError("scalar input exceeds eight bytes");
    std::uint64_t scalar = 0;
    for (std::size_t offset = 0; offset < input.size(); ++offset)
      scalar |= std::uint64_t(input[offset]) << (offset * 8);
    write_register(raw, 0, scalar);
  } else if (input_mode == "bytes" || input_mode == "string") {
    ByteArray bytes(input.begin(), input.end());
    if (input_mode == "string")
      bytes.push_back(0);
    if (!helper_contains(input_pointer, bytes.size()))
      throw AnalysisError("input buffer lies outside configured IO mapping");
    if (!bytes.empty())
      checked(uc_mem_write(raw, input_pointer, bytes.data(), bytes.size()),
              "place input");
    write_register(raw,
                   register_number(
                       input_spec.value("pointer_register", std::string("X0"))),
                   input_pointer);
    if (input_spec.contains("length_register"))
      write_register(raw, register_number(input_spec["length_register"]),
                     input.size());
  } else
    throw AnalysisError("unknown input mode");
  write_register(raw, 31, (stack + stack_size - stack_offset) & ~Address{15});
  write_register(raw, 30, sentinel);
  const auto registers = specification_.value("registers", Json::object());
  for (const auto &[name, value] : registers.items()) {
    const auto number = register_number(name);
    const auto bits = parse_address(value);
    write_register(raw, number,
                   name.starts_with('W') ? bits & 0xffffffff : bits);
  }
  checked(uc_reg_write(raw, UC_ARM64_REG_TPIDR_EL0, &tls), "set TLS");
  auto canary = numeric(layout, "canary", 0x43414e415259);
  const auto canary_bytes = [&] {
    ByteArray bytes(8);
    for (unsigned i = 0; i < 8; ++i)
      bytes[i] = static_cast<std::uint8_t>(canary >> (i * 8));
    return bytes;
  }();
  checked(uc_mem_write(raw, tls + canary_offset, canary_bytes.data(), 8),
          "set canary");
  NativeCallContext calls(raw, heap, heap_size, pages);
  RunContext context{&image, &sites, {}, "", {}, &calls, &imports, {}};
  uc_hook hook = 0;
  checked(uc_hook_add(raw, &hook, UC_HOOK_CODE,
                      reinterpret_cast<void *>(observe), &context, 1, 0),
          "install observer");
  auto status = uc_emu_start(raw, entry, sentinel, timeout,
                             static_cast<std::size_t>(limit));
  if (!context.error.empty())
    throw AnalysisError(context.error);
  checked(status, "execute candidate");
  std::uint64_t final_pc = 0;
  checked(uc_reg_read(raw, UC_ARM64_REG_PC, &final_pc), "read final PC");
  if (final_pc != sentinel)
    throw AnalysisError("execution did not return within its budget");
  context.result.returned = read_register(raw, 0);
  auto output_mode = output_spec.value("mode", std::string("return"));
  if (output_mode == "return") {
    auto size = numeric(output_spec, "size", 8);
    if (size == 0 || size > 8)
      throw AnalysisError("return output size must be 1..8");
    for (unsigned index = 0; index < size; ++index)
      context.result.output.push_back(
          static_cast<std::uint8_t>(context.result.returned >> (index * 8)));
  } else if (output_mode == "bytes" || output_mode == "region" ||
             output_mode == "string") {
    auto pointer =
        output_mode == "region"
            ? numeric(output_spec, "address", input_pointer)
            : read_register(raw, register_number(output_spec.value(
                                     "pointer_register", std::string("X0"))));
    auto size = numeric(output_spec,
                        output_mode == "string" ? "maximum_length" : "length",
                        output_mode == "string" ? 4096 : 0);
    if (size == 0 || size > 1024 * 1024)
      throw AnalysisError("output size limit exceeded");
    bool terminated = output_mode != "string";
    for (std::uint64_t offset = 0; offset < size; ++offset) {
      if (pointer > std::numeric_limits<Address>::max() - offset)
        throw AnalysisError("output pointer overflow");
      std::uint8_t byte = 0;
      checked(uc_mem_read(raw, pointer + offset, &byte, 1), "read output");
      if (output_mode == "string" && byte == 0) {
        terminated = true;
        break;
      }
      context.result.output.push_back(byte);
    }
    if (!terminated)
      throw AnalysisError("unterminated string output");
  } else
    throw AnalysisError("unknown output mode");
  return context.result;
}
Json ExecutionOracle::compare(const CodeImage &pristine,
                              const CodeImage &candidate,
                              const std::vector<DispatchSite> &sites) const {
  auto vectors = specification_.value("known_vectors", Json::array());
  if (!vectors.is_array() || vectors.empty() || vectors.size() > 10000)
    throw AnalysisError("verification requires 1..10000 known vectors");
  Json rows = Json::array();
  bool passed = true;
  for (const auto &vector : vectors) {
    Address entry = vector.contains("entry")
                        ? parse_address(vector["entry"])
                        : parse_address(specification_.at("entry"));
    auto input = parse_hex(vector.at("input"));
    auto expected = parse_hex(vector.at("output"));
    Json row = {{"entry", hex_address(entry)},
                {"input", hex_bytes(input)},
                {"expected", hex_bytes(expected)}};
    try {
      auto local_spec = specification_;
      if (vector.contains("input_spec"))
        local_spec["input"] = vector["input_spec"];
      if (vector.contains("output_spec"))
        local_spec["output"] = vector["output_spec"];
      ExecutionOracle local_oracle(local_spec, registry_);
      auto before = local_oracle.run(pristine, entry, input, sites),
           after = local_oracle.run(candidate, entry, input, sites);
      bool equal = before.output == expected && after.output == expected;
      row["passed"] = equal;
      row["original"] = hex_bytes(before.output);
      row["candidate"] = hex_bytes(after.output);
      row["original_instructions"] = before.instructions;
      row["candidate_instructions"] = after.instructions;
      row["original_observations"] = before.observations.json();
      row["candidate_observations"] = after.observations.json();
      row["original_control_edges"] =
          execution_json(before).at("control_edges");
      row["candidate_control_edges"] =
          execution_json(after).at("control_edges");
      row["original_coverage"] = Json::array();
      for (auto address : before.executed)
        row["original_coverage"].push_back(hex_address(address));
      passed = passed && equal;
    } catch (const std::exception &error) {
      row["passed"] = false;
      row["error"] = error.what();
      passed = false;
    }
    rows.push_back(std::move(row));
  }
  return {{"passed", passed},
          {"original_sha256", pristine.fingerprint()},
          {"candidate_sha256", candidate.fingerprint()},
          {"vectors", rows}};
}
} // namespace a64dispatch
