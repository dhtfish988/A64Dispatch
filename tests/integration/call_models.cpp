#include <a64dispatch/execution.hpp>
#include <a64dispatch/process.hpp>
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <limits>
using namespace a64dispatch;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &name) {
  if (value)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
template <class F> void rejects(F action, const std::string &name) {
  try {
    action();
    check(false, name);
  } catch (const AnalysisError &) {
    check(true, name);
  }
}
class ModelMemory final : public CallContext {
public:
  ByteArray memory = ByteArray(262144, 0);
  std::uint64_t arguments[8] = {};
  std::uint64_t returned = 0;
  Address next = 0x20000;
  std::map<Address, std::size_t> live;
  std::uint64_t argument(unsigned n) const override { return arguments[n]; }
  ByteArray read(Address p, std::size_t n) const override {
    if (p > memory.size() || n > memory.size() - p)
      throw AnalysisError("unmapped model memory");
    return {memory.begin() + static_cast<std::ptrdiff_t>(p),
            memory.begin() + static_cast<std::ptrdiff_t>(p + n)};
  }
  void write(Address p, std::span<const std::uint8_t> b) override {
    if (p > memory.size() || b.size() > memory.size() - p)
      throw AnalysisError("unmapped model memory");
    std::copy(b.begin(), b.end(),
              memory.begin() + static_cast<std::ptrdiff_t>(p));
  }
  Address allocate(std::size_t n) override {
    auto p = next;
    next += std::max<std::size_t>(n, 16);
    if (next > memory.size())
      throw AnalysisError("heap exhausted");
    live[p] = n;
    return p;
  }
  std::size_t allocation_size(Address p) const override {
    if (!live.contains(p))
      throw AnalysisError("invalid allocation");
    return live.at(p);
  }
  void release(Address p) override {
    if (!live.erase(p))
      throw AnalysisError("invalid free");
  }
  void return_value(std::uint64_t v) override { returned = v; }
  void word(Address p, std::uint64_t v, unsigned width = 8) {
    for (unsigned i = 0; i < width; ++i)
      memory.at(p + i) = static_cast<std::uint8_t>(v >> (8 * i));
  }
  void text(Address p, const std::string &s) {
    write(p, {reinterpret_cast<const std::uint8_t *>(s.c_str()), s.size() + 1});
  }
  std::string text(Address p) const {
    std::string s;
    for (; memory.at(p); ++p)
      s.push_back(static_cast<char>(memory.at(p)));
    return s;
  }
  void invoke(const std::string &name,
              std::initializer_list<std::uint64_t> args) {
    std::fill(std::begin(arguments), std::end(arguments), 0);
    std::copy(args.begin(), args.end(), arguments);
    CallRegistry::standard()->lookup(name)(*this);
  }
};
Address named(const CodeImage &i, const std::string &n) {
  for (const auto &f : i.functions)
    if (f.label == n)
      return f.begin;
  throw AnalysisError("missing fixture symbol: " + n);
}
ByteArray bytes(const std::string &s) { return {s.begin(), s.end()}; }
} // namespace
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  try {
    ModelMemory memory;
    memory.text(0x1000, "abcdefgh");
    for (const auto &name :
         {"memcpy", "memmove", "__memcpy_chk", "__memmove_chk"}) {
      memory.invoke(name, {0x1100, 0x1000, 9, 9});
      check(memory.text(0x1100) == "abcdefgh" && memory.returned == 0x1100,
            "copy model: " + std::string(name));
    }
    memory.invoke("memmove", {0x1002, 0x1000, 6});
    check(memory.text(0x1000) == "ababcdef",
          "overlapping move stages its input");
    rejects([&] { memory.invoke("__memcpy_chk", {0x1100, 0x1000, 9, 8}); },
            "checked copy rejects insufficient destination");
    for (const auto &name : {"memset", "__memset_chk"}) {
      memory.invoke(name, {0x1100, 'Z', 4, 4});
      check(memory.read(0x1100, 4) == bytes("ZZZZ"),
            "fill model: " + std::string(name));
    }
    rejects([&] { memory.invoke("__memset_chk", {0x1100, 0, 5, 4}); },
            "checked fill enforces object bound");
    memory.text(0x1200, "hello");
    memory.text(0x1300, "help");
    memory.invoke("strlen", {0x1200});
    check(memory.returned == 5, "strlen terminates at zero");
    memory.invoke("strcmp", {0x1200, 0x1300});
    check(static_cast<std::int64_t>(memory.returned) == -4,
          "strcmp reports unsigned-byte difference");
    memory.invoke("strncmp", {0x1200, 0x1300, 3});
    check(memory.returned == 0, "strncmp obeys count");
    memory.invoke("strncmp", {std::numeric_limits<std::uint64_t>::max(), 0, 0});
    check(memory.returned == 0, "zero-length compare reads no memory");
    rejects([&] { memory.invoke("strlen", {0x50000}); },
            "invalid string pointer is not silently accepted");
    memory.invoke("malloc", {8});
    auto old = memory.returned;
    memory.write(old, bytes("12345678"));
    memory.invoke("realloc", {old, 16});
    auto grown = memory.returned;
    check(memory.read(grown, 8) == bytes("12345678") &&
              !memory.live.contains(old),
          "realloc preserves min old/new size and retires old block");
    memory.invoke("realloc", {grown, 4});
    auto shrunk = memory.returned;
    check(memory.read(shrunk, 4) == bytes("1234"),
          "realloc shrink copies bounded prefix");
    memory.invoke("free", {shrunk});
    check(!memory.live.contains(shrunk), "free retires allocation");
    rejects([&] { memory.invoke("free", {shrunk}); },
            "double-free is explicit failure");
    memory.invoke("free", {0});
    check(memory.returned == 0, "free null is accepted");
    memory.invoke("calloc", {4, 8});
    check(memory.read(memory.returned, 32) == ByteArray(32, 0),
          "calloc zeroes complete allocation");
    rejects(
        [&] {
          memory.invoke("calloc",
                        {std::numeric_limits<std::uint64_t>::max(), 16});
        },
        "calloc multiplication overflow rejected");
    rejects([&] { memory.invoke("memcpy", {0x1000, 0x1100, 1024 * 1024 + 1}); },
            "copy bounded before allocating buffer");
    for (const auto &name : {"pthread_mutex_lock", "pthread_mutex_unlock"}) {
      memory.invoke(name, {0});
      check(memory.returned == 0, "explicit single-thread mutex model");
    }
    for (const auto &name : {"abort", "__stack_chk_fail"})
      rejects([&] { memory.invoke(name, {}); },
              "terminating model throws instead of returning");
    // AAPCS64 register save area followed by stack arguments. Compare integer
    // and string formatting against the host C library on the same independent
    // data.
    const std::string pattern = "%+06d %#x %.3s %llu %c %p %%";
    memory.text(0x3000, pattern);
    memory.text(0x4000, "abcdef");
    memory.word(0x2000, 0x6000);
    memory.word(0x2008, 0x5020);
    memory.word(0x2018, 0xffffffe0, 4);
    memory.word(0x5000, static_cast<std::uint64_t>(-42));
    memory.word(0x5008, 0xab);
    memory.word(0x5010, 0x4000);
    memory.word(0x5018, 0x123456789abcdef0ULL);
    memory.word(0x6000, 'Q');
    memory.word(0x6008, 0x1234);
    char reference[256];
    std::snprintf(reference, sizeof(reference), pattern.c_str(), -42, 0xab,
                  "abcdef", 0x123456789abcdef0ULL, 'Q',
                  reinterpret_cast<void *>(0x1234));
    memory.invoke("__vsprintf_chk", {0x1000, 0, 256, 0x3000, 0x2000});
    check(memory.text(0x1000) == reference &&
              memory.returned == std::string(reference).size(),
          "checked format matches native snprintf across register and stack "
          "va_list");
    memory.invoke("__vsnprintf_chk", {0x1100, 8, 0, 256, 0x3000, 0x2000});
    check(memory.text(0x1100) == std::string(reference).substr(0, 7) &&
              memory.returned == std::string(reference).size(),
          "bounded format truncates with NUL but returns full length");
    memory.memory[0x1100] = 0x7e;
    memory.invoke("__vsnprintf_chk", {0x1100, 0, 0, 0, 0x3000, 0x2000});
    check(memory.memory[0x1100] == 0x7e &&
              memory.returned == std::string(reference).size(),
          "zero-capacity snprintf writes no byte");
    rejects(
        [&] {
          memory.invoke("__vsprintf_chk", {0x1000, 0, 2, 0x3000, 0x2000});
        },
        "checked unbounded format rejects object overflow");
    rejects(
        [&] {
          memory.invoke("__vsnprintf_chk", {0x1000, 8, 0, 4, 0x3000, 0x2000});
        },
        "snprintf requested capacity cannot exceed object size");
    memory.text(0x3000, "%n");
    rejects(
        [&] {
          memory.invoke("__vsprintf_chk", {0x1000, 0, 256, 0x3000, 0x2000});
        },
        "unsupported percent-n is explicit failure");
    memory.word(0x2018, 0xfffffffe, 4);
    memory.text(0x3000, "%d");
    rejects(
        [&] {
          memory.invoke("__vsprintf_chk", {0x1000, 0, 256, 0x3000, 0x2000});
        },
        "misaligned va_list rejected");
    rejects([&] { CallRegistry::standard()->lookup("missing"); },
            "unknown modeled call is explicit failure");
    // Real independently assembled instructions use the native Unicorn import
    // hook.
    const auto image = CodeImage::load(argv[1]);
    Json imports = Json::object();
    for (const auto &name : {"malloc", "memcpy", "memset", "calloc", "realloc",
                             "free", "strlen", "strcmp", "strncmp", "abort"})
      imports[name] =
          hex_address(named(image, "imported_" + std::string(name)));
    imports["__memcpy_chk"] =
        hex_address(named(image, "imported_memcpy_checked"));
    imports["__vsprintf_chk"] = hex_address(named(image, "imported_printf"));
    imports["__vsnprintf_chk"] = hex_address(named(image, "imported_snprintf"));
    Json spec = {{"imports", imports},
                 {"input", {{"mode", "string"}}},
                 {"output", {{"mode", "return"}}}};
    ExecutionOracle oracle(spec);
    check(oracle.run(image, named(image, "copy_roundtrip"), bytes("ABCDEFGH"))
                  .output == bytes("ABCDEFGH"),
          "machine code calls malloc/copy/realloc/free and returns preserved "
          "data");
    check(oracle.run(image, named(image, "calloc_zero"), {}).returned == 0,
          "machine code observes zeroed allocation");
    check(oracle.run(image, named(image, "string_length"), bytes("hello"))
                  .returned == 5,
          "native import hook strlen");
    check(static_cast<std::int64_t>(
              oracle.run(image, named(image, "compare_strings"), bytes("abc"))
                  .returned) == -1,
          "native import hook strcmp");
    check(oracle.run(image, named(image, "limited_compare"), bytes("abc"))
                  .returned == 0,
          "native import hook strncmp");
    check(oracle.run(image, named(image, "canary_value"), {}).returned ==
              0x43414e415259ULL,
          "TLS canary is initialized independently");
    auto filled = spec;
    filled["output"] = {{"mode", "bytes"}, {"length", 4}};
    check(ExecutionOracle(filled)
                  .run(image, named(image, "fill_buffer"), bytes("aaaa"))
                  .output == bytes("ZZZZ"),
          "native memset output buffer");
    for (const auto &name :
         {"checked_copy_bad", "abort_path", "copy_to_readonly"})
      rejects([&] { oracle.run(image, named(image, name), bytes("abcdefgh")); },
              "native call failure propagated: " + std::string(name));
    auto coverage =
        oracle.run(image, named(image, "string_length"), bytes("hello"));
    check(!coverage.executed.contains(named(image, "imported_strlen")),
          "modeled stub is not falsely counted as executed candidate bytes");
    auto registered = std::make_shared<CallRegistry>(*CallRegistry::standard());
    registered->define("custom", [](CallContext &ctx) {
      ctx.return_value(ctx.argument(0) + 100);
    });
    Json custom = {
        {"imports",
         {{"custom", hex_address(named(image, "imported_custom"))}}}};
    check(ExecutionOracle(custom, registered)
                  .run(image, named(image, "custom_call"), ByteArray{7})
                  .returned == 107,
          "native library supports a caller-supplied model registry");
    rejects(
        [&] {
          ExecutionOracle(custom).run(image, named(image, "custom_call"),
                                      ByteArray{7});
        },
        "custom import is not silently treated as a builtin");
    auto narrow = spec;
    narrow["memory"] = {{"stack_size", 4096},
                        {"io_size", 4096},
                        {"heap_size", 4096},
                        {"tls_size", 4096},
                        {"canary", 123}};
    check(ExecutionOracle(narrow)
                  .run(image, named(image, "canary_value"), {})
                  .returned == 123,
          "configurable helper sizes and canary");
    auto invalid = narrow;
    invalid["memory"]["canary_offset"] = 4092;
    rejects([&] { ExecutionOracle(invalid).run(image, image.entry, {}); },
            "TLS canary cannot cross mapping");
    invalid = narrow;
    invalid["memory"]["stack_size"] = 123;
    rejects([&] { ExecutionOracle(invalid).run(image, image.entry, {}); },
            "misaligned helper size rejected");
    // The separately running command backend receives the same import contract.
    auto external = spec;
    external["backend"] = "command";
    external["command"] = Json::array({argv[2]});
    check(ExecutionOracle(external)
                  .run(image, named(image, "copy_roundtrip"), bytes("ABCDEFGH"))
                  .output == bytes("ABCDEFGH"),
          "command worker executes candidate with native call models");
    ModelMemory layout;
    constexpr Address input_base = 0x500000100;
    layout.text(0x3000, "%d/%s/%x");
    layout.text(0x4000, "abc");
    layout.word(0x2000, input_base + 0x6000);
    layout.word(0x2008, input_base + 0x5018);
    layout.word(0x2018, 0xffffffe8, 4);
    layout.word(0x5000, 42);
    layout.word(0x5008, input_base + 0x4000);
    layout.word(0x5010, 0xab);
    const auto payload = layout.read(0, 0x7000);
    auto formatted = spec;
    formatted["input"] = {{"mode", "bytes"},
                          {"address", hex_address(input_base)}};
    formatted["output"] = {{"mode", "string"}, {"pointer_register", "X19"}};
    formatted["registers"] = {{"X0", hex_address(input_base + 0x10000)},
                              {"X1", 0},
                              {"X2", 128},
                              {"X3", hex_address(input_base + 0x3000)},
                              {"X4", hex_address(input_base + 0x2000)},
                              {"X19", hex_address(input_base + 0x10000)}};
    auto formatted_result = ExecutionOracle(formatted).run(
        image, named(image, "printf_call"), payload);
    check(formatted_result.output == bytes("42/abc/ab") &&
              formatted_result.returned == 9,
          "real AArch64 call uses PCS va_list and checked formatting model");
    formatted["registers"]["X1"] = 6;
    formatted["registers"]["X2"] = 0;
    formatted["registers"]["X3"] = 128;
    formatted["registers"]["X4"] = hex_address(input_base + 0x3000);
    formatted["registers"]["X5"] = hex_address(input_base + 0x2000);
    formatted_result = ExecutionOracle(formatted).run(
        image, named(image, "snprintf_call"), payload);
    check(formatted_result.output == bytes("42/ab") &&
              formatted_result.returned == 9,
          "real AArch64 snprintf call truncates while retaining full length");
    auto narrow_register = custom;
    narrow_register["registers"] = {{"W0", "0x100000007"}};
    check(ExecutionOracle(narrow_register, registered)
                  .run(image, named(image, "custom_call"), {})
                  .returned == 107,
          "explicit W-register initialization clears upper bits");
    std::cout << passed << " call-model checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
