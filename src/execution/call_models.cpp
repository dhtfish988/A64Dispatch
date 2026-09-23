#include <a64dispatch/call_models.hpp>
#include <algorithm>
#include <charconv>
#include <limits>
namespace a64dispatch {
namespace {
constexpr std::size_t limit = 1024 * 1024;
std::size_t bounded(std::uint64_t value) {
  if (value > limit)
    throw AnalysisError("modeled libc call exceeds its memory limit");
  return static_cast<std::size_t>(value);
}
Address offset(Address pointer, std::uint64_t distance) {
  if (distance > std::numeric_limits<Address>::max() - pointer)
    throw AnalysisError("modeled pointer overflow");
  return pointer + distance;
}
std::uint64_t integer(CallContext &context, Address pointer, unsigned width) {
  auto bytes = context.read(pointer, width);
  std::uint64_t result = 0;
  for (unsigned index = 0; index < width; ++index)
    result |= std::uint64_t(bytes.at(index)) << (index * 8);
  return result;
}
std::string string(CallContext &context, Address pointer,
                   std::size_t maximum = limit, bool precision = false) {
  std::string result;
  for (std::size_t index = 0; index < maximum; ++index) {
    auto byte = context.read(offset(pointer, index), 1).at(0);
    if (byte == 0)
      return result;
    result.push_back(static_cast<char>(byte));
  }
  if (precision)
    return result;
  throw AnalysisError("modeled string is unterminated within its limit");
}
void copy(CallContext &context, bool checked) {
  auto destination = context.argument(0), source = context.argument(1);
  auto count = bounded(context.argument(2));
  if (checked && count > context.argument(3))
    throw AnalysisError("checked memory copy exceeds destination size");
  context.write(destination, context.read(source, count));
  context.return_value(destination);
}
void fill(CallContext &context, bool checked) {
  auto destination = context.argument(0);
  auto count = bounded(context.argument(2));
  if (checked && count > context.argument(3))
    throw AnalysisError("checked memory fill exceeds destination size");
  context.write(destination, ByteArray(count, static_cast<std::uint8_t>(
                                                  context.argument(1))));
  context.return_value(destination);
}
void compare(CallContext &context, bool length_limited) {
  auto first = context.argument(0), second = context.argument(1);
  const auto count = length_limited ? bounded(context.argument(2)) : limit;
  for (std::size_t index = 0; index < count; ++index) {
    auto a = context.read(offset(first, index), 1).at(0),
         b = context.read(offset(second, index), 1).at(0);
    if (a != b || a == 0) {
      const auto difference = static_cast<std::int64_t>(a) - b;
      context.return_value(static_cast<std::uint64_t>(difference));
      return;
    }
  }
  if (!length_limited)
    throw AnalysisError("modeled comparison has no terminator");
  context.return_value(0);
}
class VariadicReader {
public:
  VariadicReader(CallContext &context, Address list) : context_(context) {
    stack_ = integer(context, list, 8);
    top_ = integer(context, offset(list, 8), 8);
    auto bits = integer(context, offset(list, 24), 4);
    available_ = static_cast<std::int64_t>(bits & 0x7fffffff) -
                 static_cast<std::int64_t>(bits & 0x80000000);
    if (available_ < -64 || available_ > 0 || available_ % 8 || stack_ % 8 ||
        top_ % 8)
      throw AnalysisError("invalid AArch64 PCS general-register va_list");
  }
  std::uint64_t next() {
    Address address;
    if (available_ < 0) {
      const auto distance = static_cast<std::uint64_t>(-available_);
      if (top_ < distance)
        throw AnalysisError("variadic register-save pointer underflow");
      address = top_ - distance;
      available_ += 8;
    } else {
      address = stack_;
      stack_ = offset(stack_, 8);
    }
    return integer(context_, address, 8);
  }

private:
  CallContext &context_;
  Address stack_ = 0, top_ = 0;
  std::int64_t available_ = 0;
};
std::string digits(std::uint64_t value, unsigned radix, bool upper) {
  char buffer[65];
  auto conversion = std::to_chars(buffer, buffer + sizeof(buffer), value,
                                  static_cast<int>(radix));
  if (conversion.ec != std::errc())
    throw AnalysisError("integer formatting failed");
  std::string result(buffer, conversion.ptr);
  if (upper)
    for (auto &character : result)
      if (character >= 'a' && character <= 'f')
        character -= 'a' - 'A';
  return result;
}
void format(CallContext &context, bool length_limited) {
  const auto destination = context.argument(0),
             capacity = context.argument(length_limited ? 3 : 2),
             maximum = length_limited ? context.argument(1) : capacity;
  if (length_limited && maximum > capacity)
    throw AnalysisError("checked formatting exceeds object capacity");
  if (maximum != std::numeric_limits<std::uint64_t>::max())
    bounded(maximum);
  const auto pattern =
      string(context, context.argument(length_limited ? 4 : 3), 4096);
  VariadicReader arguments(context, context.argument(length_limited ? 5 : 4));
  std::string output;
  auto append = [&](const std::string &part) {
    if (part.size() > limit - output.size())
      throw AnalysisError("formatted output limit exceeded");
    output += part;
  };
  for (std::size_t cursor = 0; cursor < pattern.size();) {
    if (pattern[cursor] != '%') {
      append(pattern.substr(cursor++, 1));
      continue;
    }
    ++cursor;
    if (cursor < pattern.size() && pattern[cursor] == '%') {
      append("%");
      ++cursor;
      continue;
    }
    bool left = false, plus = false, space = false, alternate = false,
         zero = false;
    for (; cursor < pattern.size(); ++cursor) {
      const auto flag = pattern[cursor];
      if (flag == '-')
        left = true;
      else if (flag == '+')
        plus = true;
      else if (flag == ' ')
        space = true;
      else if (flag == '#')
        alternate = true;
      else if (flag == '0')
        zero = true;
      else
        break;
    }
    auto number = [&]() {
      unsigned result = 0;
      while (cursor < pattern.size() && pattern[cursor] >= '0' &&
             pattern[cursor] <= '9') {
        result = result * 10 + static_cast<unsigned>(pattern[cursor++] - '0');
        if (result > 65536)
          throw AnalysisError("format width or precision limit exceeded");
      }
      return result;
    };
    auto width = number();
    std::optional<unsigned> precision;
    if (cursor < pattern.size() && pattern[cursor] == '.') {
      ++cursor;
      precision = number();
    }
    unsigned bits = 32;
    if (cursor < pattern.size() && pattern[cursor] == 'h') {
      ++cursor;
      bits = 16;
      if (cursor < pattern.size() && pattern[cursor] == 'h') {
        ++cursor;
        bits = 8;
      }
    } else if (cursor < pattern.size() &&
               (pattern[cursor] == 'l' || pattern[cursor] == 'j' ||
                pattern[cursor] == 'z' || pattern[cursor] == 't')) {
      const auto length = pattern[cursor++];
      bits = 64;
      if (length == 'l' && cursor < pattern.size() && pattern[cursor] == 'l')
        ++cursor;
    }
    if (cursor == pattern.size())
      throw AnalysisError("unterminated format conversion");
    const auto conversion = pattern[cursor++];
    if (std::string("diouxXscp").find(conversion) == std::string::npos)
      throw AnalysisError(
          "unsupported conversion in modeled integer/string formatting");
    auto value = arguments.next();
    std::string prefix, body;
    if (conversion == 's')
      body = string(context, value, precision ? *precision : limit,
                    precision.has_value());
    else if (conversion == 'c')
      body.push_back(static_cast<char>(value & 0xff));
    else {
      if (conversion == 'p')
        bits = 64;
      if (bits < 64)
        value &= (std::uint64_t{1} << bits) - 1;
      const bool signed_value = conversion == 'd' || conversion == 'i';
      const bool negative =
          signed_value && (value & (std::uint64_t{1} << (bits - 1)));
      if (negative) {
        prefix = "-";
        value = ~value + 1;
        if (bits < 64)
          value &= (std::uint64_t{1} << bits) - 1;
      } else if (signed_value && plus)
        prefix = "+";
      else if (signed_value && space)
        prefix = " ";
      const auto radix =
          conversion == 'o'                                             ? 8u
          : conversion == 'x' || conversion == 'X' || conversion == 'p' ? 16u
                                                                        : 10u;
      body = digits(value, radix, conversion == 'X');
      if (precision && *precision == 0 && value == 0)
        body.clear();
      if (precision && *precision > body.size())
        body.insert(0, *precision - body.size(), '0');
      if (conversion == 'p' || (alternate && radix == 16 && value))
        prefix += conversion == 'X' ? "0X" : "0x";
      else if (alternate && radix == 8 && (body.empty() || body.front() != '0'))
        prefix += "0";
    }
    const auto padding = width > prefix.size() + body.size()
                             ? width - prefix.size() - body.size()
                             : 0;
    if (!left && zero && !precision && conversion != 's' && conversion != 'c')
      body.insert(0, padding, '0');
    else if (left)
      body.append(padding, ' ');
    else
      prefix.insert(0, padding, ' ');
    append(prefix + body);
  }
  if (!length_limited && output.size() + 1 > capacity)
    throw AnalysisError("checked formatting would overflow destination");
  const auto count =
      maximum == 0 ? 0 : std::min<std::uint64_t>(output.size(), maximum - 1);
  if (maximum != 0) {
    ByteArray bytes(output.begin(),
                    output.begin() + static_cast<std::ptrdiff_t>(count));
    bytes.push_back(0);
    context.write(destination, bytes);
  }
  context.return_value(output.size());
}
} // namespace
void CallRegistry::define(std::string name, CallModel model) {
  if (name.empty() || name.size() > 256 || !model)
    throw AnalysisError("invalid modeled call registration");
  models_.insert_or_assign(std::move(name), std::move(model));
}
const CallModel &CallRegistry::lookup(const std::string &name) const {
  auto found = models_.find(name);
  if (found == models_.end())
    throw AnalysisError("unregistered imported call: " + name);
  return found->second;
}
std::shared_ptr<const CallRegistry> CallRegistry::standard() {
  static const auto models = [] {
    auto result = std::make_shared<CallRegistry>();
    for (const auto &name : {"memcpy", "memmove"})
      result->define(name, [](CallContext &context) { copy(context, false); });
    for (const auto &name : {"__memcpy_chk", "__memmove_chk"})
      result->define(name, [](CallContext &context) { copy(context, true); });
    result->define("memset",
                   [](CallContext &context) { fill(context, false); });
    result->define("__memset_chk",
                   [](CallContext &context) { fill(context, true); });
    result->define("strlen", [](CallContext &context) {
      context.return_value(string(context, context.argument(0)).size());
    });
    result->define("strcmp",
                   [](CallContext &context) { compare(context, false); });
    result->define("strncmp",
                   [](CallContext &context) { compare(context, true); });
    result->define("malloc", [](CallContext &context) {
      context.return_value(context.allocate(bounded(context.argument(0))));
    });
    result->define("calloc", [](CallContext &context) {
      auto count = context.argument(0), size = context.argument(1);
      if (size && count > limit / size)
        throw AnalysisError("calloc size overflow or limit exceeded");
      const auto length = bounded(count * size);
      auto pointer = context.allocate(length);
      context.write(pointer, ByteArray(length, 0));
      context.return_value(pointer);
    });
    result->define("realloc", [](CallContext &context) {
      auto old = context.argument(0);
      auto length = bounded(context.argument(1));
      if (length == 0 && old) {
        context.release(old);
        context.return_value(0);
        return;
      }
      auto previous =
          old ? context.read(old,
                             std::min(length, context.allocation_size(old)))
              : ByteArray{};
      auto pointer = context.allocate(length);
      context.write(pointer, previous);
      if (old)
        context.release(old);
      context.return_value(pointer);
    });
    result->define("free", [](CallContext &context) {
      if (context.argument(0))
        context.release(context.argument(0));
      context.return_value(0);
    });
    for (const auto &name : {"pthread_mutex_lock", "pthread_mutex_unlock"})
      result->define(name,
                     [](CallContext &context) { context.return_value(0); });
    result->define("__vsprintf_chk",
                   [](CallContext &context) { format(context, false); });
    result->define("__vsnprintf_chk",
                   [](CallContext &context) { format(context, true); });
    for (const auto &name : {"abort", "__stack_chk_fail"})
      result->define(name, [name](CallContext &) {
        throw AnalysisError(std::string("execution stopped by ") + name);
      });
    return result;
  }();
  return models;
}
} // namespace a64dispatch
