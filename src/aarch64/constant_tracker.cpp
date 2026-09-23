#include <a64dispatch/instruction.hpp>
#include <algorithm>
#include <limits>
namespace a64dispatch {
namespace {
std::uint64_t width_mask(unsigned width) {
  return width == 64 ? ~std::uint64_t{0} : 0xffffffff;
}
void merge_producers(ConstantValue &value, const ConstantValue &other) {
  value.producers.insert(value.producers.end(), other.producers.begin(),
                         other.producers.end());
  std::sort(value.producers.begin(), value.producers.end());
  value.producers.erase(
      std::unique(value.producers.begin(), value.producers.end()),
      value.producers.end());
}
} // namespace
ConstantTracker::ConstantTracker(const CodeImage &image,
                                 const InstructionDecoder &decoder,
                                 unsigned window, unsigned depth)
    : image_(image), decoder_(decoder), window_(window), depth_(depth) {
  if (window == 0 || window > 4096 || depth == 0 || depth > 64)
    throw AnalysisError("invalid constant-analysis budget");
}
std::optional<Address> ConstantTracker::producer(Address use,
                                                 unsigned reg) const {
  if (reg > 30 || use % 4)
    return {};
  const auto *region = image_.region_at(use);
  if (!region && use >= 4)
    region = image_.region_at(use - 4);
  if (!region)
    return {};
  Address lower = region->begin;
  const auto *function = image_.function_at(use);
  if (function)
    lower = std::max(lower, function->begin);
  for (const auto &edge : image_.references)
    if (edge.target >= lower && edge.target <= use &&
        edge.source + 4 != edge.target)
      lower = edge.target;
  Address cursor = use;
  for (unsigned distance = 0; distance < window_ && cursor >= 4; ++distance) {
    cursor -= 4;
    if (cursor < lower)
      break;
    auto word = image_.instruction(cursor);
    if (!word)
      return {};
    auto instruction = decoder_.decode(cursor, *word);
    if (!instruction.valid)
      return {};
    if (instruction.control_transfer) {
      if (instruction.call && !instruction.writes(reg))
        continue;
      return {};
    }
    if (instruction.writes(reg))
      return cursor;
    if (std::any_of(image_.references.begin(), image_.references.end(),
                    [&](const auto &edge) {
                      return edge.target == cursor && edge.source != cursor - 4;
                    }))
      return {};
  }
  return {};
}
std::optional<ConstantValue> ConstantTracker::resolve(Address use, unsigned reg,
                                                      unsigned width) const {
  if (reg > 31 || (width != 32 && width != 64))
    return {};
  unsigned budget = 4096;
  return derive(use, reg, width, depth_, budget);
}
std::optional<ConstantValue> ConstantTracker::derive(Address use, unsigned reg,
                                                     unsigned width,
                                                     unsigned depth,
                                                     unsigned &budget) const {
  if (budget == 0 || depth == 0)
    return {};
  --budget;
  if (reg == 31)
    return ConstantValue{{0}, {}, {}, {}};
  auto location = producer(use, reg);
  if (!location)
    return {};
  auto word = image_.instruction(*location);
  if (!word)
    return {};
  auto instruction = decoder_.decode(*location, *word);
  if (instruction.destination != static_cast<int>(reg))
    return {};
  auto mask = width_mask(instruction.width);
  ConstantValue output;
  output.producers.push_back(*location);
  auto previous = [&](int source) -> std::optional<ConstantValue> {
    if (source < 0 || source > 31)
      return {};
    return derive(*location, static_cast<unsigned>(source), instruction.width,
                  depth - 1, budget);
  };
  auto constant = [&](std::uint64_t number) {
    return ConstantValue{{number & mask}, {}, {}, {}};
  };
  std::optional<ConstantValue> left, right;
  switch (instruction.operation) {
  case Operation::move_zero:
    output.values = {*instruction.immediate & mask};
    break;
  case Operation::move_not:
    output.values = {(~*instruction.immediate) & mask};
    break;
  case Operation::address:
  case Operation::page_address:
    if (!instruction.target)
      return {};
    output.values = {*instruction.target};
    break;
  case Operation::move_keep: {
    left = previous(static_cast<int>(reg));
    if (!left)
      return {};
    output = *left;
    auto field = std::uint64_t{0xffff} << instruction.shift;
    for (auto &value : output.values)
      value = ((value & ~field) | *instruction.immediate) & mask;
    output.producers.push_back(*location);
    break;
  }
  case Operation::move_register: {
    left = previous(instruction.left);
    if (!left)
      return {};
    output = *left;
    output.producers.push_back(*location);
    break;
  }
  case Operation::select:
  case Operation::select_increment:
  case Operation::select_invert:
  case Operation::select_negate: {
    left = previous(instruction.left);
    right = previous(instruction.right);
    if (!left || !right || !left->singleton() || !right->singleton() ||
        instruction.condition >= 14)
      return {};
    auto first = left->values[0], second = right->values[0];
    if (instruction.operation == Operation::select_increment)
      ++second;
    else if (instruction.operation == Operation::select_invert)
      second = ~second;
    else if (instruction.operation == Operation::select_negate)
      second = 0 - second;
    output.values = {first & mask, second & mask};
    output.condition = instruction.condition;
    output.selection = *location;
    merge_producers(output, *left);
    merge_producers(output, *right);
    break;
  }
  case Operation::add:
  case Operation::subtract:
  case Operation::bit_and:
  case Operation::bit_or:
  case Operation::bit_xor: {
    // Register 31 denotes SP, not ZR, in add/sub immediate encodings.
    if ((instruction.operation == Operation::add ||
         instruction.operation == Operation::subtract) &&
        instruction.immediate && instruction.left == 31)
      return {};
    left = previous(instruction.left);
    right = instruction.immediate
                ? std::optional<ConstantValue>(constant(*instruction.immediate))
                : previous(instruction.right);
    if (!left || !right)
      return {};
    if (left->condition && right->condition &&
        (left->condition != right->condition ||
         left->selection != right->selection))
      return {};
    auto count = std::max(left->values.size(), right->values.size());
    if (count == 0 || count > 2)
      return {};
    output.condition = left->condition ? left->condition : right->condition;
    output.selection = left->selection ? left->selection : right->selection;
    for (std::size_t index = 0; index < count; ++index) {
      auto a = left->values[left->singleton() ? 0 : index],
           b = right->values[right->singleton() ? 0 : index];
      if (!instruction.immediate && instruction.shift) {
        if (instruction.shift >= instruction.width)
          return {};
        if (instruction.shift_kind == 0)
          b = (b << instruction.shift) & mask;
        else if (instruction.shift_kind == 1)
          b >>= instruction.shift;
        else
          return {};
      }
      if (instruction.operation == Operation::add)
        output.values.push_back((a + b) & mask);
      else if (instruction.operation == Operation::subtract)
        output.values.push_back((a - b) & mask);
      else if (instruction.operation == Operation::bit_and)
        output.values.push_back((a & b) & mask);
      else if (instruction.operation == Operation::bit_or)
        output.values.push_back((a | b) & mask);
      else
        output.values.push_back((a ^ b) & mask);
    }
    merge_producers(output, *left);
    merge_producers(output, *right);
    break;
  }
  case Operation::bitfield: {
    left = previous(instruction.left);
    if (!left)
      return {};
    auto rotate = instruction.shift, ones = instruction.bit_index,
         bits = instruction.width;
    if (rotate >= bits || ones >= bits)
      return {};
    output = *left;
    for (auto &value : output.values) {
      if (instruction.shift_kind == 2) {
        if (ones >= rotate) {
          auto size = ones - rotate + 1;
          auto keep =
              size == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << size) - 1;
          value = (value >> rotate) & keep;
        } else {
          auto keep = (std::uint64_t{1} << (ones + 1)) - 1;
          value = ((value & keep) << (bits - rotate)) & mask;
        }
      } else if (instruction.shift_kind == 0 && ones >= rotate) {
        auto size = ones - rotate + 1;
        auto keep =
            size == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << size) - 1;
        value = (value >> rotate) & keep;
        if (size < 64 && (value & (std::uint64_t{1} << (size - 1))))
          value |= ~keep;
        value &= mask;
      } else
        return {};
    }
    output.producers.push_back(*location);
    break;
  }
  default:
    return {};
  }
  for (auto &value : output.values)
    value &= width_mask(width) & mask;
  if (output.values.size() == 2 && output.values[0] == output.values[1]) {
    output.values.resize(1);
    output.condition.reset();
    output.selection.reset();
  }
  return output;
}
} // namespace a64dispatch
