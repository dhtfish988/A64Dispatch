#pragma once
#include <a64dispatch/image.hpp>
#include <functional>
#include <map>
#include <memory>
namespace a64dispatch {
class CallContext {
public:
  virtual ~CallContext() = default;
  virtual std::uint64_t argument(unsigned index) const = 0;
  virtual ByteArray read(Address pointer, std::size_t length) const = 0;
  virtual void write(Address pointer, std::span<const std::uint8_t> bytes) = 0;
  virtual Address allocate(std::size_t length) = 0;
  virtual std::size_t allocation_size(Address pointer) const = 0;
  virtual void release(Address pointer) = 0;
  virtual void return_value(std::uint64_t value) = 0;
};
using CallModel = std::function<void(CallContext &)>;
class CallRegistry {
public:
  void define(std::string name, CallModel model);
  const CallModel &lookup(const std::string &name) const;
  static std::shared_ptr<const CallRegistry> standard();

private:
  std::map<std::string, CallModel> models_;
};
} // namespace a64dispatch
