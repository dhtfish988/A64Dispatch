#pragma once
#include <a64dispatch/analysis.hpp>
#include <a64dispatch/call_models.hpp>
namespace a64dispatch {
Json collect_external_trace(const CodeImage &image, const Json &configuration);
struct ExecutionResult {
  ByteArray output;
  std::uint64_t returned = 0, instructions = 0;
  ObservationSet observations;
  std::set<Address> executed;
  std::map<Address, std::set<Address>> control_edges;
  std::map<Address, std::map<std::uint64_t, std::set<Address>>> state_targets;
};
Json execution_json(const ExecutionResult &result);
ExecutionResult execution_from_json(const Json &record, const CodeImage &image);
class ExecutionOracle {
public:
  explicit ExecutionOracle(
      Json specification,
      std::shared_ptr<const CallRegistry> registry = CallRegistry::standard());
  ExecutionResult run(const CodeImage &image, Address entry,
                      std::span<const std::uint8_t> input,
                      const std::vector<DispatchSite> &sites = {}) const;
  Json compare(const CodeImage &pristine, const CodeImage &candidate,
               const std::vector<DispatchSite> &sites = {}) const;

private:
  Json specification_;
  std::shared_ptr<const CallRegistry> registry_;
};
} // namespace a64dispatch
