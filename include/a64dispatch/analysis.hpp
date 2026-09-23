#pragma once
#include <a64dispatch/instruction.hpp>
#include <map>
#include <set>
namespace a64dispatch {
struct AnalysisSettings {
  unsigned lookback = 128, maximum_targets = 256;
  bool single_level = true, comparison_tree = true;
  std::set<unsigned> state_bases{29, 31}, index_registers;
  std::vector<std::pair<Address, Address>> ranges;
  std::map<Address, Address> index_overrides, target_overrides;
  Json raw = Json::object();
  static AnalysisSettings from_json(const Json &document,
                                    const CodeImage &image);
  bool selects(Address address) const;
};
struct DispatchSite {
  std::string model;
  Address branch = 0, head = 0, load_target = 0, parent = 0, parent_end = 0;
  std::optional<Address> load_index, load_state, index_table, target_table;
  int target_reg = -1, state_reg = -1, index_base = -1, target_base = -1;
  std::optional<MemoryOperand> state_slot, index_access, target_access;
  std::vector<Address> arrivals;
  std::map<std::uint64_t, Address> comparisons;
  Json detail = Json::object();
};
struct FlowTransition {
  Address branch = 0, arrival = 0;
  std::optional<Address> state_store;
  std::string category = "unknown", reason;
  std::optional<ConstantValue> state;
  Json predicate = nullptr;
  Json transform = nullptr;
};
struct TargetRecord {
  std::uint64_t state = 0;
  std::optional<std::int64_t> index;
  std::optional<Address> destination;
  std::string evidence = "invalid", reason;
};
struct ResolvedFlow {
  FlowTransition transition;
  std::vector<TargetRecord> targets;
};
struct ObservationSet {
  std::map<Address, std::set<Address>> targets;
  void merge(const Json &document);
  std::string grade(Address site, Address target) const;
  bool multiple(Address site) const;
  Json json() const;
};
void collect_direct_edges(CodeImage &image, const InstructionDecoder &decoder);
std::vector<DispatchSite> survey_dispatch(const CodeImage &image,
                                          const InstructionDecoder &decoder,
                                          const AnalysisSettings &settings);
std::vector<FlowTransition>
classify_transitions(const CodeImage &image, const InstructionDecoder &decoder,
                     const AnalysisSettings &settings,
                     const std::vector<DispatchSite> &sites);
std::vector<ResolvedFlow>
resolve_targets(const CodeImage &image, const AnalysisSettings &settings,
                const std::vector<DispatchSite> &sites,
                const std::vector<FlowTransition> &transitions,
                const ObservationSet &observed);
Json expand_state_space(
    const CodeImage &image, const InstructionDecoder &decoder,
    const AnalysisSettings &settings, const std::vector<DispatchSite> &sites,
    std::vector<ResolvedFlow> &flows, const ObservationSet &observed,
    const std::map<Address, std::map<std::uint64_t, std::set<Address>>>
        &traced_states = {});
DispatchSite site_from_json(const Json &record);
FlowTransition transition_from_json(const Json &record);
ResolvedFlow flow_from_json(const Json &record);
Json site_json(const DispatchSite &value);
Json transition_json(const FlowTransition &value);
Json flow_json(const ResolvedFlow &value);
} // namespace a64dispatch
