#pragma once
#include <a64dispatch/rewrite.hpp>
namespace a64dispatch {
// Owns an immutable input. Every stage is regenerated from this image and the
// configuration; imported artifacts are evidence to check, never instructions.
class AnalysisWorkflow {
public:
  AnalysisWorkflow(CodeImage input, Json configuration);
  Json stage(const std::string &name);
  void check_artifact(const Json &artifact);
  Json execute(const std::string &command, bool apply = false,
               const CodeImage *candidate = nullptr);
  Json restore(const Json &receipt, const CodeImage *current = nullptr);
  const CodeImage &source() const { return input_; }
  const Json &configuration() const { return configuration_; }

private:
  Json envelope(const std::string &name) const;
  void analyze(unsigned depth);
  Json exercise();
  Json execute_batch(bool apply);
  RewritePlan effective_plan(const std::string &command) const;
  CodeImage with_graph(CodeImage candidate, const RewritePlan &plan,
                       Json &added) const;
  Json receipt(const std::string &command, const RewritePlan &plan,
               const CodeImage &candidate, const Json &added, bool applied,
               const Json &verification) const;
  CodeImage input_, analysis_image_;
  Json configuration_, executions_ = Json::array();
  Json expansion_ = Json::object(), table_graph_ = Json::object();
  AnalysisSettings settings_;
  InstructionDecoder decoder_;
  std::string configuration_hash_, mode_;
  unsigned depth_ = 0;
  std::vector<DispatchSite> sites_;
  std::vector<FlowTransition> transitions_;
  std::vector<ResolvedFlow> flows_;
  ObservationSet observations_;
  std::map<Address, std::map<std::uint64_t, std::set<Address>>> state_targets_;
  RewritePlan plan_;
  bool exercised_ = false;
};
} // namespace a64dispatch
