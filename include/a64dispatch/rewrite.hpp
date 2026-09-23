#pragma once
#include <a64dispatch/execution.hpp>
namespace a64dispatch {
struct InstructionEdit {
  Address address = 0, parent = 0, site = 0;
  ByteArray expected, replacement;
  std::optional<Address> target;
  std::string reason;
};
struct RewritePlan {
  std::string source_sha256;
  std::vector<InstructionEdit> edits;
  Json skipped = Json::array();
  std::vector<ControlEdge> graph;
  Json json() const;
};
RewritePlan plan_from_json(const Json &record);
RewritePlan plan_cleanup(const CodeImage &image,
                         const InstructionDecoder &decoder,
                         const AnalysisSettings &settings);
RewritePlan plan_rewrites(const CodeImage &image,
                          const InstructionDecoder &decoder,
                          const AnalysisSettings &settings,
                          const std::vector<DispatchSite> &sites,
                          const std::vector<ResolvedFlow> &flows,
                          const ObservationSet &observed);
Json enrich_table_graph(const CodeImage &image,
                        const AnalysisSettings &settings,
                        const std::vector<DispatchSite> &sites,
                        RewritePlan &plan);
Json check_plan_expectations(const CodeImage &candidate,
                             const RewritePlan &plan, const Json &expectations);
class RewriteTransaction {
public:
  static CodeImage prepare(const CodeImage &pristine, const RewritePlan &plan);
  static Json commit(CodeImage &current, const CodeImage &pristine,
                     const RewritePlan &plan, const ExecutionOracle &oracle);
  static void restore(CodeImage &current, const CodeImage &pristine,
                      const RewritePlan &plan);
  static Json self_check(const CodeImage &candidate, const RewritePlan &plan);
};
} // namespace a64dispatch
