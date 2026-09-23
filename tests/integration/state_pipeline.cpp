#include <a64dispatch/workflow.hpp>
#include <iostream>
using namespace a64dispatch;
namespace {
unsigned passed = 0, failed = 0;
void check(bool ok, const std::string &name) {
  if (ok)
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
  } catch (const std::exception &) {
    check(true, name);
  }
}
Address named(const CodeImage &i, const std::string &name) {
  for (const auto &f : i.functions)
    if (f.label == name)
      return f.begin;
  throw AnalysisError("missing function");
}
} // namespace
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    const auto image = CodeImage::load(argv[1]);
    Json config = {{"executable_regions", Json::array({{{"label", "load_0"}}})},
                   {"mode", "linear"},
                   {"functions", Json::array({"state_chain"})}};
    auto analysis = AnalysisWorkflow(image, config).stage("plan");
    check(analysis.at("sites").size() == 1, "two-level state chain identified");
    unsigned transforms = 0;
    for (const auto &flow : analysis.at("flows")) {
      if (flow.at("transition").at("category") == "transform")
        ++transforms;
      (void)flow_from_json(flow);
    }
    check(transforms == 2,
          "both arithmetic/bitwise chains classified as transforms");
    const auto &expanded = analysis.at("state_expansion");
    check(!expanded.at("truncated").get<bool>() &&
              expanded.at("sites")[0].at("state_count") == 3,
          "bounded expansion discovers the closed three-state chain");
    check(expanded.at("sites")[0].at("states") ==
              Json::array({"0x0", "0x1", "0x3"}),
          "operation order and 32-bit arithmetic yield states 0,3,1");
    check(expanded.at("sites")[0].at("transitions").size() == 2,
          "expansion follows only reachable transform bodies");
    auto plan = plan_from_json(analysis.at("plan"));
    check(plan.edits.empty() && plan.graph.size() == 3,
          "scrambler and shared branch remain intact while all derived edges "
          "are reported");
    InstructionDecoder decoder;
    auto analyzed = image;
    collect_direct_edges(analyzed, decoder);
    auto settings = AnalysisSettings::from_json(config, analyzed);
    auto sites = survey_dispatch(analyzed, decoder, settings);
    auto execution =
        ExecutionOracle(Json::object())
            .run(image, named(image, "state_chain"), ByteArray{5}, sites);
    check(execution.returned == 42,
          "independent machine execution traverses both state transforms");
    for (const auto &edge : plan.graph)
      check(execution.observations.targets[edge.source].contains(edge.target),
            "derived graph edge agrees with actual Unicorn execution");
    config["analysis"] = {{"state_expansion", {{"enabled", false}}},
                          {"graph_tables", {{"enabled", false}}}};
    auto disabled = AnalysisWorkflow(image, config).stage("plan");
    check(
        !disabled.at("state_expansion").at("enabled").get<bool>() &&
            disabled.at("plan").at("graph").size() == 1,
        "explicitly disabling expansion keeps only original constant evidence");
    config["analysis"]["state_expansion"] = {{"maximum_states", 1}};
    auto capped =
        AnalysisWorkflow(image, config).stage("resolve").at("state_expansion");
    check(capped.at("truncated").get<bool>() &&
              capped.at("sites")[0].at("state_count") == 1,
          "state cap is explicit and no extra state is admitted");
    config["analysis"]["state_expansion"] = {{"maximum_steps", 1}};
    capped =
        AnalysisWorkflow(image, config).stage("resolve").at("state_expansion");
    check(capped.at("truncated").get<bool>() && capped.at("steps_used") == 1,
          "step budget cannot silently become complete");
    config["analysis"]["state_expansion"] = {{"maximum_states", 1.5}};
    rejects([&] { AnalysisWorkflow(image, config).stage("resolve"); },
            "fractional state cap rejected");
    const auto state_site = parse_address(analysis.at("sites")[0].at("branch"));
    config["analysis"]["state_expansion"] = {
        {"seed_states", {{"0x1234", Json::array({1})}}}};
    rejects([&] { AnalysisWorkflow(image, config).stage("resolve"); },
            "unrecognized seed site is rejected");
    config["analysis"]["state_expansion"] = {
        {"seed_states",
         {{hex_address(state_site), Json::array({"0x100000000"})}}}};
    rejects([&] { AnalysisWorkflow(image, config).stage("resolve"); },
            "explicit seed cannot exceed a 32-bit state slot");
    config["analysis"] = Json::object();
    config["functions"] = Json::array({"state_cycle"});
    auto cycle =
        AnalysisWorkflow(image, config).stage("resolve").at("state_expansion");
    check(!cycle.at("truncated").get<bool>() &&
              cycle.at("sites")[0].at("states") == Json::array({"0x0", "0x1"}),
          "cyclic state graph reaches a finite fixed point");
    rejects(
        [&] {
          ExecutionOracle({{"maximum_instructions", 1000}})
              .run(image, named(image, "state_cycle"), {});
        },
        "finite analysis does not claim an infinite program returns");
    config["functions"] = Json::array({"state_wrap"});
    auto wrapped = AnalysisWorkflow(image, config).stage("plan");
    check(wrapped.at("state_expansion").at("sites")[0].at("states") ==
              Json::array({"0x0", "0xffffffff"}),
          "subtraction wraps as 32-bit state with signed table indexing");
    execution =
        ExecutionOracle(Json::object())
            .run(image, named(image, "state_wrap"), ByteArray{7}, sites);
    check(execution.returned == 7, "signed state table remains executable");
    const auto wrap_site = site_from_json(wrapped.at("sites")[0]);
    check(execution.state_targets.at(wrap_site.branch).contains(0xffffffff),
          "LDRSW observation is normalized to the stored 32-bit state");
    config["analysis"] = {{"emulate", true}};
    config["execution"] = {
        {"known_vectors",
         Json::array({{{"entry", hex_address(named(image, "state_wrap"))},
                       {"input", "07"},
                       {"output", "0700000000000000"}}})}};
    auto observed = AnalysisWorkflow(image, config).stage("resolve");
    for (const auto &flow : observed.at("flows"))
      for (const auto &target : flow.at("targets"))
        check(
            target.at("evidence") == "observed",
            "expanded wrap target is cross-checked against natural execution");
    std::cout << passed << " state-expansion checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
