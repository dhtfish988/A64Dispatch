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
CodeImage fixture(std::initializer_list<std::uint32_t> words) {
  CodeImage image;
  MemoryRegion code;
  code.begin = 0x1000;
  code.label = "code";
  code.executable = true;
  for (auto word : words) {
    auto bytes = instruction_bytes(word);
    code.bytes.insert(code.bytes.end(), bytes.begin(), bytes.end());
  }
  image.regions.push_back(code);
  image.functions.push_back({0x1000, code.end(), "fixture"});
  image.entry = 0x1000;
  image.relocated = true;
  return image;
}
} // namespace
int main() {
  try {
    const Json config = {
        {"executable_regions", Json::array({{{"label", "code"}}})},
        {"mode", "linear"}};
    InstructionDecoder decoder;
    auto image = fixture({0x58000089, 0xd63f0120, 0xd503201f, 0xd503201f,
                          0xd28000e0, 0xd65f03c0});
    auto settings = AnalysisSettings::from_json(config, image);
    auto plan = plan_cleanup(image, decoder, settings);
    check(plan.edits.size() == 2 && plan.graph.size() == 1,
          "literal-load/BLR produces two grouped proposals");
    auto prepared = RewriteTransaction::prepare(image, plan);
    check(decoder.decode(0x1000, *prepared.instruction(0x1000)).target ==
              0x1010,
          "cleanup branch encodes literal address");
    check(*prepared.instruction(0x1004) == 0xd503201f,
          "paired BLR becomes proposed NOP");
    auto entered = image;
    entered.references.push_back({0x1010, 0x1004, false});
    check(plan_cleanup(entered, decoder, settings).edits.empty(),
          "interior entry prevents literal/BLR fold");
    auto mismatch = image;
    mismatch.replace(0x1004, instruction_bytes(0xd63f0140));
    check(plan_cleanup(mismatch, decoder, settings).edits.empty(),
          "load and call registers must match");
    auto no_owner = image;
    no_owner.functions.clear();
    check(plan_cleanup(no_owner, decoder, settings).edits.empty(),
          "cleanup requires function ownership");
    auto bad_target = image;
    bad_target.replace(0x1010, instruction_bytes(0xa2f2fff1));
    const auto rejected_literal = plan_cleanup(bad_target, decoder, settings);
    check(rejected_literal.graph.empty() && !rejected_literal.skipped.empty(),
          "undecodable literal target cannot produce a branch fold");
    auto filler = fixture({0xd503201f, 0xa2f2fff1, 0xa2f2fff1, 0xd65f03c0});
    auto filler_plan = plan_cleanup(filler, decoder, settings);
    check(filler_plan.edits.size() == 2,
          "short reserved filler is proposed between valid instructions");
    check(RewriteTransaction::self_check(
              RewriteTransaction::prepare(filler, filler_plan), filler_plan)
              .at("passed")
              .get<bool>(),
          "filler candidate self-check is only structural");
    auto long_run =
        fixture({0xd503201f, 0xa2f2fff1, 0xa2f2fff1, 0xa2f2fff1, 0xd65f03c0});
    check(plan_cleanup(long_run, decoder, settings).edits.empty(),
          "long filler run is preserved");
    auto unterminated = fixture({0xd503201f, 0xa2f2fff1, 0xa2f2fff1});
    check(plan_cleanup(unterminated, decoder, settings).edits.empty(),
          "trailing bytes without a valid following instruction preserved");
    auto prefix = fixture({0xa2f2fff1, 0xa2f2fff1, 0xd65f03c0});
    check(plan_cleanup(prefix, decoder, settings).edits.empty(),
          "leading undecodable bytes lack sandwich evidence");
    auto malformed = config;
    malformed["cleanup"] = {{"maximum_filler_bytes", 5}};
    rejects(
        [&] {
          plan_cleanup(filler, decoder,
                       AnalysisSettings::from_json(malformed, filler));
        },
        "invalid cleanup window rejected");
    auto vectors = config;
    vectors["execution"] = {
        {"known_vectors", Json::array({{{"entry", "0x1010"},
                                        {"input", "00"},
                                        {"output", "0700000000000000"}}})}};
    AnalysisWorkflow workflow(image, vectors);
    auto preview = workflow.execute("cleanup");
    check(!preview.at("applied").get<bool>() &&
              preview.at("plan").at("edits").size() == 2,
          "workflow exposes cleanup as unverified preview");
    rejects([&] { workflow.execute("cleanup", true); },
            "cleanup cannot commit without original execution coverage of "
            "proposed slots");
    check(workflow.source().fingerprint() == image.fingerprint(),
          "failed cleanup leaves original intact");
    auto graph = config;
    graph["mode"] = "graph";
    rejects([&] { AnalysisWorkflow(image, graph).execute("cleanup", true); },
            "graph mode cannot authorize cleanup byte changes");
    std::cout << passed << " cleanup checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
