#include <a64dispatch/process.hpp>
#include <a64dispatch/rewrite.hpp>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <unistd.h>
using namespace a64dispatch;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &message) {
  if (value)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << message << '\n';
  }
}
template <typename Function>
void rejects(Function action, const std::string &message) {
  try {
    action();
    check(false, message);
  } catch (const std::exception &) {
    check(true, message);
  }
}
Json parse(const std::string &text) {
  return parse_document(
      {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
}
ByteArray bytes(const std::string &text) { return {text.begin(), text.end()}; }
} // namespace
int main(int argc, char **argv) {
  if (argc > 1 && std::string(argv[1]) == "--echo") {
    std::cout << std::cin.rdbuf();
    return 0;
  }
  if (argc > 2 && std::string(argv[1]) == "--argument") {
    std::cout << argv[2];
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--sleep") {
    usleep(300000);
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--flood") {
    for (unsigned i = 0; i < 10000; ++i)
      std::cout << std::string(1000, 'x');
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--exit") {
    std::cerr << "expected failure";
    return 7;
  }
  if (argc > 1 && std::string(argv[1]) == "--wrong-receipt") {
    std::cout
        << R"({"protocol_version":1,"image_sha256":"wrong","entry":"0x0","completed":true})";
    return 0;
  }
  if (argc != 3)
    return 2;
  try {
    check(parse("{\"a\":1,\"nested\":{\"a\":2}}")["nested"]["a"] == 2,
          "same key in separate objects is legal");
    rejects([&] { parse("{\"a\":1,\"a\":2}"); }, "duplicate JSON key rejected");
    rejects([&] { parse(std::string(70, '[') + "0" + std::string(70, ']')); },
            "excessive JSON nesting rejected");
    rejects([&] { parse("{\"a\":1} {} "); }, "trailing JSON value rejected");
    TemporaryDirectory temporary;
    auto document = temporary.path() / "report.json";
    write_document(document, {{"original", true}});
    rejects(
        [&] {
          write_document(document, {{"invalid", std::string(1, char(0xff))}});
        },
        "failed encoding rejects atomic write");
    check(read_document(document) == Json({{"original", true}}),
          "failed write preserves original document");
    write_document(document, {{"replacement", true}});
    check(read_document(document) == Json({{"replacement", true}}),
          "atomic replacement readable");
    check(std::distance(std::filesystem::directory_iterator(temporary.path()),
                        std::filesystem::directory_iterator{}) == 1,
          "temporary output files cleaned");
    auto yaml = temporary.path() / "config.yml";
    {
      std::ofstream stream(yaml);
      stream << "a: &cycle [*cycle]\n";
    }
    rejects([&] { read_document(yaml); }, "recursive YAML alias rejected");
    {
      std::ofstream stream(yaml);
      stream << "a: 1\na: 2\n";
    }
    rejects([&] { read_document(yaml); }, "duplicate YAML key rejected");
    ByteArray input(512 * 1024, 0x61);
    auto echo = run_process({argv[0], "--echo"}, input, 5000);
    check(echo.exit_code == 0 && echo.output == input,
          "bounded process drains output while feeding input");
    auto literal = std::string("space ' ; $HOME ");
    auto argument = run_process({argv[0], "--argument", literal}, {}, 5000);
    check(argument.output == bytes(literal),
          "arguments are not interpreted by a shell");
    auto exit = run_process({argv[0], "--exit"}, {}, 5000);
    check(exit.exit_code == 7 && exit.errors == bytes("expected failure"),
          "child status and stderr preserved");
    rejects([&] { run_process({argv[0], "--sleep"}, {}, 30); },
            "process timeout enforced");
    rejects([&] { run_process({argv[0], "--flood"}, {}, 5000, 1024); },
            "process output limit enforced");
    rejects([&] { run_process({"/no/such/a64dispatch-worker"}, {}, 5000); },
            "missing process executable rejected");
    auto image = CodeImage::load(argv[1]);
    InstructionDecoder decoder;
    collect_direct_edges(image, decoder);
    Json selectors = Json::array();
    for (const auto &region : image.regions)
      if (region.executable)
        selectors.push_back({{"label", region.label}});
    auto settings =
        AnalysisSettings::from_json({{"executable_regions", selectors}}, image);
    auto sites = survey_dispatch(image, decoder, settings);
    auto transitions = classify_transitions(image, decoder, settings, sites);
    ObservationSet none;
    auto flows = resolve_targets(image, settings, sites, transitions, none);
    auto plan = plan_rewrites(image, decoder, settings, sites, flows, none);
    for (const auto &site : sites)
      check(site_json(site_from_json(site_json(site))) == site_json(site),
            "site artifact roundtrip");
    for (const auto &value : transitions)
      check(transition_json(transition_from_json(transition_json(value))) ==
                transition_json(value),
            "transition artifact roundtrip");
    for (const auto &value : flows)
      check(flow_json(flow_from_json(flow_json(value))) == flow_json(value),
            "resolution artifact roundtrip");
    check(plan_from_json(plan.json()).json() == plan.json(),
          "plan artifact roundtrip");
    auto wrong = site_json(sites.front());
    wrong["state_register"] = 2.5;
    rejects([&] { site_from_json(wrong); }, "fractional register rejected");
    auto invalid = plan.json();
    invalid["edits"][0]["replacement"] = "00";
    rejects([&] { plan_from_json(invalid); }, "incorrect edit width rejected");
    auto unknown = transition_json(transitions.front());
    unknown["category"] = "invented";
    rejects([&] { transition_from_json(unknown); },
            "unknown transition category rejected");
    ExecutionOracle direct({{"input", {{"mode", "scalar"}}}});
    ExecutionOracle external(
        {{"backend", "command"}, {"command", Json::array({argv[2]})}});
    auto before = direct.run(image, image.entry, ByteArray{3}, sites);
    auto actual = external.run(image, image.entry, ByteArray{3}, sites);
    check(actual.output == before.output && actual.executed == before.executed,
          "external worker executes the supplied image with matching coverage");
    check(actual.observations.json() == before.observations.json(),
          "external branch observations agree");
    auto corrupted = image;
    corrupted.replace(image.entry + 36, instruction_bytes(0x91002000));
    auto altered = external.run(corrupted, image.entry, ByteArray{3}, sites);
    check(altered.output != actual.output,
          "external worker receives changed candidate bytes");
    ExecutionOracle mismatched(
        {{"backend", "command"},
         {"command", Json::array({argv[0], "--wrong-receipt"})}});
    rejects([&] { mismatched.run(image, image.entry, ByteArray{3}); },
            "mismatched image receipt rejected");
    ExecutionOracle raw({{"backend", "command"},
                         {"protocol", "bytes"},
                         {"command", Json::array({argv[0], "--echo"})}});
    rejects([&] { raw.run(image, image.entry, ByteArray{3}); },
            "raw oracle cannot omit candidate image argument");
    std::cout << passed << " boundary/IPC checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
