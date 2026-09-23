#include <a64dispatch/rewrite.hpp>
#include <iostream>
using namespace a64dispatch;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &name) {
  if (value)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
Address entry(const CodeImage &image, const std::string &name) {
  for (const auto &function : image.functions)
    if (function.label == name)
      return function.begin;
  throw AnalysisError("missing fixture function: " + name);
}
ByteArray scalar(std::uint64_t value) {
  ByteArray result(8);
  for (unsigned index = 0; index < 8; ++index)
    result[index] = static_cast<std::uint8_t>(value >> (index * 8));
  return result;
}
} // namespace
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    auto image = CodeImage::load(argv[1]);
    InstructionDecoder decoder;
    collect_direct_edges(image, decoder);
    Json selected = Json::array();
    for (const auto &region : image.regions)
      if (region.executable)
        selected.push_back({{"label", region.label}});
    auto settings =
        AnalysisSettings::from_json({{"executable_regions", selected}}, image);
    auto sites = survey_dispatch(image, decoder, settings);
    auto transitions = classify_transitions(image, decoder, settings, sites);
    ObservationSet none;
    auto flows = resolve_targets(image, settings, sites, transitions, none);
    check(sites.size() == 7,
          "seven dispatcher sites from independent assembler");
    check(transitions.size() == 9,
          "shared and comparison-tree arrivals stay separate");
    unsigned two = 0, single = 0, tree = 0, constant = 0, choice = 0;
    for (const auto &site : sites) {
      two += site.model == "two_level";
      single += site.model == "single_level";
      tree += site.model == "comparison_tree";
    }
    for (const auto &transition : transitions) {
      constant += transition.category == "constant";
      choice += transition.category == "choice";
    }
    check(two == 3 && single == 3 && tree == 1, "all three model families");
    check(constant == 5 && choice == 4,
          "constant, condition and bit classifications");
    for (const auto &flow : flows) {
      check(!flow.targets.empty(), "fixture target set resolved");
      for (const auto &target : flow.targets)
        check(target.destination && image.valid_target(*target.destination) &&
                  target.evidence == "static_only",
              "static evidence is not marked observed");
    }
    ExecutionOracle oracle({{"backend", "unicorn"},
                            {"input", {{"mode", "scalar"}}},
                            {"output", {{"mode", "return"}}}});
    ObservationSet combined;
    for (const auto &name : {"two_constant", "two_choice", "single_choice",
                             "shared_dispatch", "compare_tree", "flag_changed"})
      for (std::uint64_t input : {0u, 1u, 7u, 32u}) {
        auto address = entry(image, name);
        auto result = oracle.run(image, address, scalar(input), sites);
        std::uint64_t expected = 0;
        std::string function = name;
        if (function == "two_constant")
          expected = input + 7;
        else if (function == "two_choice")
          expected = input == 0 ? 7 : input - 3;
        else if (function == "single_choice" || function == "flag_changed")
          expected = input + (input == 0 ? 11 : 19);
        else if (function == "shared_dispatch")
          expected = input + (input == 0 ? 23 : 31);
        else
          expected = input + 2;
        check(result.returned == expected,
              "Unicorn known scalar result: " + function);
        check(result.output == scalar(expected),
              "explicit little-endian output");
        combined.merge(result.observations.json());
      }
    ExecutionOracle bytes(
        {{"input", {{"mode", "bytes"}}}, {"output", {{"mode", "return"}}}});
    for (unsigned input = 0; input < 4; ++input) {
      ByteArray payload{static_cast<std::uint8_t>(input)};
      auto result =
          bytes.run(image, entry(image, "bit_selected"), payload, sites);
      check(result.returned == (input % 2 ? 43u : 41u),
            "acquire-byte selection result");
      combined.merge(result.observations.json());
    }
    auto observed =
        resolve_targets(image, settings, sites, transitions, combined);
    for (const auto &flow : observed)
      if (flow.transition.branch != entry(image, "compare_tree") + 16)
        for (const auto &target : flow.targets)
          check(target.evidence == "observed",
                "static and emulator target agree");
    auto shared = entry(image, "shared_dispatch");
    for (const auto &site : sites)
      if (site.parent == shared)
        check(combined.multiple(site.branch) && site.arrivals.size() == 2,
              "shared dispatcher exposes multiple observed targets");
    auto plan =
        plan_rewrites(image, decoder, settings, sites, observed, combined);
    check(!plan.edits.empty(), "rewrite planner emits concrete changes");
    for (const auto &change : plan.edits)
      check(change.parent != entry(image, "shared_dispatch") &&
                change.parent != entry(image, "flag_changed"),
            "shared and flag-clobbered dispatchers retain their bytes");
    auto candidate = RewriteTransaction::prepare(image, plan);
    check(RewriteTransaction::self_check(candidate, plan)["passed"],
          "every emitted branch roundtrips");
    for (const auto &name : {"two_constant", "two_choice", "single_choice",
                             "shared_dispatch", "compare_tree", "flag_changed"})
      for (std::uint64_t input : {0u, 1u, 7u, 32u})
        check(
            oracle.run(image, entry(image, name), scalar(input)).output ==
                oracle.run(candidate, entry(image, name), scalar(input)).output,
            "candidate IO equivalence");
    for (unsigned input = 0; input < 4; ++input) {
      ByteArray payload{static_cast<std::uint8_t>(input)};
      check(bytes.run(image, entry(image, "bit_selected"), payload).output ==
                bytes.run(candidate, entry(image, "bit_selected"), payload)
                    .output,
            "bit-branch candidate IO equivalence");
    }
    Json transaction_vectors = Json::array();
    for (const auto &name :
         {"two_constant", "two_choice", "single_choice", "compare_tree"})
      for (std::uint64_t input : {0u, 1u}) {
        auto before = oracle.run(image, entry(image, name), scalar(input));
        transaction_vectors.push_back(
            {{"entry", hex_address(entry(image, name))},
             {"input", hex_bytes(scalar(input))},
             {"output", hex_bytes(before.output)}});
      }
    for (unsigned input = 0; input < 2; ++input) {
      ByteArray payload{static_cast<std::uint8_t>(input)};
      auto before = bytes.run(image, entry(image, "bit_selected"), payload);
      transaction_vectors.push_back(
          {{"entry", hex_address(entry(image, "bit_selected"))},
           {"input", hex_bytes(payload)},
           {"output", hex_bytes(before.output)},
           {"input_spec", {{"mode", "bytes"}}}});
    }
    ExecutionOracle transaction_oracle(
        {{"known_vectors", transaction_vectors}});
    auto current = image;
    RewriteTransaction::commit(current, image, plan, transaction_oracle);
    auto applied = current.fingerprint();
    RewriteTransaction::commit(current, image, plan, transaction_oracle);
    check(current.fingerprint() == applied, "idempotent commit");
    RewriteTransaction::restore(current, image, plan);
    check(current.fingerprint() == image.fingerprint(),
          "exact original restoration");
    auto repeated_sites = survey_dispatch(current, decoder, settings);
    auto repeated_transitions =
        classify_transitions(current, decoder, settings, repeated_sites);
    auto repeated_flows = resolve_targets(current, settings, repeated_sites,
                                          repeated_transitions, combined);
    auto repeated_plan = plan_rewrites(
        current, decoder, settings, repeated_sites, repeated_flows, combined);
    check(repeated_plan.json() == plan.json(),
          "restored image reproduces the complete plan and skip set");
    auto drifted = image;
    drifted.replace(image.entry, instruction_bytes(0xd503201f));
    auto drift_hash = drifted.fingerprint();
    bool refused = false;
    try {
      RewriteTransaction::commit(drifted, image, plan, transaction_oracle);
    } catch (const AnalysisError &) {
      refused = true;
    }
    check(refused && drifted.fingerprint() == drift_hash,
          "preflight failure leaves current image intact");
    auto unverified = image;
    bool verifier_refused = false;
    try {
      RewriteTransaction::commit(unverified, image, plan, oracle);
    } catch (const AnalysisError &) {
      verifier_refused = true;
    }
    check(verifier_refused && unverified.fingerprint() == image.fingerprint(),
          "commit cannot bypass required known vectors");
    auto binary_plan = plan;
    std::erase_if(binary_plan.edits, [&](const auto &change) {
      return change.parent != entry(image, "two_choice");
    });
    ExecutionOracle one_path(
        {{"known_vectors",
          Json::array({{{"entry", hex_address(entry(image, "two_choice"))},
                        {"input", hex_bytes(scalar(0))},
                        {"output", hex_bytes(scalar(7))}}})}});
    bool path_refused = false;
    try {
      RewriteTransaction::commit(unverified, image, binary_plan, one_path);
    } catch (const AnalysisError &) {
      path_refused = true;
    }
    check(path_refused && unverified.fingerprint() == image.fingerprint(),
          "a binary rewrite requires vectors covering both original targets");
    auto duplicate = plan;
    duplicate.edits.push_back(duplicate.edits.front());
    refused = false;
    try {
      RewriteTransaction::prepare(image, duplicate);
    } catch (const AnalysisError &) {
      refused = true;
    }
    check(refused, "duplicate edit rejected before write");
    Json specification = {
        {"entry", hex_address(entry(image, "two_constant"))},
        {"known_vectors", Json::array({{{"input", hex_bytes(scalar(3))},
                                        {"output", hex_bytes(scalar(10))}}})}};
    ExecutionOracle verifier(specification);
    check(verifier.compare(image, image, sites)["passed"],
          "known-vector baseline pass");
    auto corrupted = image;
    corrupted.replace(entry(image, "two_constant") + 36,
                      instruction_bytes(0x91002000));
    check(!verifier.compare(image, corrupted, sites)["passed"],
          "changed candidate is really executed and rejected");
    auto endless = image;
    endless.replace(entry(image, "two_constant"),
                    instruction_bytes(0x14000000));
    bool rejected = false;
    try {
      oracle.run(endless, entry(image, "two_constant"), scalar(0));
    } catch (const AnalysisError &) {
      rejected = true;
    }
    check(rejected, "instruction budget is failure rather than success");
    std::cout << passed << " pipeline checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
