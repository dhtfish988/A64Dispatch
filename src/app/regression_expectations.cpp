#include <a64dispatch/rewrite.hpp>
namespace a64dispatch {
Json check_plan_expectations(const CodeImage &candidate,
                             const RewritePlan &plan,
                             const Json &expectations) {
  if (!expectations.is_object())
    throw AnalysisError("regression expectations require an object");
  Json rows = Json::array();
  bool passed = true;
  auto record = [&](const std::string &name, bool ok, Json detail) {
    rows.push_back(
        {{"name", name}, {"passed", ok}, {"detail", std::move(detail)}});
    passed = passed && ok;
  };
  if (expectations.contains("minimum_edits")) {
    auto minimum = parse_address(expectations.at("minimum_edits"));
    record("minimum_edits", plan.edits.size() >= minimum,
           {{"expected", minimum}, {"actual", plan.edits.size()}});
  }
  if (expectations.contains("maximum_skips")) {
    auto maximum = parse_address(expectations.at("maximum_skips"));
    record("maximum_skips", plan.skipped.size() <= maximum,
           {{"expected", maximum}, {"actual", plan.skipped.size()}});
  }
  if (expectations.contains("expected_skips")) {
    const auto &expected = expectations.at("expected_skips");
    if (!expected.is_array() || expected.size() > 100000)
      throw AnalysisError("expected_skips must be a bounded array");
    auto normalize = [](const Json &values) {
      std::set<std::tuple<Address, Address, std::string>> out;
      for (const auto &value : values) {
        const auto site = parse_address(value.at("site"));
        const auto arrival =
            value.contains("arrival") ? parse_address(value.at("arrival")) : 0;
        const auto reason = value.at("reason").get<std::string>();
        if (!out.emplace(site, arrival, reason).second)
          throw AnalysisError("duplicate expected skip");
      }
      return out;
    };
    record("expected_skips", normalize(expected) == normalize(plan.skipped),
           {{"expected", expected}, {"actual", plan.skipped}});
  }
  const auto samples = expectations.value("instruction_samples", Json::array());
  if (!samples.is_array() || samples.size() > 10000)
    throw AnalysisError("instruction_samples must be a bounded array");
  InstructionDecoder decoder;
  for (const auto &sample : samples) {
    const auto address = parse_address(sample.at("address"));
    const auto word = candidate.instruction(address);
    bool ok = word.has_value();
    if (!sample.contains("word") && !sample.contains("operation") &&
        !sample.contains("target"))
      throw AnalysisError("instruction sample has no expectation");
    Json actual = {{"address", hex_address(address)}};
    if (word) {
      const auto view = decoder.decode(address, *word);
      actual["word"] = hex_address(*word);
      actual["operation"] = operation_name(view.operation);
      actual["target"] =
          view.target ? Json(hex_address(*view.target)) : Json(nullptr);
      ok = view.valid;
      if (sample.contains("word"))
        ok = ok && *word == parse_address(sample.at("word"));
      if (sample.contains("operation"))
        ok = ok && operation_name(view.operation) ==
                       sample.at("operation").get<std::string>();
      if (sample.contains("target"))
        ok = ok && view.target &&
             *view.target == parse_address(sample.at("target"));
    }
    record("instruction_sample", ok,
           {{"expected", sample}, {"actual", actual}});
  }
  return {{"passed", passed}, {"checks", rows}};
}
} // namespace a64dispatch
