#include <a64dispatch/rewrite.hpp>
#include <limits>
namespace a64dispatch {
namespace {
std::optional<Address> optional_address(const Json &record,
                                        const std::string &key) {
  if (!record.contains(key) || record[key].is_null())
    return {};
  return parse_address(record[key]);
}
std::int64_t integer(const Json &value, std::int64_t low, std::int64_t high) {
  if (!value.is_number_integer())
    throw AnalysisError("artifact integer field has a non-integer value");
  if (value.is_number_unsigned() &&
      value.get<std::uint64_t>() >
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
    throw AnalysisError("artifact integer overflow");
  auto result = value.get<std::int64_t>();
  if (result < low || result > high)
    throw AnalysisError("artifact integer outside its bounds");
  return result;
}
std::optional<MemoryOperand> memory(const Json &record,
                                    const std::string &key) {
  if (!record.contains(key) || record[key].is_null())
    return {};
  const auto &value = record[key];
  MemoryOperand result;
  result.base = static_cast<int>(integer(value.at("base"), -1, 31));
  result.index = static_cast<int>(integer(value.at("index"), -1, 31));
  result.displacement = integer(value.at("displacement"), INT64_MIN, INT64_MAX);
  result.width = static_cast<unsigned>(integer(value.at("width"), 1, 16));
  result.scale = static_cast<unsigned>(integer(value.at("scale"), 0, 6));
  result.extension =
      static_cast<unsigned>(integer(value.at("extension"), 0, 7));
  result.signed_value = value.at("signed").get<bool>();
  result.writeback = value.value("writeback", false);
  return result;
}
void bounded_array(const Json &value, std::size_t maximum) {
  if (!value.is_array() || value.size() > maximum)
    throw AnalysisError("artifact array has invalid shape or size");
}
} // namespace
DispatchSite site_from_json(const Json &record) {
  DispatchSite result;
  result.model = record.at("model");
  if (result.model != "two_level" && result.model != "single_level" &&
      result.model != "comparison_tree")
    throw AnalysisError("unknown dispatch model");
  result.branch = parse_address(record.at("branch"));
  result.head = parse_address(record.at("head"));
  result.load_target = parse_address(record.at("target_load"));
  result.parent = parse_address(record.at("parent"));
  result.parent_end = parse_address(record.at("parent_end"));
  if (result.parent >= result.parent_end || result.branch < result.parent ||
      result.branch >= result.parent_end || result.branch % 4 ||
      result.head % 4)
    throw AnalysisError(
        "dispatch site has invalid parent or instruction bounds");
  result.load_index = optional_address(record, "index_load");
  result.load_state = optional_address(record, "state_load");
  result.target_table = optional_address(record, "target_table");
  result.index_table = optional_address(record, "index_table");
  result.target_reg =
      static_cast<int>(integer(record.at("target_register"), -1, 31));
  result.state_reg =
      static_cast<int>(integer(record.at("state_register"), -1, 31));
  result.index_base = static_cast<int>(
      integer(record.value("index_base_register", Json(-1)), -1, 31));
  result.target_base = static_cast<int>(
      integer(record.value("target_base_register", Json(-1)), -1, 31));
  result.state_slot = memory(record, "state_slot");
  result.index_access = memory(record, "index_access");
  result.target_access = memory(record, "target_access");
  const auto &arrivals = record.at("arrivals");
  bounded_array(arrivals, 65536);
  for (const auto &value : arrivals)
    result.arrivals.push_back(parse_address(value));
  const auto &comparisons = record.at("comparisons");
  if (!comparisons.is_object() || comparisons.size() > 65536)
    throw AnalysisError("invalid comparison table");
  for (const auto &[state, target] : comparisons.items())
    result.comparisons.emplace(parse_address(Json(state)),
                               parse_address(target));
  result.detail = record.at("detail");
  if (!result.detail.is_object())
    throw AnalysisError("dispatch details must be an object");
  return result;
}
FlowTransition transition_from_json(const Json &record) {
  FlowTransition result;
  result.branch = parse_address(record.at("branch"));
  result.arrival = parse_address(record.at("arrival"));
  result.state_store = optional_address(record, "state_store");
  result.category = record.at("category");
  if (result.category != "constant" && result.category != "choice" &&
      result.category != "transform" && result.category != "unknown")
    throw AnalysisError("unknown transition category");
  result.reason = record.at("reason");
  result.predicate = record.at("predicate");
  result.transform = record.at("transform");
  if (!record.at("state").is_null()) {
    ConstantValue state;
    const auto &value = record["state"];
    bounded_array(value.at("values"), 2);
    if (value["values"].empty())
      throw AnalysisError("empty finite state set");
    for (const auto &number : value["values"])
      state.values.push_back(parse_address(number));
    bounded_array(value.at("producers"), 4096);
    for (const auto &number : value["producers"])
      state.producers.push_back(parse_address(number));
    if (value.contains("condition") && !value["condition"].is_null())
      state.condition =
          static_cast<unsigned>(integer(value["condition"], 0, 13));
    state.selection = optional_address(value, "selection");
    result.state = std::move(state);
  }
  if (result.predicate.is_object()) {
    auto kind = result.predicate.at("kind").get<std::string>();
    if (kind == "condition")
      integer(result.predicate.at("condition"), 0, 13);
    else if (kind == "bit") {
      integer(result.predicate.at("register"), 0, 30);
      integer(result.predicate.at("bit"), 0, 63);
    } else
      throw AnalysisError("unknown transition predicate");
    (void)parse_address(result.predicate.at("selection"));
  } else if (!result.predicate.is_null())
    throw AnalysisError("invalid transition predicate shape");
  if ((result.category == "constant" || result.category == "choice") &&
      !result.state)
    throw AnalysisError("finite transition requires states");
  if (result.category == "constant" && result.state->values.size() != 1)
    throw AnalysisError("constant transition has multiple values");
  if (result.category == "choice" &&
      (result.state->values.size() != 2 || result.predicate.is_null()))
    throw AnalysisError(
        "choice transition requires two values and a predicate");
  return result;
}
ResolvedFlow flow_from_json(const Json &record) {
  ResolvedFlow result;
  result.transition = transition_from_json(record.at("transition"));
  bounded_array(record.at("targets"), 65536);
  for (const auto &value : record["targets"]) {
    TargetRecord target;
    target.state = parse_address(value.at("state"));
    if (!value.at("index").is_null())
      target.index = integer(value["index"], INT64_MIN, INT64_MAX);
    target.destination = optional_address(value, "destination");
    target.evidence = value.at("evidence");
    if (target.evidence != "invalid" && target.evidence != "static_only" &&
        target.evidence != "observed" && target.evidence != "conflict" &&
        target.evidence != "emulated")
      throw AnalysisError("unknown target evidence");
    target.reason = value.at("reason");
    result.targets.push_back(std::move(target));
  }
  return result;
}
RewritePlan plan_from_json(const Json &record) {
  if (record.at("schema_version") != 1)
    throw AnalysisError("unsupported rewrite-plan version");
  RewritePlan result;
  result.source_sha256 = record.at("source_sha256");
  if (parse_hex(result.source_sha256).size() != 32)
    throw AnalysisError("invalid plan source digest");
  bounded_array(record.at("edits"), 1000000);
  bounded_array(record.at("graph"), 1000000);
  bounded_array(record.at("skipped"), 1000000);
  result.skipped = record["skipped"];
  for (const auto &value : record["edits"]) {
    InstructionEdit edit;
    edit.address = parse_address(value.at("address"));
    edit.parent = parse_address(value.at("parent"));
    edit.site = parse_address(value.at("site"));
    edit.expected = parse_hex(value.at("expected"));
    edit.replacement = parse_hex(value.at("replacement"));
    if (edit.expected.size() != 4 || edit.replacement.size() != 4 ||
        edit.address % 4)
      throw AnalysisError("invalid instruction edit width or alignment");
    edit.target = optional_address(value, "target");
    edit.reason = value.at("reason");
    result.edits.push_back(std::move(edit));
  }
  for (const auto &value : record["graph"])
    result.graph.push_back({parse_address(value.at("source")),
                            parse_address(value.at("target")), false});
  return result;
}
} // namespace a64dispatch
