#include <a64dispatch/analysis.hpp>
namespace a64dispatch {
namespace {
Json address(const std::optional<Address> &value) {
  return value ? Json(hex_address(*value)) : Json(nullptr);
}
Json memory(const std::optional<MemoryOperand> &value) {
  if (!value)
    return nullptr;
  return {{"base", value->base},
          {"index", value->index},
          {"displacement", value->displacement},
          {"width", value->width},
          {"scale", value->scale},
          {"extension", value->extension},
          {"signed", value->signed_value},
          {"writeback", value->writeback}};
}
} // namespace
Json site_json(const DispatchSite &value) {
  Json arrivals = Json::array(), comparisons = Json::object();
  for (auto item : value.arrivals)
    arrivals.push_back(hex_address(item));
  for (auto [state, target] : value.comparisons)
    comparisons[hex_address(state)] = hex_address(target);
  return {{"model", value.model},
          {"branch", hex_address(value.branch)},
          {"head", hex_address(value.head)},
          {"target_load", hex_address(value.load_target)},
          {"index_load", address(value.load_index)},
          {"state_load", address(value.load_state)},
          {"parent", hex_address(value.parent)},
          {"parent_end", hex_address(value.parent_end)},
          {"target_table", address(value.target_table)},
          {"index_table", address(value.index_table)},
          {"target_register", value.target_reg},
          {"state_register", value.state_reg},
          {"index_base_register", value.index_base},
          {"target_base_register", value.target_base},
          {"state_slot", memory(value.state_slot)},
          {"index_access", memory(value.index_access)},
          {"target_access", memory(value.target_access)},
          {"arrivals", arrivals},
          {"comparisons", comparisons},
          {"detail", value.detail}};
}
Json transition_json(const FlowTransition &value) {
  Json state = nullptr;
  if (value.state) {
    Json values = Json::array(), producers = Json::array();
    for (auto entry : value.state->values)
      values.push_back(hex_address(entry));
    for (auto entry : value.state->producers)
      producers.push_back(hex_address(entry));
    state = {{"values", values},
             {"producers", producers},
             {"condition", value.state->condition
                               ? Json(*value.state->condition)
                               : Json(nullptr)},
             {"selection", address(value.state->selection)}};
  }
  return {{"branch", hex_address(value.branch)},
          {"arrival", hex_address(value.arrival)},
          {"state_store", address(value.state_store)},
          {"category", value.category},
          {"state", state},
          {"predicate", value.predicate},
          {"transform", value.transform},
          {"reason", value.reason}};
}
Json flow_json(const ResolvedFlow &value) {
  Json targets = Json::array();
  for (const auto &target : value.targets)
    targets.push_back(
        {{"state", hex_address(target.state)},
         {"index", target.index ? Json(*target.index) : Json(nullptr)},
         {"destination", address(target.destination)},
         {"evidence", target.evidence},
         {"reason", target.reason}});
  return {{"transition", transition_json(value.transition)},
          {"targets", targets}};
}
} // namespace a64dispatch
