#include <a64dispatch/analysis.hpp>
#include <limits>
namespace a64dispatch {
namespace {
std::optional<Address> indexed(Address base, std::int64_t index,
                               unsigned scale) {
  if (scale > 6)
    return {};
  if (index >= 0) {
    auto number = static_cast<std::uint64_t>(index);
    if (number > (std::numeric_limits<Address>::max() - base) >> scale)
      return {};
    return base + (number << scale);
  }
  auto number = static_cast<std::uint64_t>(-(index + 1)) + 1;
  if (number > (base >> scale))
    return {};
  return base - (number << scale);
}
std::int64_t signed32(std::uint64_t value) {
  auto number = value & 0xffffffff;
  return static_cast<std::int64_t>(number & 0x7fffffff) -
         static_cast<std::int64_t>(number & 0x80000000);
}
} // namespace
void ObservationSet::merge(const Json &document) {
  if (document.is_array()) {
    for (const auto &value : document)
      merge(value);
    return;
  }
  if (!document.is_object() || !document.contains("sites") ||
      !document["sites"].is_object())
    throw AnalysisError("trace requires a sites object");
  if (document["sites"].size() > 100000)
    throw AnalysisError("trace site count exceeded");
  for (const auto &[location, hits] : document["sites"].items()) {
    auto site = parse_address(Json(location));
    auto &values = targets[site];
    if (hits.is_object()) {
      for (const auto &[destination, count] : hits.items()) {
        if (!count.is_number_integer() || count.get<std::int64_t>() <= 0)
          throw AnalysisError("trace counts must be positive integers");
        values.insert(parse_address(Json(destination)));
      }
    } else if (hits.is_array()) {
      for (const auto &destination : hits)
        values.insert(parse_address(destination));
    } else
      throw AnalysisError("trace hits must be an object or array");
    if (values.size() > 65536)
      throw AnalysisError("trace target count exceeded");
  }
}
std::string ObservationSet::grade(Address site, Address target) const {
  auto found = targets.find(site);
  if (found == targets.end() || found->second.empty())
    return "static_only";
  return found->second.contains(target) ? "observed" : "conflict";
}
bool ObservationSet::multiple(Address site) const {
  auto found = targets.find(site);
  return found != targets.end() && found->second.size() > 1;
}
Json ObservationSet::json() const {
  Json sites = Json::object();
  for (const auto &[site, destinations] : targets) {
    auto &values = sites[hex_address(site)] = Json::array();
    for (auto target : destinations)
      values.push_back(hex_address(target));
  }
  return {{"sites", sites}};
}
std::vector<ResolvedFlow>
resolve_targets(const CodeImage &image, const AnalysisSettings &,
                const std::vector<DispatchSite> &sites,
                const std::vector<FlowTransition> &transitions,
                const ObservationSet &observed) {
  std::vector<ResolvedFlow> result;
  for (const auto &transition : transitions) {
    ResolvedFlow flow;
    flow.transition = transition;
    const DispatchSite *site = nullptr;
    for (const auto &candidate : sites)
      if (candidate.branch == transition.branch) {
        site = &candidate;
        break;
      }
    if (!site)
      throw AnalysisError("transition refers to an unknown dispatch site");
    if (!transition.state) {
      result.push_back(std::move(flow));
      continue;
    }
    for (auto value : transition.state->values) {
      TargetRecord record;
      record.state = value;
      if (site->model == "comparison_tree") {
        auto target = site->comparisons.find(value);
        if (target != site->comparisons.end())
          record.destination = target->second;
        else
          record.reason = "state is absent from comparison map";
      } else if (!image.relocated) {
        record.reason = "table image is not declared relocated";
      } else if (!site->target_table || !site->target_access) {
        record.reason = "target table base is unresolved";
      } else {
        std::int64_t table_index = 0;
        bool usable = true;
        if (site->model == "two_level") {
          if (!site->index_table || !site->index_access) {
            record.reason = "index table base is unresolved";
            usable = false;
          } else {
            auto input = site->state_slot && site->state_slot->signed_value
                             ? signed32(value)
                             : static_cast<std::int64_t>(value & 0xffffffff);
            if (site->index_access->extension == 6)
              input = signed32(value);
            auto location =
                indexed(*site->index_table, input, site->index_access->scale);
            auto index = location ? image.integer(*location, 4) : std::nullopt;
            if (!index) {
              record.reason = "index table read failed";
              usable = false;
            } else
              table_index = signed32(*index);
          }
        } else {
          if (site->target_access->extension == 6)
            table_index = signed32(value);
          else if (site->target_access->extension == 2)
            table_index = static_cast<std::int64_t>(value & 0xffffffff);
          else if (value > static_cast<std::uint64_t>(
                               std::numeric_limits<std::int64_t>::max())) {
            record.reason = "index is outside supported range";
            usable = false;
          } else
            table_index = static_cast<std::int64_t>(value);
        }
        if (usable) {
          record.index = table_index;
          if (table_index < 0 || table_index > 65535)
            record.reason = "target index is outside 0..65535";
          else {
            auto location = indexed(*site->target_table, table_index,
                                    site->target_access->scale);
            if (location)
              record.destination = image.integer(*location, 8);
            if (!record.destination)
              record.reason = "target table read failed";
          }
        }
      }
      if (record.destination) {
        if (!image.valid_target(*record.destination)) {
          record.reason = "target is not aligned executable memory";
          record.evidence = "invalid";
        } else
          record.evidence = observed.grade(site->branch, *record.destination);
      }
      flow.targets.push_back(std::move(record));
    }
    result.push_back(std::move(flow));
  }
  return result;
}
} // namespace a64dispatch
