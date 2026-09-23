#include <a64dispatch/rewrite.hpp>
#include <algorithm>
#include <limits>
namespace a64dispatch {
Json enrich_table_graph(const CodeImage &image,
                        const AnalysisSettings &settings,
                        const std::vector<DispatchSite> &sites,
                        RewritePlan &plan) {
  const auto options = settings.raw.value("analysis", Json::object())
                           .value("graph_tables", Json::object());
  if (!options.is_object())
    throw AnalysisError("graph_tables requires an object");
  if (!options.value("enabled", true))
    return {{"enabled", false}};
  const auto maximum =
      parse_address(options.value("maximum_entries", Json(256)));
  if (!maximum || maximum > 65536)
    throw AnalysisError("graph table entry cap must be in 1..65536");
  std::set<Address> changed;
  for (const auto &edit : plan.edits)
    changed.insert(edit.site);
  std::map<Address, std::set<Address>> edges;
  for (const auto &edge : plan.graph)
    edges[edge.source].insert(edge.target);
  Json report = {{"enabled", true},
                 {"maximum_entries", maximum},
                 {"sites", Json::array()},
                 {"truncated", false},
                 {"semantics", "table candidates for unchanged dispatchers; "
                               "not execution or byte-rewrite evidence"}};
  for (const auto &site : sites) {
    if (site.model == "comparison_tree" || changed.contains(site.branch))
      continue;
    Json row = {{"site", hex_address(site.branch)},
                {"entries", Json::array()},
                {"truncated", false},
                {"stop", "unresolved table"}};
    if (!image.relocated)
      row["stop"] = "image is not declared relocated";
    else if (site.target_table && site.target_access) {
      const auto &access = *site.target_access;
      if (access.width != 8 || access.scale > 3)
        row["stop"] = "unsupported target access";
      else {
        const auto stride = std::uint64_t{1} << access.scale;
        row["stride"] = stride;
        row["table"] = hex_address(*site.target_table);
        row["stop"] = "entry cap";
        bool ended = false;
        for (std::uint64_t index = 0; index < maximum; ++index) {
          if (index >
              (std::numeric_limits<Address>::max() - *site.target_table) /
                  stride) {
            row["stop"] = "address overflow";
            ended = true;
            break;
          }
          const auto address = *site.target_table + index * stride;
          const auto region = image.region_at(address, 8);
          const auto value = region && region->readable
                                 ? image.integer(address, 8)
                                 : std::nullopt;
          if (!value || !image.valid_target(*value)) {
            row["stop"] = value ? "invalid target" : "unmapped entry";
            ended = true;
            break;
          }
          auto &destinations = edges[site.branch];
          if (!destinations.contains(*value) &&
              destinations.size() >= settings.maximum_targets) {
            row["stop"] = "target cap";
            break;
          }
          if (destinations.insert(*value).second)
            plan.graph.push_back({site.branch, *value, false});
          row["entries"].push_back({{"address", hex_address(address)},
                                    {"target", hex_address(*value)},
                                    {"evidence", "table_candidate"},
                                    {"mutable", region && region->writable}});
        }
        if (!ended) {
          row["truncated"] = true;
          report["truncated"] = true;
        }
      }
    }
    report["sites"].push_back(std::move(row));
  }
  std::sort(plan.graph.begin(), plan.graph.end(),
            [](const auto &left, const auto &right) {
              return std::pair(left.source, left.target) <
                     std::pair(right.source, right.target);
            });
  return report;
}
} // namespace a64dispatch
